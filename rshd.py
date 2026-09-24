#!/usr/bin/env python3
"""rshd — reverse command channel hub (runs on the hub machine only).

Workers (rsh-worker.py) connect *outbound* to this daemon and register with a
shared token; the hub then pushes commands down the established connections.
That inverts the reachability requirement: machines behind NAT/firewall only
need outbound TCP to the hub.

  listen   TCP 0.0.0.0:$RSH_PORT (default 8790), token-gated.
  register first line {"type":"register","host":..,"token":..}; the hub sends
           nothing before a valid register (a port scan sees no banner), and
           closes + logs DENY on a bad/missing token.
  heartbeat hub pings every 30s, worker pongs; >90s silence -> evict.
  control  unix socket run/rsh/rshd.sock (0600), JSON-lines ops:
             {"op":"list"}
             {"op":"exec","worker":..,"cmd":[..],"timeout":N}
           exec streams back {"t":"out"/"err","data"} then
           {"t":"done","exit":N,"timeout":bool} or {"t":"error","msg":..}.
  forward  for every registered worker named in RSH_FWD_HOSTS the hub listens
           on the unix socket <FWD_DIR>/<worker>.sock (default run/rsh-fwd/,
           dir 0700 + node 0600) and tunnels each inbound connection over the
           same long-lived channel to the worker's 127.0.0.1:FWD_TARGET
           (default 8080), via fwd_open/fwd_ack/fwd_data(base64, <=64KB raw
           per chunk)/fwd_close. Listener lifecycle follows the
           registration: opened on register, closed (+ node unlinked) on
           disconnect or eviction; a same-name re-registration keeps the
           listener and re-points it at the new connection.

Invariants (do not weaken without a replacement):
  * a forward problem never touches the command channel — every fwd path is
    fail-soft (log + degrade to command mode);
  * the unix listener node *is* its occupied state, so bind() unlinks any
    leftover first and cannot fail with EADDRINUSE; close always unlinks, so
    a stale node never advertises a forward that is gone;
  * one connection per worker name: a re-registration supersedes the old
    connection and drops its in-flight tunnels (the new one cannot know their
    fids);
  * the hub derives the listener path from the worker name (single source of
    truth) and sanitises the name — it arrives over the wire;
  * the token is compared in constant time and non-string tokens are rejected
    without raising;
  * an unterminated line beyond MAX_LINE drops the connection instead of
    buffering forever.

Auth: single shared token from the config face ($RSH_ENV, default
<ws>/env/rsh.env) as RSH_TOKEN — possibly `enc1:`-encrypted, decrypted in
memory — or from the RSH_TOKEN env var. Trust model = "holding the token is
equivalent to ssh trust across all workers"; see README.md. Python 3 stdlib only.
"""
import argparse
import base64
import binascii
import hmac
import json
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (WS_ROOT, ENV_FILE, close_quiet, env_value, host_list,  # noqa: E402
                     load_env_file, make_logger)

DEFAULT_SOCK = os.path.join(WS_ROOT, "run", "rsh", "rshd.sock")
FWD_DIR_DEFAULT = os.path.join(WS_ROOT, "run", "rsh-fwd")

PING_INTERVAL = 30.0   # seconds between hub->worker pings
EVICT_AFTER = 90.0     # seconds of silence before a worker is evicted
REGISTER_TIMEOUT = 10.0
CHUNK_LIMIT = 64 * 1024
MAX_LINE = 1024 * 1024
FWD_TARGET_DEFAULT = 8080   # worker-side upstream port

log = make_logger("rshd")


class Worker(object):
    def __init__(self, host, sock, has_fwd=False):
        self.host = host
        self.sock = sock
        self.has_fwd = has_fwd           # a unix listener is live for it
        self.connected_at = time.time()
        self.last_seen = time.time()
        self.lock = threading.Lock()     # serialises sends
        self.sessions = {}               # exec id -> Session
        self.alive = True

    def send(self, obj):
        data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
        with self.lock:
            self.sock.sendall(data)

    def close(self):
        self.alive = False
        close_quiet(self.sock, shutdown=False)


class Session(object):
    """One in-flight exec: forwards worker output to the CLI control conn."""
    def __init__(self, exec_id, ctrl):
        self.exec_id = exec_id
        self.ctrl = ctrl                 # file object of the control socket
        self.done = threading.Event()
        self.exit = None
        self.started = time.time()


class Hub(object):
    def __init__(self, token, sock_path, fwd_dir=FWD_DIR_DEFAULT,
                 fwd_target=FWD_TARGET_DEFAULT, fwd_hosts=()):
        self.token = token
        self.sock_path = sock_path
        self.fwd_dir = fwd_dir           # unix fwd listeners live here
        self.fwd_target = fwd_target     # worker-side upstream port
        self.fwd_hosts = set(fwd_hosts)  # worker names that get a listener
        self.workers = {}                # host -> Worker
        self.workers_lock = threading.Lock()
        self.next_id = 0
        self.id_lock = threading.Lock()
        # port forwarding state
        self.fwd_lock = threading.Lock()
        self.fwd_listeners = {}          # host -> {path, sock}; at most one
                                         # listener per worker (the path is
                                         # derived from the name, so
                                         # cross-worker conflicts are
                                         # structurally impossible)
        self.fwd_conns = {}              # fid -> {host, client}
        self.fwd_seq = 0

    # ---------------- port forward ----------------

    def fwd_setup(self, w):
        """Reconcile the forward state of a freshly registered worker:
        listeners of the same name follow the new connection, in-flight
        tunnels of the superseded one are dropped. Mutates w.has_fwd.
        Never raises; a forward problem must not affect the command
        channel."""
        try:
            w.has_fwd = self._fwd_setup(w)
        except Exception as e:  # defensive: keep 8790 alive no matter what
            log("ERROR fwd setup for %s: %s" % (w.host, e))
            w.has_fwd = False
        return w.has_fwd

    def fwd_sock_path(self, host):
        """Unix socket path of a worker's inbound forward listener. The name
        arrives over the wire -> keep it fs-safe."""
        safe = "".join(c if (c.isalnum() or c in "-_.") else "_"
                       for c in host)[:80] or "worker"
        return os.path.join(self.fwd_dir, safe + ".sock")

    def fwd_dir_init(self):
        """Create the fwd dir (0700) and sweep socket nodes left by a
        previous run that died without teardown. Non-fatal."""
        try:
            os.makedirs(self.fwd_dir, exist_ok=True)
        except OSError as e:
            log("ERROR cannot create fwd dir %s: %s (forwards will fail)"
                % (self.fwd_dir, e))
            return
        try:
            os.chmod(self.fwd_dir, 0o700)
        except OSError:
            pass
        try:
            names = sorted(os.listdir(self.fwd_dir))
        except OSError:
            return
        for name in names:
            if not name.endswith(".sock"):
                continue
            p = os.path.join(self.fwd_dir, name)
            try:
                os.unlink(p)
                log("removed stale fwd socket %s" % p)
            except OSError as e:
                log("WARN cannot remove stale fwd socket %s: %s" % (p, e))

    def _fwd_bind_unix(self, path):
        """bind+listen an AF_UNIX listener at path, unlinking any leftover
        node first (ENOENT ignored): a dead socket can then never make bind
        fail. Returns the listening socket (node chmod 0600); raises OSError
        on a genuine failure (permissions, path length, fs error)."""
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            srv.bind(path)
            os.chmod(path, 0o600)
            srv.listen(32)
        except OSError:
            close_quiet(srv, shutdown=False)
            try:
                os.unlink(path)   # never leave a half-made node behind
            except OSError:
                pass
            raise
        return srv

    def _fwd_close_listener(self, L):
        """Close one listener fd and unlink its socket node. Caller holds
        fwd_lock. The unlink matters: a leftover node would advertise a
        forward that no longer exists (clients get ECONNREFUSED instead of
        ENOENT)."""
        close_quiet(L["sock"], shutdown=False)   # makes accept() raise
        try:
            os.unlink(L["path"])
        except FileNotFoundError:
            pass
        except OSError as e:
            log("WARN cannot unlink fwd socket %s: %s" % (L["path"], e))

    def _fwd_setup(self, w):
        """True = a listener is live for w after this call."""
        with self.fwd_lock:
            # in-flight tunnels of a superseded registration are closed: the
            # new worker connection has no knowledge of their fids
            self._fwd_drop_host_conns(w.host)
            L = self.fwd_listeners.get(w.host)
            if w.host not in self.fwd_hosts:
                # this worker gets no forward: a listener left by an earlier
                # registration of the same name must not survive it
                if L is not None:
                    del self.fwd_listeners[w.host]
                    self._fwd_close_listener(L)
                    log("forward listen %s closed (worker %s re-registered "
                        "and is not in the forward host list)"
                        % (L["path"], w.host))
                return False
            if L is not None:
                # same host re-registering: the listener persists and follows
                # the new connection
                return True
            path = self.fwd_sock_path(w.host)
            try:
                srv = self._fwd_bind_unix(path)
            except OSError as e:
                # Remaining bind failures are configuration-level (directory
                # permissions, path length, fs error), not races: report and
                # serve this worker in command mode. It gets a listener again
                # on its next registration.
                log("ERROR cannot listen on %s for worker %s: %s "
                    "(registered without forward)" % (path, w.host, e))
                return False
            self.fwd_listeners[w.host] = {"path": path, "sock": srv}
        log("forward listen %s -> worker %s 127.0.0.1:%d"
            % (path, w.host, self.fwd_target))
        threading.Thread(target=self.fwd_accept_loop, args=(w.host,),
                         daemon=True).start()
        return True

    def _fwd_drop_host_conns(self, host):
        """Close all in-flight tunnel client sockets of a host. Caller holds
        fwd_lock."""
        for fid, c in list(self.fwd_conns.items()):
            if c["host"] == host:
                self.fwd_conns.pop(fid, None)
                close_quiet(c["client"])

    def fwd_teardown(self, host):
        """Registration ended (disconnect/evict): drop listener + tunnels."""
        with self.fwd_lock:
            L = self.fwd_listeners.pop(host, None)
            if L is not None:
                self._fwd_close_listener(L)
                log("forward listen %s closed (worker %s gone)"
                    % (L["path"], host))
            self._fwd_drop_host_conns(host)

    def fwd_accept_loop(self, host):
        with self.fwd_lock:
            L = self.fwd_listeners.get(host)
            srv = L["sock"] if L else None
        if srv is None:
            return
        while True:
            try:
                conn, addr = srv.accept()   # AF_UNIX: addr is ''
            except OSError:
                return
            threading.Thread(target=self.fwd_client, args=(host, conn, addr),
                             daemon=True).start()

    def fwd_client(self, host, conn, addr):
        """Hub side of one forwarded connection: allocate fid, ask the worker
        to dial the upstream, then pump client -> worker."""
        with self.fwd_lock:
            self.fwd_seq += 1
            fid = "%s-f%d" % (host, self.fwd_seq)
            self.fwd_conns[fid] = {"host": host, "client": conn}
        try:
            self._fwd_send(host, {"type": "fwd_open", "id": fid,
                                  "port": self.fwd_target})
        except OSError as e:
            log("fwd %s: cannot notify worker %s (%s)" % (fid, host, e))
            with self.fwd_lock:
                self.fwd_conns.pop(fid, None)
            close_quiet(conn)
            return
        while True:
            try:
                chunk = conn.recv(CHUNK_LIMIT)
            except OSError:
                break
            if not chunk:
                break
            try:
                self._fwd_send(host, {"type": "fwd_data", "id": fid,
                                      "data": base64.b64encode(chunk)
                                      .decode("ascii")})
            except OSError:
                break
        try:
            self._fwd_send(host, {"type": "fwd_close", "id": fid})
        except OSError:
            pass
        self._fwd_drop_conn(fid, conn)

    def _fwd_send(self, host, obj):
        """Send to the *current* connection of host (a re-registration may
        have swapped the Worker object since the tunnel opened)."""
        with self.workers_lock:
            w = self.workers.get(host)
        if w is None or not w.alive:
            raise OSError("worker %s not connected" % host)
        w.send(obj)

    def _fwd_drop_conn(self, fid, conn):
        with self.fwd_lock:
            self.fwd_conns.pop(fid, None)
        close_quiet(conn)

    def fwd_route(self, w, msg):
        """Worker -> hub tunnel messages (fwd_ack / fwd_data / fwd_close)."""
        fid = msg.get("id")
        with self.fwd_lock:
            c = self.fwd_conns.get(fid)
        if c is None or c["host"] != w.host:
            return  # stale or unknown fid
        mtype = msg.get("type")
        if mtype == "fwd_data":
            try:
                raw = base64.b64decode(msg.get("data", ""), validate=True)
            except (binascii.Error, ValueError):
                log("fwd %s: bad base64 from worker %s, closing tunnel"
                    % (fid, w.host))
                self._fwd_drop_conn(fid, c["client"])
                return
            try:
                c["client"].sendall(raw)
            except OSError:
                self._fwd_drop_conn(fid, c["client"])
                try:
                    self._fwd_send(w.host, {"type": "fwd_close", "id": fid})
                except OSError:
                    pass
        elif mtype == "fwd_close":
            self._fwd_drop_conn(fid, c["client"])
        # fwd_ack: upstream dialed; nothing to do (data may have been sent
        # ahead of the ack and is buffered on the worker side)

    def token_ok(self, tok):
        """Constant-time token compare; rejects non-string tokens without
        raising."""
        if not isinstance(tok, str):
            return False
        return hmac.compare_digest(tok.encode("utf-8"),
                                   self.token.encode("utf-8"))

    # ---------------- worker side ----------------

    def accept_loop(self, listen_sock):
        while True:
            try:
                conn, addr = listen_sock.accept()
            except OSError:
                return
            threading.Thread(target=self.handle_conn, args=(conn, addr),
                             daemon=True).start()

    def handle_conn(self, conn, addr):
        peer = "%s:%s" % addr[:2]
        conn.settimeout(REGISTER_TIMEOUT)
        try:
            first = conn.recv(MAX_LINE)
        except OSError:
            close_quiet(conn, shutdown=False)
            return
        line = first.split(b"\n", 1)[0].strip()
        try:
            reg = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            reg = None
        if (not isinstance(reg, dict) or reg.get("type") != "register"
                or not reg.get("host")
                or not self.token_ok(reg.get("token"))):
            log("DENY register from %s (bad/missing register or token)" % peer)
            close_quiet(conn, shutdown=False)
            return
        host = str(reg["host"])[:200]
        conn.settimeout(None)
        try:
            conn.sendall(b'{"type":"registered"}\n')
        except OSError:
            close_quiet(conn, shutdown=False)
            return
        w = Worker(host, conn)
        with self.workers_lock:
            old = self.workers.get(host)
            if old is not None:
                log("worker %s re-registered from %s (replacing old conn)"
                    % (host, peer))
                old.close()
            self.workers[host] = w
        has_fwd = self.fwd_setup(w)
        log("worker %s registered from %s%s"
            % (host, peer,
               " (forward -> %s)" % self.fwd_sock_path(host) if has_fwd
               else " (no forward)" if host in self.fwd_hosts else ""))
        self.worker_reader(w)
        # reader returns when the connection dies
        with self.workers_lock:
            current = self.workers.get(host) is w
            if current:
                del self.workers[host]
        w.close()
        if current:
            self.fwd_teardown(host)
        log("worker %s disconnected" % host)
        # fail any in-flight execs on this worker
        for s in list(w.sessions.values()):
            try:
                s.ctrl.write(json.dumps(
                    {"t": "error", "msg": "worker %s disconnected" % host}
                ) + "\n")
                s.ctrl.flush()
            except (OSError, ValueError):
                pass
            s.done.set()

    def worker_reader(self, w):
        buf = b""
        while w.alive:
            try:
                chunk = w.sock.recv(CHUNK_LIMIT + 4096)
            except OSError:
                return
            if not chunk:
                return
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    continue
                if not isinstance(msg, dict):
                    continue
                w.last_seen = time.time()
                mtype = msg.get("type")
                if mtype == "pong":
                    continue
                if mtype in ("out", "err", "result"):
                    self.route(w, msg)
                elif mtype in ("fwd_ack", "fwd_data", "fwd_close"):
                    self.fwd_route(w, msg)
                # unknown types ignored
            # No newline in sight and the buffer outgrew MAX_LINE: an
            # (authenticated) worker is streaming an unterminated line —
            # drop the connection instead of buffering forever.
            if len(buf) > MAX_LINE:
                log("worker %s sent an unterminated line > %d bytes; "
                    "disconnecting" % (w.host, MAX_LINE))
                return

    def route(self, w, msg):
        s = w.sessions.get(msg.get("id"))
        if s is None:
            return
        try:
            if msg["type"] == "result":
                s.exit = msg.get("exit")
                s.ctrl.write(json.dumps(
                    {"t": "done", "exit": s.exit,
                     "timeout": msg.get("timeout", False)}) + "\n")
                s.ctrl.flush()
                s.done.set()
            else:
                data = msg.get("data", "")
                if len(data) > CHUNK_LIMIT:
                    data = data[:CHUNK_LIMIT]
                s.ctrl.write(json.dumps(
                    {"t": msg["type"], "data": data}) + "\n")
                s.ctrl.flush()
        except (OSError, ValueError):
            s.done.set()

    def heartbeat_loop(self):
        while True:
            time.sleep(PING_INTERVAL)
            now = time.time()
            with self.workers_lock:
                items = list(self.workers.items())
            for host, w in items:
                if now - w.last_seen > EVICT_AFTER:
                    log("evicting worker %s (no traffic for %.0fs)"
                        % (host, now - w.last_seen))
                    with self.workers_lock:
                        evicted = self.workers.get(host) is w
                        if evicted:
                            del self.workers[host]
                    w.close()
                    if evicted:
                        self.fwd_teardown(host)
                    continue
                try:
                    w.send({"type": "ping", "ts": now})
                except OSError:
                    pass

    # ---------------- control side (CLI) ----------------

    def ctrl_loop(self):
        d = os.path.dirname(self.sock_path)
        os.makedirs(d, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        try:
            os.unlink(self.sock_path)
        except OSError:
            pass
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self.sock_path)
        os.chmod(self.sock_path, 0o600)
        srv.listen(16)
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=self.handle_ctrl, args=(conn,),
                             daemon=True).start()

    def handle_ctrl(self, conn):
        try:
            ctrl = conn.makefile("r")
            req = ctrl.readline()
            if not req:
                return
            try:
                op = json.loads(req)
            except ValueError:
                self.ctrl_error(conn, "bad request")
                return
            kind = op.get("op")
            if kind == "list":
                self.op_list(conn)
            elif kind == "exec":
                self.op_exec(conn, op)
            else:
                self.ctrl_error(conn, "unknown op %r" % kind)
        finally:
            close_quiet(conn, shutdown=False)

    @staticmethod
    def ctrl_error(conn, msg):
        try:
            conn.sendall((json.dumps({"t": "error", "msg": msg})
                          + "\n").encode("utf-8"))
        except OSError:
            pass

    def op_list(self, conn):
        now = time.time()
        # Snapshot the listener paths before taking workers_lock: keeps the
        # lock order identical to everywhere else (never fwd_lock nested
        # inside workers_lock and vice versa).
        with self.fwd_lock:
            live = dict((h, L["path"]) for h, L in self.fwd_listeners.items())
        with self.workers_lock:
            rows = [{"host": w.host,
                     "connected_secs": int(now - w.connected_at),
                     "last_seen_secs": int(now - w.last_seen),
                     "fwd_sock": live.get(w.host)}
                    for w in self.workers.values()]
        rows.sort(key=lambda r: r["host"])
        conn.sendall((json.dumps({"t": "list", "workers": rows})
                      + "\n").encode("utf-8"))

    def op_exec(self, conn, op):
        host = op.get("worker") or ""
        cmd = op.get("cmd")
        timeout = float(op.get("timeout") or 60)
        if not isinstance(cmd, list) or not cmd:
            return self.ctrl_error(conn, "exec needs non-empty cmd list")
        with self.workers_lock:
            w = self.workers.get(host)
        if w is None or not w.alive:
            return self.ctrl_error(conn, "worker %r not registered" % host)
        with self.id_lock:
            self.next_id += 1
            exec_id = "%d-%d" % (int(time.time()), self.next_id)
        f = conn.makefile("w")
        s = Session(exec_id, f)
        w.sessions[exec_id] = s
        try:
            w.send({"type": "exec", "id": exec_id, "cmd": cmd,
                    "timeout": timeout})
        except OSError as e:
            w.sessions.pop(exec_id, None)
            return self.ctrl_error(conn, "send to worker failed: %s" % e)
        got = s.done.wait(timeout)
        w.sessions.pop(exec_id, None)
        if not got:
            # Timed out: ask the worker to kill, then tell the CLI. Re-fetch
            # the live worker first — a re-registration may have replaced it,
            # and a cancel sent to the stale connection is silently
            # swallowed, leaking the remote process.
            with self.workers_lock:
                live = self.workers.get(host)
            try:
                (live or w).send({"type": "cancel", "id": exec_id})
            except OSError:
                pass
            try:
                f.write(json.dumps({"t": "done", "exit": 124,
                                    "timeout": True}) + "\n")
                f.flush()
            except (OSError, ValueError):
                pass


def main():
    cfg = load_env_file(ENV_FILE, log)
    ap = argparse.ArgumentParser(description="rsh reverse command channel hub")
    ap.add_argument("--port", type=int,
                    default=int(env_value(cfg, "RSH_PORT", "8790")))
    ap.add_argument("--bind", default=env_value(cfg, "RSH_BIND", "0.0.0.0"))
    ap.add_argument("--sock", default=env_value(cfg, "RSH_SOCK", DEFAULT_SOCK))
    ap.add_argument("--fwd-dir", default=env_value(
        cfg, "RSH_FWD_DIR", FWD_DIR_DEFAULT),
        help="directory of the unix-socket forward listeners: path = "
             "<dir>/<worker>.sock (default <repo>/run/rsh-fwd)")
    ap.add_argument("--fwd-target", type=int, default=int(env_value(
        cfg, "RSH_FWD_TARGET", str(FWD_TARGET_DEFAULT))),
        help="upstream port on the worker side (default 8080)")
    ap.add_argument("--fwd-hosts", default=env_value(cfg, "RSH_FWD_HOSTS", ""),
        help="worker names that get an inbound forward listener "
             "(comma/space separated; empty = command mode for everyone)")
    args = ap.parse_args()

    token = os.environ.get("RSH_TOKEN") or cfg.get("RSH_TOKEN", "")
    if not token:
        sys.exit("rshd: no RSH_TOKEN (set env RSH_TOKEN or add RSH_TOKEN to "
                 "%s)" % ENV_FILE)

    fwd_hosts = host_list(args.fwd_hosts)
    hub = Hub(token, args.sock, fwd_dir=args.fwd_dir,
              fwd_target=args.fwd_target, fwd_hosts=fwd_hosts)
    hub.fwd_dir_init()

    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind((args.bind, args.port))
    listen.listen(32)
    log("rshd listening on %s:%d, control socket %s (fwd dir %s -> worker "
        "127.0.0.1:%d, fwd hosts: %s)"
        % (args.bind, args.port, args.sock, args.fwd_dir, args.fwd_target,
           ",".join(sorted(fwd_hosts)) or "-"))

    threading.Thread(target=hub.accept_loop, args=(listen,),
                     daemon=True).start()
    threading.Thread(target=hub.heartbeat_loop, daemon=True).start()
    try:
        hub.ctrl_loop()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

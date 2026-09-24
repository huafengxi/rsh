#!/usr/bin/env python3
"""rsh-worker — reverse command channel worker (runs on every managed machine).

Makes an outbound TCP connection to the hub (rshd.py), registers with the
shared token, then runs commands pushed down the connection and streams
output back. Reconnects with exponential backoff (1 -> 60s).

  register  {"type":"register","host":<name>,"token":..} on connect;
            expects {"type":"registered"}.
  heartbeat answers hub pings with pong; >100s of silence -> reconnect.
  exec      {"type":"exec","id","cmd":[argv],"timeout"} -> `bash -c` with
            argv shlex-joined, cwd = this process's startup directory (the
            workspace root when a service manager launches it from there);
            streams {"type":"out"/"err","id",
            "data"} in <=64KB chunks and ends with {"type":"result","id",
            "exit"}. {"type":"cancel","id"} kills the process group.
  forward   the hub decides which workers get an inbound forward (its own
            RSH_FWD_HOSTS list) and drives the tunnel from here: it sends
            {"type":"fwd_open","id","port"}, this worker dials
            127.0.0.1:<port> and bridges both ways with fwd_ack /
            fwd_data(base64) / fwd_close on the same connection. The worker
            holds no forward configuration of its own.
  name      hostname looked up in the host-id table ($RSH_HOST_ID, default
            <ws>/env/host-id: `<hostname> <canonical name>` lines) for a
            canonical machine alias, falling back to the raw hostname;
            --name overrides. A duplicate
            name re-registration supersedes the previous connection on the
            hub.

Invariants (do not weaken without a replacement):
  * every exec is its own session and process group (start_new_session) so a
    timeout or cancel can killpg the whole tree;
  * the local timeout timer mirrors the hub's semantics (missing/0 -> 60s)
    and fires even when the hub's cancel is lost (hub dead/disconnected);
  * a duplicate exec id reclaims ownership: the old process group is killed
    and the superseded thread's generation check keeps it from popping the
    new entry or emitting a late result;
  * the reader socket stays blocking — a socket timeout would permanently
    poison the buffered reader — so a watchdog thread shuts the socket down
    on hub silence instead;
  * an upstream socket is closed with shutdown before close, otherwise a
    thread blocked in recv() on it is never woken;
  * data arriving before the upstream dial completes is buffered, capped at
    FWD_BUF_LIMIT.

Auth: token from the config face ($RSH_ENV, default <ws>/env/rsh.env) as
RSH_TOKEN — possibly `enc1:`-encrypted, decrypted in memory — or from the
RSH_TOKEN env var. RSH_HUB must be an address this machine can resolve: the
worker dials it directly, so ssh-config aliases do NOT apply — use an IP or a
name the resolver knows. Trust model: README.md.
Python 3 stdlib only.
"""
import argparse
import base64
import binascii
import json
import os
import shlex
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (HOST_ID_FILE, ENV_FILE, close_quiet, env_value,  # noqa: E402
                     load_env_file, make_logger)

CHUNK_LIMIT = 64 * 1024
SILENCE_LIMIT = 100.0
BACKOFF_MAX = 60.0
REGISTER_ACK_TIMEOUT = 15.0
FWD_DIAL_TIMEOUT = 10.0
FWD_BUF_LIMIT = 4 * 1024 * 1024   # pre-connect buffer cap per tunnel

log = make_logger("rsh-worker")


def canonical_name():
    hn = socket.gethostname()
    try:
        with open(HOST_ID_FILE) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0] == hn:
                    return parts[1]
    except OSError:
        pass
    return hn


class Worker(object):
    def __init__(self, hub_host, port, name, token):
        self.hub_host = hub_host
        self.port = port
        self.name = name
        self.token = token
        self.sock = None
        self.lock = threading.Lock()     # serialises sends
        self.last_recv = time.time()
        self.cwd = os.getcwd()           # exec's default cwd = startup directory
        self.procs = {}                  # exec id -> Popen
        self.fwd_lock = threading.Lock()
        self.forwards = {}               # fid -> {sock, buf, lock}

    def send(self, obj):
        data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
        with self.lock:
            self.sock.sendall(data)

    def connect(self):
        sock = socket.create_connection((self.hub_host, self.port), timeout=15)
        sock.settimeout(None)
        self.sock = sock
        self.send({"type": "register", "host": self.name, "token": self.token})
        # Dedicated one-shot timeout for the ack read: a half-open hub must
        # not hang us forever here (the read_loop watchdog is not running
        # yet). Each connect creates a fresh socket/reader, so CPython's
        # SocketIO._timeout_occurred poisoning is confined to this
        # (discarded) connection.
        sock.settimeout(REGISTER_ACK_TIMEOUT)
        f = sock.makefile("r")
        line = f.readline()
        sock.settimeout(None)
        try:
            ack = json.loads(line)
        except ValueError:
            raise RuntimeError("register rejected (no valid ack)")
        if ack.get("type") != "registered":
            raise RuntimeError("register rejected: %s" % line.strip()[:200])
        self.last_recv = time.time()
        log("registered with hub %s:%d as %r"
            % (self.hub_host, self.port, self.name))
        return f

    # ---------------- port forward ----------------

    def fwd_open(self, fid, port):
        """Hub asks for a tunnel: dial local upstream and bridge both ways."""
        entry = {"sock": None, "buf": b"", "lock": threading.Lock()}
        with self.fwd_lock:
            if fid in self.forwards:      # duplicate fid: replace cleanly
                self._fwd_close_locked(fid)
            self.forwards[fid] = entry
        threading.Thread(target=self.run_fwd, args=(fid, port, entry),
                         daemon=True).start()

    def run_fwd(self, fid, port, entry):
        try:
            up = socket.create_connection(("127.0.0.1", port),
                                          timeout=FWD_DIAL_TIMEOUT)
        except OSError as e:
            log("fwd %s: cannot dial 127.0.0.1:%s: %s" % (fid, port, e))
            with self.fwd_lock:
                self._fwd_close_locked(fid)
            self._fwd_notify_close(fid)
            return
        up.settimeout(None)
        with entry["lock"]:
            if self.forwards.get(fid) is not entry:
                # superseded while dialing
                close_quiet(up, shutdown=False)
                return
            entry["sock"] = up
            pending, entry["buf"] = entry["buf"], b""
        try:
            self.send({"type": "fwd_ack", "id": fid})
            if pending:
                up.sendall(pending)
        except OSError:
            self._fwd_close(fid)
            return
        # upstream -> hub pump
        while True:
            try:
                chunk = up.recv(CHUNK_LIMIT)
            except OSError:
                break
            if not chunk:
                break
            try:
                self.send({"type": "fwd_data", "id": fid,
                           "data": base64.b64encode(chunk).decode("ascii")})
            except OSError:
                break
        self._fwd_close(fid)
        self._fwd_notify_close(fid)

    def _fwd_notify_close(self, fid):
        try:
            self.send({"type": "fwd_close", "id": fid})
        except OSError:
            pass

    def fwd_data(self, fid, data_b64):
        try:
            raw = base64.b64decode(data_b64, validate=True)
        except (binascii.Error, ValueError):
            log("fwd %s: bad base64 from hub, closing tunnel" % fid)
            self._fwd_close(fid)
            return
        with self.fwd_lock:
            entry = self.forwards.get(fid)
        if entry is None:
            return
        with entry["lock"]:
            up = entry["sock"]
            if up is None:                # still dialing: buffer
                entry["buf"] += raw
                if len(entry["buf"]) > FWD_BUF_LIMIT:
                    log("fwd %s: pre-connect buffer overflow, closing" % fid)
                    self._fwd_close(fid)
                    self._fwd_notify_close(fid)
                    return
                return
        try:
            up.sendall(raw)
        except OSError:
            self._fwd_close(fid)

    def _fwd_close(self, fid):
        with self.fwd_lock:
            self._fwd_close_locked(fid)

    def _fwd_close_locked(self, fid):
        """Remove tunnel state and close the upstream socket. Caller holds
        fwd_lock."""
        entry = self.forwards.pop(fid, None)
        if entry is None:
            return
        with entry["lock"]:
            entry["buf"] = b""
            up, entry["sock"] = entry["sock"], None
        close_quiet(up)

    def fwd_close(self, fid):
        self._fwd_close(fid)

    def fwd_drop_all(self):
        """Hub connection died: close every upstream tunnel."""
        with self.fwd_lock:
            for fid in list(self.forwards):
                self._fwd_close_locked(fid)

    # ---------------- exec ----------------

    def run_exec(self, exec_id, cmd, timeout):
        cmd_str = " ".join(shlex.quote(str(c)) for c in cmd)
        # Duplicate id: reclaim ownership and kill the old process group
        # before starting the new one so it cannot leak; popping first also
        # makes the old run_exec thread's generation check below fail fast.
        old = self.procs.pop(exec_id, None)
        if old is not None:
            self._kill_proc(old)
        try:
            proc = subprocess.Popen(
                ["bash", "-c", cmd_str],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True, cwd=self.cwd)
        except OSError as e:
            self.send({"type": "err", "id": exec_id, "data": str(e) + "\n"})
            self.send({"type": "result", "id": exec_id, "exit": 127})
            return
        self.procs[exec_id] = proc
        # Local timeout fallback mirroring the hub's semantics (missing/0 ->
        # 60s): kills the process group even if the hub's cancel is lost.
        killer = None
        if timeout and timeout > 0:
            killer = threading.Timer(timeout, self.cancel,
                                     args=(exec_id, proc))
            killer.daemon = True
            killer.start()

        def pump(stream, kind):
            while True:
                try:
                    chunk = stream.read(CHUNK_LIMIT)
                except (OSError, ValueError):
                    break
                if not chunk:
                    break
                try:
                    self.send({"type": kind, "id": exec_id,
                               "data": chunk.decode("utf-8", "replace")})
                except OSError:
                    break
            try:
                stream.close()
            except OSError:
                pass

        t_out = threading.Thread(target=pump, args=(proc.stdout, "out"),
                                 daemon=True)
        t_err = threading.Thread(target=pump, args=(proc.stderr, "err"),
                                 daemon=True)
        t_out.start()
        t_err.start()
        t_out.join()
        t_err.join()
        rc = proc.wait()
        if killer is not None:
            killer.cancel()
        # Generation guard: a duplicate dispatch may have replaced our proc;
        # the newer run_exec owns the id, so do not pop it or emit a late
        # result.
        if self.procs.get(exec_id) is not proc:
            return
        self.procs.pop(exec_id, None)
        if rc < 0:
            rc = 128 + (-rc)             # signal death -> 128+signum
        try:
            self.send({"type": "result", "id": exec_id, "exit": rc & 0xFF})
        except OSError:
            pass

    @staticmethod
    def _kill_proc(proc):
        try:
            os.killpg(proc.pid, 9)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except OSError:
                pass

    def cancel(self, exec_id, proc=None):
        cur = self.procs.get(exec_id)
        if cur is None:
            return
        if proc is not None and cur is not proc:
            # stale local timeout of a replaced exec — the id is now owned by
            # a newer dispatch; leave it alone
            return
        self._kill_proc(cur)

    # ---------------- reader ----------------

    def read_loop(self, f):
        # Silence watchdog: the socket stays blocking (a socket timeout would
        # permanently poison the buffered reader — CPython sets
        # SocketIO._timeout_occurred and every later readline raises
        # ValueError("cannot read from timed out object")). Instead a
        # watchdog thread shuts the socket down when the hub goes silent.
        stop = threading.Event()

        def watchdog():
            while not stop.wait(10.0):
                if time.time() - self.last_recv > SILENCE_LIMIT:
                    try:
                        # shutdown only: the reader sees a clean EOF and
                        # run_forever closes the socket on the reconnect path
                        self.sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    return

        threading.Thread(target=watchdog, daemon=True).start()
        try:
            self._read_loop_inner(f)
        finally:
            stop.set()

    def _read_loop_inner(self, f):
        while True:
            line = f.readline()
            if not line:
                if time.time() - self.last_recv > SILENCE_LIMIT:
                    raise OSError("no traffic from hub for %.0fs"
                                  % SILENCE_LIMIT)
                raise OSError("hub closed connection")
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if not isinstance(msg, dict):
                continue
            self.last_recv = time.time()
            mtype = msg.get("type")
            if mtype == "ping":
                self.send({"type": "pong"})
            elif mtype == "exec":
                exec_id = msg.get("id")
                cmd = msg.get("cmd")
                if exec_id and isinstance(cmd, list) and cmd:
                    try:
                        timeout = float(msg.get("timeout") or 60)
                    except (TypeError, ValueError):
                        timeout = 60.0
                    threading.Thread(target=self.run_exec,
                                     args=(exec_id, cmd, timeout),
                                     daemon=True).start()
            elif mtype == "cancel":
                self.cancel(msg.get("id"))
            elif mtype == "fwd_open":
                fid = msg.get("id")
                port = msg.get("port")
                if fid and isinstance(port, int) and 0 < port < 65536:
                    self.fwd_open(fid, port)
            elif mtype == "fwd_data":
                fid = msg.get("id")
                if fid:
                    self.fwd_data(fid, msg.get("data", ""))
            elif mtype == "fwd_close":
                fid = msg.get("id")
                if fid:
                    self.fwd_close(fid)
            # unknown types ignored

    def run_forever(self):
        backoff = 1.0
        while True:
            try:
                f = self.connect()
                backoff = 1.0
                # read_loop raises OSError on EOF/error/silence -> reconnect
                try:
                    self.read_loop(f)
                except OSError as e:
                    log("connection lost (%s), reconnecting" % e)
                self.fwd_drop_all()
                close_quiet(self.sock, shutdown=False)
            except (OSError, RuntimeError) as e:
                log("connect/register failed: %s" % e)
            time.sleep(backoff)
            backoff = min(backoff * 2, BACKOFF_MAX)


def main():
    cfg = load_env_file(ENV_FILE, log)
    ap = argparse.ArgumentParser(description="rsh reverse command channel "
                                             "worker")
    ap.add_argument("--hub", default=env_value(cfg, "RSH_HUB", ""))
    ap.add_argument("--port", type=int,
                    default=int(env_value(cfg, "RSH_PORT", "8790")))
    ap.add_argument("--name", default=canonical_name())
    args = ap.parse_args()

    if not args.hub:
        sys.exit("rsh-worker: no hub address (set RSH_HUB in %s or pass "
                 "--hub; must be resolvable — use the hub's real IP)"
                 % ENV_FILE)
    token = os.environ.get("RSH_TOKEN") or cfg.get("RSH_TOKEN", "")
    if not token:
        sys.exit("rsh-worker: no RSH_TOKEN (set env RSH_TOKEN or add "
                 "RSH_TOKEN to %s)" % ENV_FILE)

    w = Worker(args.hub, args.port, args.name, token)
    try:
        w.run_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

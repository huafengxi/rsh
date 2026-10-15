#!/usr/bin/env python3
"""Sandbox regression test for the rshd fwd unix-socket listeners.

Usage:  python3 rsh/test/fwd_unix_test.py [--rshd PATH] [--base DIR] [--keep]
Expect: RESULT: PASS (18/18 passed), exit code 0 (any FAIL -> exit code 1).

Self-contained sandbox — safe to run next to a live hub:
  * a *second* rshd instance is spawned from the repo source, listening on an
    ephemeral 127.0.0.1 TCP port (the production hub port 8790 is never
    touched),
  * control socket + fwd dir live in a fresh temp dir (production
    run/rsh-fwd/*.sock are never touched),
  * the token is random per run, so real workers cannot register here and this
    test cannot register with the real hub,
  * the forward host list is passed explicitly (--fwd-hosts), so nothing
    depends on the production env/rsh.env,
  * every wait is bounded (no bare wait / sleep-forever); the sandbox rshd is
    terminated in a finally block and the temp dir removed (--keep to inspect).

Covers:
  A. startup sweep of stale *.sock nodes in --fwd-dir; dir mode 0700
  B. bind over a leftover node (real stale unix socket AND a plain file)
     succeeds -> no EADDRINUSE, no WARN, node mode 0600; a worker outside
     --fwd-hosts gets no listener and stays in command mode
  C. end-to-end tunnel over the unix listener (fake worker speaks
     fwd_open/fwd_ack/fwd_data, client gets an HTTP response)
  D. 20x register -> disconnect cycles: node appears then is unlinked,
     no residue, no "Address already in use" in the log
  E. bind failure (fwd dir mode 0500 -> EACCES) -> ERROR + degraded to
     command mode, command channel unaffected; the next registration of the
     same worker restores the listener once the dir is writable again
  F. op list reports fwd_sock (path) and clears it when the worker is gone
"""
import argparse
import base64
import errno
import json
import os
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RSHD_DEFAULT = os.path.join(os.path.dirname(HERE), "rshd.py")

# fake worker names that get a forward listener (E. uses "degraded")
FWD_HOSTS = ["orph", "plain", "flap", "degraded"]
# registered but deliberately outside the forward host list
NO_FWD_HOST = "cmdonly"

results = []          # (name, True/False, detail)
skipped = []          # (name, reason)


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print("%s: %s%s" % ("PASS" if ok else "FAIL", name,
                        ("  | " + str(detail)) if detail else ""))


def skip(name, reason):
    skipped.append((name, reason))
    print("SKIP: %s  | %s" % (name, reason))


def report():
    failed = [r for r in results if not r[1]]
    total = len(results)
    extra = (", %d skipped" % len(skipped)) if skipped else ""
    print("\nRESULT: %s (%d/%d passed%s)"
          % ("PASS" if not failed else "FAIL", total - len(failed), total,
             extra))
    if failed:
        print("failed: %s" % ", ".join(f[0] for f in failed))
    return 1 if failed else 0


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_for(pred, timeout, interval=0.25):
    """Bounded wait: returns (ok, elapsed).

    A predicate raising OSError counts as "not yet", never as an abort: the
    hub unlinks+rebinds listener nodes underneath us, so `exists()`/`stat()`
    in a predicate can legitimately lose that race (TOCTOU) — swallowing it
    here is what keeps a rare race from aborting the whole run."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            if pred():
                return True, time.time() - t0
        except OSError:
            pass
        time.sleep(interval)
    try:
        return bool(pred()), time.time() - t0
    except OSError:
        return False, time.time() - t0


def sock_mode(path):
    """Race-free node probe: mode bits if path is a live socket node, else
    None (missing / not a socket / stat lost the unlink+bind race)."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return stat.S_IMODE(st.st_mode) if stat.S_ISSOCK(st.st_mode) else None


def stale_unix_node(path):
    """Create a real leftover unix socket node (bind, then close without
    unlink) = exactly what a crashed/killed listener leaves behind."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    s.close()


def connect_unix(path, timeout=5):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(path)
    return s


def _connects(path):
    try:
        connect_unix(path, 3).close()
        return True
    except OSError:
        return False


def node_ready(path):
    """Predicate helper: a socket node exists AND accepts a connection."""
    return sock_mode(path) is not None and _connects(path)


class Sandbox(object):
    """Temp-dir + ephemeral-port rshd instance."""

    def __init__(self, rshd, token, base=None):
        self.rshd = rshd
        self.token = token
        self.base = base or tempfile.mkdtemp(prefix="rsh-fwd-sb-")
        self.ctl = os.path.join(self.base, "ctl", "rshd.sock")
        self.fwd_dir = os.path.join(self.base, "fwd")
        self.log = os.path.join(self.base, "rshd.log")
        self.proc = None
        self.port = None

    def prepare(self):
        """Create the layout and plant stale nodes *before* rshd starts;
        returns the planted file names."""
        shutil.rmtree(self.base, ignore_errors=True)
        os.makedirs(os.path.join(self.base, "ctl"))
        os.makedirs(self.fwd_dir)
        stale_unix_node(os.path.join(self.fwd_dir, "deadworker.sock"))
        with open(os.path.join(self.fwd_dir, "plainfile.sock"), "w") as fh:
            fh.write("not a socket\n")
        return sorted(os.listdir(self.fwd_dir))

    def start(self, attempts=3, timeout=15):
        """Spawn the sandbox rshd; True once the control socket is live.
        Bounded retries: the ephemeral port can be taken by someone else in
        the microseconds between picking it and rshd binding it."""
        for _ in range(attempts):
            self.port = free_port()
            self.proc = subprocess.Popen(
                [sys.executable, self.rshd, "--port", str(self.port),
                 "--bind", "127.0.0.1", "--sock", self.ctl,
                 "--fwd-dir", self.fwd_dir,
                 "--fwd-hosts", ",".join(FWD_HOSTS)],
                env=dict(os.environ, RSH_TOKEN=self.token,
                         RSH_FWD_HOSTS=""),
                stdout=open(self.log, "a"), stderr=subprocess.STDOUT)
            if wait_for(lambda: os.path.exists(self.ctl), timeout)[0]:
                return True
            self.stop()                       # failed attempt: clean up
        return False

    def stop(self):
        if self.proc is None:
            return None
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        rc = self.proc.returncode
        self.proc = None
        return rc

    def logtext(self):
        try:
            with open(self.log) as fh:
                return fh.read()
        except OSError:
            return ""

    def cleanup(self):
        self.stop()
        try:
            os.chmod(self.fwd_dir, 0o700)     # E. left it read-only
        except OSError:
            pass
        shutil.rmtree(self.base, ignore_errors=True)


class FakeWorker(object):
    """Minimal rsh-worker: register, answer pings, serve one canned HTTP
    response per forwarded connection, and answer one canned exec."""

    BODY = b"hello-fwd-sandbox"

    def __init__(self, port, token, host, response=None):
        self.host = host
        self.response = response or (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Length: %d\r\n\r\n%s"
            % (len(self.BODY), self.BODY))
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(60)
        self.s.connect(("127.0.0.1", port))
        reg = {"type": "register", "host": host, "token": token}
        self.s.sendall((json.dumps(reg) + "\n").encode())
        self.alive = True
        self.buf = b""
        self.fids = {}
        self.opened = 0
        self.execs = 0
        self.t = threading.Thread(target=self._reader, daemon=True)
        self.t.start()

    def _send(self, obj):
        try:
            self.s.sendall((json.dumps(obj) + "\n").encode())
        except OSError:
            self.alive = False

    def _reader(self):
        while self.alive:
            try:
                chunk = self.s.recv(65536)
            except OSError:
                return
            if not chunk:
                return
            self.buf += chunk
            while b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line.decode())
                except ValueError:
                    continue
                t = msg.get("type")
                if t == "ping":
                    self._send({"type": "pong", "ts": msg.get("ts")})
                elif t == "exec":
                    eid = msg.get("id")
                    self.execs += 1
                    self._send({"type": "out", "id": eid,
                                "data": "exec-ok %s\n" % self.host})
                    self._send({"type": "result", "id": eid, "exit": 0})
                elif t == "fwd_open":
                    fid = msg.get("id")
                    self.fids[fid] = True
                    self.opened += 1
                    self._send({"type": "fwd_ack", "id": fid})
                elif t == "fwd_data":
                    fid = msg.get("id")
                    if fid in self.fids:
                        # canned reply once per tunnel (the request bytes are
                        # consumed and discarded)
                        self.fids.pop(fid, None)
                        self._send({"type": "fwd_data", "id": fid,
                                    "data": base64.b64encode(
                                        self.response).decode()})
                elif t == "fwd_close":
                    self.fids.pop(msg.get("id"), None)

    def close(self):
        # shutdown() first: on Linux close() does not wake a thread blocked
        # in recv() on the same fd (the file description stays alive -> no
        # FIN -> the hub would never see the disconnect). shutdown sends the
        # FIN and wakes our own reader.
        self.alive = False
        try:
            self.s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.s.close()
        except OSError:
            pass


def http_over_unix(path, want, timeout=5):
    """One request/response over the unix listener. The fake worker never
    closes the tunnel (rshd keeps the client socket open), so read until the
    expected body bytes arrived; a bounded recv timeout also ends the read."""
    try:
        s = connect_unix(path, timeout)
    except OSError as e:
        return b"<connect failed: %s>" % str(e).encode()
    s.sendall(b"GET /index.md HTTP/1.1\r\nHost: localhost\r\n\r\n")
    out = b""
    t0 = time.time()
    while want not in out and time.time() - t0 < timeout * 2:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    s.close()
    return out


def ctrl(sb, op):
    """One control-socket round trip; {} if the hub is unreachable (a dead
    hub must surface as a FAIL, never as an exception)."""
    try:
        s = connect_unix(sb.ctl, 10)
        s.sendall((json.dumps(op) + "\n").encode())
        line = s.makefile("r").readline()
        s.close()
        return json.loads(line)
    except (OSError, ValueError):
        return {}


def list_rows(sb):
    reply = ctrl(sb, {"op": "list"})
    return reply.get("workers", []) if reply else None


def fwd_sock_of(sb, host):
    rows = list_rows(sb)
    if rows is None:
        return "<ctrl unreachable>"
    for r in rows:
        if r["host"] == host:
            return r.get("fwd_sock")
    return "<worker not registered>"


def ctrl_exec(sb, host, cmd, timeout=10):
    """One exec round trip over the control socket. Returns
    (exit, stdout, stderr) or (None, "", "<error>") if the hub refused."""
    try:
        s = connect_unix(sb.ctl, timeout)
        s.sendall((json.dumps({"op": "exec", "worker": host, "cmd": cmd,
                               "timeout": timeout}) + "\n").encode())
        out, err, exit_code = "", "", None
        t0 = time.time()
        for line in s.makefile("r"):
            if time.time() - t0 > timeout:
                break
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            t = msg.get("t")
            if t == "out":
                out += msg.get("data", "")
            elif t == "err":
                err += msg.get("data", "")
            elif t == "done":
                exit_code = msg.get("exit")
                break
            elif t == "error":
                return None, "", msg.get("msg", "<error>")
        s.close()
        return exit_code, out, err
    except OSError as e:
        return None, "", str(e)


def worker(sb, host):
    return FakeWorker(sb.port, sb.token, host)


def run_checks(sb, before):
    """A–F against a running sandbox hub."""
    fwd = sb.fwd_dir
    log = sb.logtext
    check("A. startup sweep removed stale *.sock nodes",
          sorted(os.listdir(fwd)) == [],
          "before=%s after=%s" % (before, sorted(os.listdir(fwd))))
    dmode = stat.S_IMODE(os.stat(fwd).st_mode)
    check("A. fwd dir mode 0700", dmode == 0o700, oct(dmode))

    # ---- B. bind over a leftover node (the orphan-socket root cause)
    orph = os.path.join(fwd, "orph.sock")
    stale_unix_node(orph)                     # real stale socket node
    try:                                      # prove it is *dead* first
        connect_unix(orph, 3).close()
        dead_before = False
    except OSError as e:
        dead_before = e.errno == errno.ECONNREFUSED
    plain = os.path.join(fwd, "plain.sock")
    with open(plain, "w") as fh:              # plain file in the way
        fh.write("junk\n")
    w_orph = worker(sb, "orph")
    w_plain = worker(sb, "plain")
    w_cmd = worker(sb, NO_FWD_HOST)
    # inode numbers get recycled after unlink, so "replaced" is proven by
    # connect() succeeding where it was ECONNREFUSED a moment ago
    ok, _ = wait_for(lambda: node_ready(orph), 10)
    ok2, _ = wait_for(lambda: node_ready(plain), 10)
    warn = [l for l in log().splitlines() if "WARN" in l]
    check("B. leftover node was dead before (ECONNREFUSED)", dead_before)
    check("B. bind succeeded over a leftover unix socket node "
          "(connect now accepted = live listener)", ok)
    check("B. bind succeeded over a plain file in the socket path", ok2)
    check("B. no EADDRINUSE / no WARN in rshd log", not warn,
          "; ".join(warn[:3]))
    nmode = sock_mode(orph)
    check("B. listener node is a socket with mode 0600", nmode == 0o600,
          oct(nmode) if nmode is not None else "no socket node at %s" % orph)
    cmd_path = os.path.join(fwd, NO_FWD_HOST + ".sock")
    ok, _ = wait_for(lambda: fwd_sock_of(sb, NO_FWD_HOST) is None
                     and not os.path.exists(cmd_path), 10)
    rows = list_rows(sb) or []
    registered = any(r["host"] == NO_FWD_HOST for r in rows)
    check("B. worker outside --fwd-hosts stays in command mode "
          "(registered, no listener)", ok and registered,
          "fwd_sock=%r node_exists=%s registered=%s"
          % (fwd_sock_of(sb, NO_FWD_HOST), os.path.exists(cmd_path),
             registered))
    check("F. op list reports fwd_sock path",
          fwd_sock_of(sb, "orph") == orph, str(fwd_sock_of(sb, "orph")))

    # ---- C. end-to-end tunnel over the unix listener
    resp = http_over_unix(orph, FakeWorker.BODY)
    check("C. tunnel over unix listener returns the worker's response",
          resp.startswith(b"HTTP/1.1 200 OK") and FakeWorker.BODY in resp,
          "%d bytes, status line %r, worker saw fwd_open=%d"
          % (len(resp), resp.split(b"\r\n")[0], w_orph.opened))

    # ---- D. 20 register/disconnect cycles leave no residue
    residue = []
    cyc = 0
    p = os.path.join(fwd, "flap.sock")
    for i in range(20):
        w = worker(sb, "flap")
        ok, _ = wait_for(lambda: sock_mode(p) is not None, 8)
        if not ok:
            residue.append("cycle %d: node never appeared" % i)
            w.close()
            break
        w.close()
        ok, _ = wait_for(lambda: not os.path.exists(p), 8)
        if not ok:
            residue.append("cycle %d: node left behind" % i)
            break
        cyc = i + 1
    eaddr = [l for l in log().splitlines()
             if "Address already in use" in l or "EADDRINUSE" in l]
    check("D. 20 setup/teardown cycles: no residue, no EADDRINUSE",
          cyc == 20 and not residue and not eaddr,
          "cycles=%d residue=%s eaddrinuse_lines=%d"
          % (cyc, residue[:2], len(eaddr)))
    check("F. fwd_sock cleared after the worker disconnected",
          fwd_sock_of(sb, "flap") == "<worker not registered>",
          str(fwd_sock_of(sb, "flap")))

    # ---- E. bind failure -> ERROR + command mode; next registration heals
    w_orph.close()
    w_plain.close()
    w_cmd.close()
    os.chmod(fwd, 0o500)          # r-x: bind inside fails with EACCES
    w_deg = worker(sb, "degraded")
    dp = os.path.join(fwd, "degraded.sock")
    ok, _ = wait_for(lambda: any("ERROR cannot listen on %s" % dp in l
                                 for l in log().splitlines()), 10)
    check("E. unwritable fwd dir -> ERROR logged, degraded to no forward",
          ok and fwd_sock_of(sb, "degraded") is None
          and not os.path.exists(dp),
          "fwd_sock=%r node_exists=%s"
          % (fwd_sock_of(sb, "degraded"), os.path.exists(dp)))
    ec, out, err = ctrl_exec(sb, "degraded", ["echo", "cmd-channel-ok"])
    check("E. command channel unaffected by the forward failure",
          ec == 0 and "exec-ok degraded" in out,
          "exit=%r out=%r err=%r worker_execs=%d" % (ec, out, err,
                                                     w_deg.execs))
    os.chmod(fwd, 0o700)
    w_deg.close()                            # heal on the next registration
    w_deg2 = worker(sb, "degraded")
    ok, el = wait_for(lambda: node_ready(dp), 20)
    check("E. re-registration restored the listener once the dir was "
          "writable", ok,
          "elapsed=%.1fs fwd_sock=%r" % (el, fwd_sock_of(sb, "degraded")))
    w_deg2.close()
    ok, _ = wait_for(lambda: not os.path.exists(dp), 8)
    check("E. teardown unlinked the restored listener", ok)


def main():
    ap = argparse.ArgumentParser(
        description="rshd fwd unix-listener sandbox regression test")
    ap.add_argument("--rshd", default=os.environ.get("RSH_RSHD", RSHD_DEFAULT),
                    help="rshd.py to exercise (default: ../rshd.py next to "
                         "this test; $RSH_RSHD overrides)")
    ap.add_argument("--base", default=None,
                    help="sandbox dir (default: a fresh tempdir)")
    ap.add_argument("--keep", action="store_true",
                    help="keep the sandbox dir (log + sockets) for inspection")
    args = ap.parse_args()

    if not os.path.exists(args.rshd):
        print("FAIL: rshd.py not found at %s" % args.rshd)
        return 2

    sb = Sandbox(args.rshd, secrets.token_hex(16), base=args.base)
    before = sb.prepare()
    started = False
    try:
        started = sb.start()
        check("rshd sandbox started (control socket live, ephemeral "
              "127.0.0.1 port)", started,
              "port=%s base=%s" % (sb.port, sb.base))
        if started:
            run_checks(sb, before)
        else:
            print("--- rshd sandbox log ---")
            print(sb.logtext())
    finally:
        rc = sb.stop()
        if started:
            check("sandbox rshd terminated (bounded wait, no hang)",
                  rc is not None, "returncode=%s log=%s" % (rc, sb.log))
        else:
            skip("sandbox rshd terminated (bounded wait, no hang)",
                 "the sandbox rshd never came up")
        if args.keep:
            print("sandbox kept at %s" % sb.base)
        else:
            sb.cleanup()
    return report()


if __name__ == "__main__":
    sys.exit(main())

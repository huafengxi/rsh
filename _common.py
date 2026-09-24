#!/usr/bin/env python3
"""Shared helpers of the rsh tools (rshd.py / rsh-worker.py / rsh CLI).

Stdlib only. Every rsh entry point lives in this directory, so it is on
sys.path when they run as scripts; each also inserts its own directory
explicitly so an absolute-path invocation from elsewhere behaves the same.

  WS_ROOT        workspace root every default path is derived from (RSH_WS)
  ENV_FILE       the KEY=VALUE config face (RSH_ENV)
  ENVDEC         decryptor for `enc1:` values (RSH_ENVDEC)
  HOST_ID_FILE   hostname -> canonical worker name table (RSH_HOST_ID)
  REMOTE_WS      cwd prefix of the ssh routes (RSH_REMOTE_WS)
  load_env_file  KEY=VALUE parser, decrypting `enc1:`-prefixed values in memory
                 through ENVDEC (plaintext never lands on disk)
  env_value      process environment wins over the parsed file
  host_list      "a,b c" -> {"a","b","c"} (RSH_NAT_HOSTS / RSH_FWD_HOSTS)
  close_quiet    shutdown-then-close, swallowing OSError
  make_logger    the `[<tag> <ts>] <msg>` line format shared by both daemons

Path resolution: the defaults assume the in-workspace layout `<ws>/rsh/`, i.e.
WS_ROOT is this repo's parent directory and holds `env/` + `encrypt/` + `run/`.
A standalone checkout sets RSH_WS (or overrides any single path with its own
variable); all five are read at import time.
"""
import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WS_ROOT = os.environ.get("RSH_WS") or os.path.dirname(HERE)
ENV_FILE = os.environ.get("RSH_ENV") or os.path.join(WS_ROOT, "env", "rsh.env")
ENVDEC = os.environ.get("RSH_ENVDEC") or os.path.join(WS_ROOT, "encrypt", "envdec.py")
HOST_ID_FILE = os.environ.get("RSH_HOST_ID") or os.path.join(WS_ROOT, "env", "host-id")
# Expanded by the REMOTE shell, so it is interpolated unquoted into a command
# string on purpose (quoting it would defeat `~`). Operator-controlled config,
# not user input.
REMOTE_WS = os.environ.get("RSH_REMOTE_WS") or "~/m"


def make_logger(tag):
    def log(msg):
        print("[%s %s] %s" % (tag, time.strftime("%Y-%m-%d %H:%M:%S"), msg),
              flush=True)
    return log


def load_env_file(path, log=None):
    """Parse KEY=VALUE lines (`export ` prefix and quoting tolerated);
    `enc1:` values are decrypted in memory. Undecryptable keys are skipped
    (via `log` when given) rather than aborting the caller."""
    out = {}
    try:
        with open(path) as fh:
            text = fh.read()
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[7:]
        val = val.strip().strip('"').strip("'")
        if val.startswith("enc1:"):
            r = subprocess.run(
                [sys.executable, ENVDEC, "--value", val[len("enc1:"):]],
                capture_output=True, text=True)
            if r.returncode != 0:
                if log is not None:
                    log("ERROR: failed to decrypt %s from %s" % (key, path))
                continue
            val = r.stdout.rstrip("\n")
        out[key] = val
    return out


def env_value(cfg, key, default=None):
    """Process environment wins over the parsed env file (override/test
    friendly)."""
    return os.environ.get(key, cfg.get(key, default))


def host_list(raw):
    """Comma- and/or space-separated host list -> set of names."""
    return {h for h in (raw or "").replace(",", " ").split() if h}


def close_quiet(sock, shutdown=True):
    """shutdown(SHUT_RDWR) then close(), ignoring OSError on both.

    The shutdown is not cosmetic: a peer thread may be blocked in recv() on
    this socket, and close() alone neither wakes it nor sends the FIN until
    that syscall returns."""
    if sock is None:
        return
    if shutdown:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    try:
        sock.close()
    except OSError:
        pass

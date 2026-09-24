#!/usr/bin/env python3
"""rsh — CLI for the reverse command channel.

  rsh -l                            list registered workers (via rshd; if no
                                    local rshd.sock, nested over ssh to the
                                    hub — source is annotated on stderr).
                                    FWD column = the worker's hub-side unix
                                    socket listener (run/rsh-fwd/<w>.sock),
                                    '-' if it has no forward
  rsh <worker> [-t N] -- cmd [args...]
                                    default mode: run cmd on <worker>, stream
                                    output, exit with the remote exit code
                                    (124 on timeout, 125 on local errors).
                                    Everything after '--' is argv: the first
                                    word is the command, the rest are its
                                    arguments (each shlex-quoted, so word
                                    boundaries survive the trip and shell
                                    metacharacters are inert). Pipes, globs,
                                    ';'/'&&' chains and $VARS therefore do NOT
                                    work as typed — for a composite command
                                    write one shell string:
                                        rsh <w> -- bash -lc 'cd d && a | b > c'
                                    A bare compound string without '--'
                                    ('rsh <w> "a; b"') is rejected:
                                    unrecognized arguments.
  rsh <worker> -f <file|-> [-t N] [--] [args...]
                                    ship a local script to the worker, run it
                                    with bash (args after '--' passed through
                                    as $1..), pass through its exit code,
                                    clean up the remote temp file.
                                    <file|->: '-' reads stdin.
                                    rshd path: auto base64 wrapper (max 10MB);
                                    ssh path: stdin pipe (no temp file;
                                    bash -s -- ends option parsing).

Options: -l list workers; -f FILE ship a local script; -t N timeout seconds
(default 60); -v routing details. There are no subcommands: the mode follows
from the flags, and the command/script args must come after '--' (mandatory
for the default exec mode).

Argv semantics: the words after '--' are handed over as argv, shlex-quoted and
joined into one string, then run by a shell — rshd path: worker-side
`bash -c '<joined>'` (rsh-worker.py run_exec); ssh path: handed to the remote
login shell with a `cd <remote ws> && ` prefix (ssh_run; REMOTE_WS, default
`~/m`). Quoting is deliberate: it keeps argument
boundaries intact and blocks shell injection. Consequence: shell syntax in your
words is literal text, not syntax — use `bash -lc '<one string>'` when you need
pipes, redirection, chains or expansion.

Note: the rsh *tool* (agent-side, action=exec) passes its whole `command`
string through as a single argv word, so a composite string typed there does
reach the remote shell — this CLI does not accept that form.

Routing:
  - target in RSH_NAT_HOSTS (config face $RSH_ENV; default: mac) -> rshd channel
    via the local control unix socket run/rsh/rshd.sock (override with RSH_SOCK);
    if the socket does not exist locally (e.g. the CLI runs on a worker like
    mac), nest over `ssh <RSH_HUB>` and run this same CLI on the hub.
  - any other target -> plain `ssh <host>` (BatchMode), argv shlex-joined and
    handed to the remote login shell, matching the `bash -c` semantics of the
    rshd path.

Every route runs with the same cwd: the rshd path inherits the worker's startup
directory, the ssh routes prefix `cd <REMOTE_WS> && ` (RSH_REMOTE_WS, default
`~/m`) so callers can use workspace-relative paths on either route.

-v in the flags section (before the first '--') prints the routing decision
on stderr; after '--' a literal -v passes through untouched (it belongs to
the user's command/script args).
Python 3 stdlib only. See README.md.
"""
import argparse
import base64
import json
import os
import shlex
import socket
import subprocess
import sys
import textwrap

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (WS_ROOT, REMOTE_WS, ENV_FILE, env_value, host_list,  # noqa: E402
                     load_env_file)

DEFAULT_SOCK = os.path.join(WS_ROOT, "run", "rsh", "rshd.sock")
EXIT_LOCAL_ERROR = 125
EXIT_TIMEOUT = 124
EXEC_FILE_MAX = 10 * 1024 * 1024   # rshd-path base64 payload cap (10MB)
SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]

def flag_section(argv):
    """The part of argv before the first '--' (flags section). Everything
    after '--' belongs to the user's command/script args and must pass
    through untouched."""
    if "--" in argv:
        return argv[:argv.index("--")]
    return argv


VERBOSE = "-v" in flag_section(sys.argv[1:])


def vlog(msg):
    if VERBOSE:
        sys.stderr.write("rsh: %s\n" % msg)


ENV_CFG = load_env_file(ENV_FILE)


def env_get(key, default=None):
    return env_value(ENV_CFG, key, default)


def nat_hosts():
    return host_list(env_get("RSH_NAT_HOSTS", "mac"))


def hub_addr():
    return env_get("RSH_HUB", "")


def connect(sock_path):
    if not os.path.exists(sock_path):
        sys.stderr.write(
            "rsh: control socket %s not found — is rshd running "
            "(make rshd.start)?\n" % sock_path)
        sys.exit(EXIT_LOCAL_ERROR)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(sock_path)
    except OSError as e:
        sys.stderr.write("rsh: cannot connect to rshd: %s\n" % e)
        sys.exit(EXIT_LOCAL_ERROR)
    return s


def fwd_label(w):
    """FWD column: the hub-side inbound listener of this worker — a unix
    socket path (absolute on the hub), shown relative to the workspace root
    when possible so the column stays narrow. '-' = no forward."""
    path = w.get("fwd_sock")
    if not path:
        return "-"
    root = WS_ROOT + os.sep
    return path[len(root):] if path.startswith(root) else path


def human_age(secs):
    if secs < 60:
        return "%ds" % secs
    if secs < 3600:
        return "%dm%02ds" % (secs // 60, secs % 60)
    if secs < 86400:
        return "%dh%02dm" % (secs // 3600, (secs % 3600) // 60)
    return "%dd%dh" % (secs // 86400, (secs % 3600) // 3600)


# ---------------------------------------------------------------- ssh path

def ssh_run(host, remote_cmd, timeout, stdin_file=None):
    """Run remote_cmd (a ready shell string) on host via plain ssh, streaming
    output. Returns exit code (124 on timeout). ssh hands the string to the
    remote login shell (-c), matching the rshd path's bash -c semantics.
    stdin_file: an OS-level file object (has fileno), e.g. open(tmp,'rb')."""
    cmd = ["ssh"] + SSH_OPTS + [host, "--", remote_cmd]
    vlog("ssh exec: %s" % " ".join(shlex.quote(c) for c in cmd))
    try:
        proc = subprocess.Popen(cmd, stdin=stdin_file)
    except OSError as e:
        sys.stderr.write("rsh: cannot spawn ssh: %s\n" % e)
        return EXIT_LOCAL_ERROR
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        sys.stderr.write("rsh: timeout after %.0fs\n" % timeout)
        return EXIT_TIMEOUT
    return rc & 0xFF


# ----------------------------------------------------------- hub nesting

def hub_nested(sub_args, stdin_file=None, timeout=60.0):
    """No local rshd.sock: ssh to the hub and run the CLI there, located as
    `<REMOTE_WS>/rsh/rsh` on the hub (home dirs differ across machines, e.g.
    /Users on mac — never reuse the local absolute path). sub_args = argv after
    'rsh'. This process's stdin is piped through (-f mode ships the file)."""
    hub = hub_addr()
    if not hub:
        sys.stderr.write("rsh: no local rshd.sock and RSH_HUB not set in %s "
                         "— cannot reach hub\n" % ENV_FILE)
        return EXIT_LOCAL_ERROR
    vlog("hub-nested ssh to %s: rsh %s" % (hub, " ".join(sub_args)))
    remote_cmd = ("cd " + REMOTE_WS + " && exec rsh/rsh "
                  + " ".join(shlex.quote(str(a)) for a in sub_args))
    return ssh_run(hub, remote_cmd, timeout, stdin_file=stdin_file)


# ------------------------------------------------------------- rshd path

def cmd_list(sock_path):
    if not os.path.exists(sock_path):
        sys.stderr.write("# rsh -l: no local rshd.sock, via hub ssh\n")
        return hub_nested(["-l"])
    s = connect(sock_path)
    s.sendall((json.dumps({"op": "list"}) + "\n").encode())
    f = s.makefile("r")
    line = f.readline()
    try:
        resp = json.loads(line)
    except ValueError:
        sys.stderr.write("rsh: bad response from rshd\n")
        return EXIT_LOCAL_ERROR
    if resp.get("t") == "error":
        sys.stderr.write("rsh: %s\n" % resp.get("msg"))
        return EXIT_LOCAL_ERROR
    workers = resp.get("workers", [])
    if not workers:
        print("(no workers registered)")
        return 0
    print("%-16s %12s %12s %s" % ("WORKER", "CONNECTED", "LAST-SEEN",
                                  "FWD"))
    for w in workers:
        print("%-16s %12s %12s %s"
              % (w["host"], human_age(w["connected_secs"]),
                 human_age(w["last_seen_secs"]), fwd_label(w)))
    return 0


def rshd_exec(sock_path, worker, timeout, argv):
    """Existing rshd control-socket exec (protocol unchanged)."""
    if not argv:
        sys.stderr.write("rsh: empty command\n")
        return EXIT_LOCAL_ERROR
    s = connect(sock_path)
    s.sendall((json.dumps({"op": "exec", "worker": worker, "cmd": argv,
                           "timeout": timeout}) + "\n").encode())
    f = s.makefile("r")
    try:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            t = msg.get("t")
            if t == "out":
                sys.stdout.write(msg.get("data", ""))
                sys.stdout.flush()
            elif t == "err":
                sys.stderr.write(msg.get("data", ""))
                sys.stderr.flush()
            elif t == "done":
                if msg.get("timeout"):
                    sys.stderr.write("rsh: timeout after %.0fs\n" % timeout)
                try:
                    return int(msg.get("exit", EXIT_LOCAL_ERROR)) & 0xFF
                except (TypeError, ValueError):
                    # malformed exit field: normalise instead of dumping a
                    # traceback into the protocol stream
                    sys.stderr.write("rsh: malformed exit field in result\n")
                    return EXIT_LOCAL_ERROR
            elif t == "error":
                sys.stderr.write("rsh: %s\n" % msg.get("msg"))
                return EXIT_LOCAL_ERROR
    except KeyboardInterrupt:
        sys.stderr.write("rsh: interrupted locally (remote job may still "
                         "run until hub timeout)\n")
        return 130
    sys.stderr.write("rsh: rshd closed connection without result\n")
    return EXIT_LOCAL_ERROR


# -------------------------------------------------------------- routing

def route_exec(sock_path, worker, timeout, argv, sub_args):
    """Dispatch exec by target: NAT host -> rshd (or hub-nested ssh); other
    hosts -> direct ssh. sub_args = full CLI argv tail for nesting."""
    if worker in nat_hosts():
        if os.path.exists(sock_path):
            vlog("route: rshd local sock %s (NAT host)" % sock_path)
            return rshd_exec(sock_path, worker, timeout, argv)
        vlog("route: hub-nested ssh (NAT host, no local sock)")
        return hub_nested(sub_args, timeout=timeout + 30)
    vlog("route: direct ssh to %s (non-NAT host)" % worker)
    # cd <REMOTE_WS>: 直连 ssh 默认 cwd = 远端 home，前置 cd 使各路由统一，
    # 与 rshd 路径（worker 启动目录）语义对齐。
    return ssh_run(worker, "cd " + REMOTE_WS + " && "
                   + " ".join(shlex.quote(str(a)) for a in argv),
                   timeout)


def wrap_exec_file_script(data, args):
    """Build the single shell command for the rshd path: decode base64 into a
    mktemp file, run it with bash + args, pass through exit code, always
    clean up (trap covers killpg on timeout)."""
    if len(data) > EXEC_FILE_MAX:
        sys.stderr.write(
            "rsh: file payload %d bytes exceeds %d-byte cap for the "
            "rshd path (use ssh-reachable hosts for larger files)\n"
            % (len(data), EXEC_FILE_MAX))
        sys.exit(EXIT_LOCAL_ERROR)
    b64 = base64.b64encode(data).decode("ascii")
    # wrap at 76 chars so no single line blows up the JSON-lines stream
    payload = "\n".join(textwrap.wrap(b64, 76)) or ""
    quoted_args = " ".join(shlex.quote(str(a)) for a in args)
    return (
        'T=$(mktemp /tmp/rsh-ef-XXXXXX) || exit %d\n'
        'trap \'rm -f "$T"\' EXIT INT TERM\n'
        "printf '%%s\\n' '%s' | base64 -d > \"$T\" || exit %d\n"
        'bash "$T"%s; ec=$?; rm -f "$T"; exit $ec\n'
        % (EXIT_LOCAL_ERROR, payload, EXIT_LOCAL_ERROR,
           (" " + quoted_args) if quoted_args else ""))


def _stdin_from_bytes(data):
    """ssh stdin needs a real fd: spool bytes to a local temp file."""
    import tempfile
    tf = tempfile.NamedTemporaryFile(prefix="rsh-ef-", delete=True)
    tf.write(data)
    tf.flush()
    tf.seek(0)
    return tf


def cmd_exec_file(sock_path, worker, timeout, file_arg, args):
    """-f mode: ship file_arg ('-' = stdin) to the worker, run with bash."""
    # read the local file ('-' = stdin)
    try:
        if file_arg == "-":
            data = sys.stdin.buffer.read()
        else:
            with open(file_arg, "rb") as fh:
                data = fh.read()
    except OSError as e:
        sys.stderr.write("rsh: cannot read %s: %s\n" % (file_arg, e))
        return EXIT_LOCAL_ERROR

    if worker in nat_hosts():
        script = wrap_exec_file_script(data, args)
        if os.path.exists(sock_path):
            vlog("route: -f via rshd local sock (base64 wrapper, "
                 "%d bytes -> %d b64)" % (len(data), len(script)))
            return rshd_exec(sock_path, worker, timeout,
                             ["bash", "-c", script])
        vlog("route: -f via hub-nested ssh (file piped on stdin)")
        sub = [worker, "-f", "-", "-t", str(timeout)]
        if args:
            sub += ["--"] + [str(a) for a in args]
        return hub_nested(sub, stdin_file=_stdin_from_bytes(data),
                          timeout=timeout + 60)
    vlog("route: -f via direct ssh (stdin pipe, no temp file)")
    # bash -s reads the script from stdin; args become $1.. in the script.
    # '--' ends bash option parsing so args starting with '-' (e.g. -v)
    # land as positional params instead of bash options.
    remote = "cd " + REMOTE_WS + " && " + " ".join(shlex.quote(str(a))
                                                   for a in ["bash", "-s", "--"]
                                                   + [str(a) for a in args])
    return ssh_run(worker, remote, timeout,
                   stdin_file=_stdin_from_bytes(data))


# ----------------------------------------------------------------- main

def main():
    sock_path = os.environ.get("RSH_SOCK", DEFAULT_SOCK)
    raw = sys.argv[1:]
    if not raw:
        sys.stderr.write(__doc__)
        sys.exit(EXIT_LOCAL_ERROR)

    # strip -v from the flags section only; keep everything from the first
    # '--' on verbatim (never touch user command args)
    nflags = len(flag_section(raw))
    flags = [a for a in raw[:nflags] if a != "-v"]
    tail = raw[nflags:]          # [] or ['--', *user command/script args]
    user_args = tail[1:]

    ap = argparse.ArgumentParser(
        prog="rsh",
        usage="rsh -l | rsh <worker> [-f <file|->] [-t N] [-v] -- cmd "
              "[args...]   (words after '--' are argv, each quoted: for "
              "pipes/chains use -- bash -lc '<string>')",
        epilog="modes: no flags = exec (command after '--' is mandatory); "
               "-f = ship a local script ('-' reads stdin) and run it with "
               "bash; -l = list online workers. Words after '--' are argv "
               "(shlex-quoted, then `bash -c`), so shell syntax is literal — "
               "for pipes, redirection, ';'/'&&' chains or $VARS use "
               "`-- bash -lc '<string>'`.",
    )
    ap.add_argument("-l", "--list", action="store_true",
                    help="list online workers")
    ap.add_argument("-f", "--file", metavar="FILE",
                    help="ship FILE ('-' = stdin) to <worker> and run it "
                         "with bash (args after '--' become $1..)")
    ap.add_argument("-t", "--timeout", type=float, default=60.0, metavar="N",
                    help="timeout in seconds (default 60)")
    ap.add_argument("worker", nargs="?", help="target worker name")

    # subcommand-style invocations are the most common misuse: point at the
    # flag forms instead of treating the word as a worker name
    if flags and flags[0] in ("list", "exec", "exec-file"):
        ap.error("%r is not a worker name — this CLI has no subcommands; "
                 "use `rsh -l`, `rsh <worker> [-t N] -- cmd`, "
                 "`rsh <worker> -f <file|-> [-t N] [-- args...]`"
                 % flags[0])
    ns = ap.parse_args(flags)

    if ns.list:
        if (ns.worker or ns.file is not None or tail
                or "-t" in flags or "--timeout" in flags):
            ap.error("-l takes no other options or arguments")
        sys.exit(cmd_list(sock_path))

    if not ns.worker:
        ap.error("missing <worker> (use -l to list online workers)")

    if ns.file is not None:
        # -f mode: args after '--' are the script's $1.. (optional)
        sys.exit(cmd_exec_file(sock_path, ns.worker, ns.timeout, ns.file,
                               user_args))

    # default exec mode: command after '--' is mandatory
    if not tail:
        ap.error("missing command — use `rsh %s [-t N] -- cmd [args...]` "
                 "(words after '--' are argv; for a composite command use "
                 "`-- bash -lc '<string>'`)" % ns.worker)
    if not user_args:
        ap.error("missing command after '--'")
    sys.exit(route_exec(sock_path, ns.worker, ns.timeout, user_args, raw))


if __name__ == "__main__":
    main()

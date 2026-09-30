# rsh — reverse command channel

Solves the operational dead end of "the hub cannot dial machines behind
NAT/firewall": instead of the hub connecting to the workers, **each worker
dials out to the hub and keeps the connection open**, and the hub pushes
commands down that established channel. A machine that only ever makes outbound
connections is fully manageable.

Three pieces, all Python 3 stdlib only:

| File | Role |
|---|---|
| `rshd.py` | the hub daemon (one machine): token-gated TCP listener + the local control socket the CLI talks to + the inbound port-forward listeners |
| `rsh-worker.py` | the worker daemon (every managed machine): dials the hub, registers, runs pushed commands, tunnels forwarded connections |
| `rsh` | the CLI: `-l` list workers, default mode exec, `-f` ship a script |
| `_common.py` | shared by all three: path resolution, config parsing (with in-memory decryption), host-list parsing, logging, quiet socket close |

```
                    TCP 8790 (token-gated, workers dial out)
   hub: rshd.py ◄──────────────── rsh-worker.py  (worker-a, worker-b, …)
        ▲  unix socket run/rsh/rshd.sock (0600)          ← control face (CLI)
        │
   hub: rsh                                              (rsh -l / exec / -f)

        ▲  unix socket run/rsh-fwd/<worker>.sock (0600, dir 0700)
        │                                                ← data face (inbound port forward)
   hub: any local process that can dial a unix socket
```

## Quick start

```bash
# hub machine
printf 'RSH_PORT=8790\nRSH_TOKEN=<a long random string>\n' > /etc/rsh.env
RSH_ENV=/etc/rsh.env python3 rshd.py

# every worker (NAT'd or not)
printf 'RSH_HUB=203.0.113.7\nRSH_PORT=8790\nRSH_TOKEN=<same token>\n' > /etc/rsh.env
RSH_ENV=/etc/rsh.env python3 rsh-worker.py --name worker-a

# from the hub (or from anywhere that can ssh to it)
RSH_ENV=/etc/rsh.env rsh -l
RSH_ENV=/etc/rsh.env rsh worker-a -- hostname
```

Run both daemons under whatever supervisor you use; neither needs a working
directory (all defaults are derived from the file locations and `RSH_WS`).

## Configuration

One KEY=VALUE file (`export ` prefix and quoting tolerated, `#` comments), read
at startup; **the process environment always wins over the file**, which makes
per-invocation overrides and tests easy. A value carrying the `enc1:` prefix is
decrypted in memory through the decryptor (contract below), so the file can be
committed without plaintext secrets.

Decryptor contract: `<python> <decryptor> --value <cipher>` prints the plaintext
on stdout. The default is `<ws>/encrypt/envdec.py`; point `RSH_ENVDEC` at any
script honouring that contract (or at a no-op passthrough if you keep the token
in the environment instead).

| Variable | Meaning | Default |
|---|---|---|
| `RSH_WS` | workspace root: `env/`, `encrypt/` and `run/` defaults resolve against it | this repo's parent directory |
| `RSH_ENV` | the config file | `<ws>/env/rsh.env` |
| `RSH_ENVDEC` | decryptor for `enc1:` values | `<ws>/encrypt/envdec.py` |
| `RSH_HOST_ID` | `<hostname> <canonical name>` table used for the worker name | `<ws>/env/host-id` |
| `RSH_REMOTE_WS` | cwd prefix the ssh routes send to the remote shell | `~/m` |
| `RSH_TOKEN` | the shared secret (hub + every worker) | — (required) |
| `RSH_HUB` | hub address **as the worker resolves it** (worker) / ssh target for CLI nesting (CLI) | — (required on workers) |
| `RSH_PORT` | TCP port | `8790` |
| `RSH_BIND` | hub listen address | `0.0.0.0` |
| `RSH_SOCK` | hub control socket | `<ws>/run/rsh/rshd.sock` |
| `RSH_NAT_HOSTS` | CLI routing: which targets go over the reverse channel (comma/space separated) | `mac` |
| `RSH_FWD_HOSTS` | hub side: which worker names get an inbound forward listener | empty (pure command mode) |
| `RSH_FWD_DIR` | directory of those listeners | `<ws>/run/rsh-fwd` |
| `RSH_FWD_TARGET` | worker-side port the tunnels dial | `8080` |

CLI flags: `-l` list, `-f <file|->` ship a script, `-t N` timeout seconds
(default 60), `-v` print the routing decision on stderr. `rshd.py` also accepts
`--bind/--port/--sock/--fwd-dir/--fwd-target/--fwd-hosts`, `rsh-worker.py`
`--hub/--port/--name`; every flag defaults to its variable above.

**`RSH_HUB` must be an address the worker can actually resolve.** The worker
dials it directly, so ssh-config aliases do not apply — short names that only
exist in `~/.ssh/config` will fail (and a short name that happens to exist in
DNS may resolve somewhere unintended). Use an IP, or a name in `/etc/hosts`. A
missing `RSH_HUB` makes the worker exit immediately instead of retrying forever.

**Worker names**: `--name` wins; otherwise the hostname is looked up in the
host-id table for a canonical alias, falling back to the raw hostname. A
duplicate name re-registration supersedes the previous connection on the hub.

## Routing (CLI)

Only NAT'd targets need the reverse channel; everything else is plain ssh:

- target listed in `RSH_NAT_HOSTS` → the hub's control socket
  (`run/rsh/rshd.sock`, or `RSH_SOCK`).
- no local control socket (e.g. the CLI runs on a worker) → nest over
  `ssh <RSH_HUB>` and run this same CLI on the hub, located as
  `<RSH_REMOTE_WS>/rsh/rsh` (home directories differ across machines — the local
  absolute path is never reused). `-l` nests the same way and annotates the
  source on stderr.
- any other target → direct `ssh <host>` (`BatchMode=yes`, `ConnectTimeout=10`),
  argv shlex-joined and handed to the remote login shell, matching the rshd
  route's `bash -c` semantics. Requires working ssh trust for that host.

`-v` in the flag section (before the first `--`) prints the decision
(`route: direct ssh …` / `route: rshd local sock …` / `route: hub-nested ssh …`);
a literal `-v` after `--` belongs to the user's command and passes through.

## Usage

```bash
rsh -l                                  # workers: name / connected / last-seen / forward listener
rsh worker-a -- hostname                # default mode is exec
rsh worker-a -t 120 -- df -h            # -t = timeout seconds (default 60)
rsh worker-a -- bash -lc 'uptime && whoami'   # composite command: wrap it yourself
rsh worker-a -f ./script.sh -- a b      # ship a script, args become $1..
```

There are **no subcommands**: the mode follows from the flags (`rsh list` /
`rsh exec` are usage errors, exit 2), and the command must come after `--`.

**Argv semantics — the one real gotcha.** The words after `--` are handed over
as argv, each `shlex.quote`d and joined into a single string that a shell then
runs. Word boundaries survive and shell metacharacters are inert, so a
composite command must be written as one shell string yourself:

```bash
rsh worker-a -- bash -lc 'hostname && uptime -s'   # ✅ wrapped in a shell
rsh worker-a -- 'hostname && uptime -s'            # ❌ one single command *name*
#   remote stderr: bash: line 1: hostname && uptime -s: command not found
```

Exit 127 there means the remote could not find that "command name" — an assembly
mistake, not a channel fault. Quoting is deliberate: it is what blocks shell
injection through arguments.

**`-f` runs the shipped file with `bash`, whatever its own shebang says.** The
payload is copied to a remote temp path and executed as `bash "$T" <args>` (see
`wrap_exec_file_script`); the exit code passes through and the temp file is
removed either way. So a `.py` payload is read line by line as shell — remote
stderr fills with `import: command not found` and nothing gets written. Ship a
bash wrapper when the payload is another language:

```bash
rsh worker-a -f ./run.sh -- a b     # ✅ run.sh is bash; it can embed a heredoc:
                                    #    python3 - "$@" <<'PYEOF' … PYEOF
rsh worker-a -f ./tool.py -- a b    # ❌ executed by bash, not by python
```

**Every route runs with the same cwd**: the rshd route inherits the worker's
startup directory, the ssh routes prefix `cd <RSH_REMOTE_WS> && `, so callers can
use workspace-relative paths on either route.

Output is streamed back (≤64KB chunks, stdout/stderr kept apart) and the remote
exit code is passed through. Exit codes: remote code as-is · **124** timeout ·
**125** local error (hub not running, worker not registered, unreadable file,
oversized payload) · **2** usage · **255** ssh's own failure (host unreachable /
unknown) on a direct route.

**Timeout semantics differ between routes.** The rshd route kills the remote
process group (`killpg`), so the remote is definitely cleaned up. The ssh route
can only kill the local ssh process: with `BatchMode` and no tty, sshd does not
send SIGHUP, so **the remote job may keep running**. If you need "timeout always
cleans the remote", use the rshd route (add the target to `RSH_NAT_HOSTS`) or
carry your own timeout in the remote command (`timeout <N> <cmd>`).

## Shipping a script (`-f`)

```bash
rsh <worker> -f <local file|-> [-t N] [--] [args...]
```

The file is run with `bash` on the worker, args after `--` become `$1..`, its
exit code is passed through, and the remote temp file is cleaned up. `-` reads
the script from stdin (that is how the hub-nested route ships it).

- **ssh route**: `ssh <host> -- bash -s -- <args> < file` — the script travels
  over stdin, no temp file on the remote.
- **rshd route**: the CLI wraps it in base64 (transparent to the caller; the
  hub/worker protocol is unchanged): remote `mktemp /tmp/rsh-ef-XXXXXX` → decode
  → `bash` → delete, with `trap … EXIT INT TERM` so a timeout `killpg` still
  cleans up. **Payload cap 10MB** (over it: exit 125) — for larger files use a
  host you can ssh to directly.

## Port forwarding

For every online worker named in `RSH_FWD_HOSTS` the hub listens on a unix
socket `<fwd-dir>/<worker>.sock` (dir 0700, node 0600) and tunnels each inbound
connection over the same long-lived channel to that worker's
`127.0.0.1:<fwd-target>`. This is how a NAT'd machine's local HTTP service
becomes reachable from the hub: point any unix-socket-capable proxy at the node.
**The paths are not configurable per worker** — the hub derives them from the
worker name (single source of truth), and consumers use the same convention.

Listener lifecycle follows registration: opened on register, closed (fd +
`unlink` of the node) on disconnect or eviction; a same-name re-registration
keeps the listener and re-points it at the new connection, dropping the old
connection's in-flight tunnels (the new one cannot know their fids); at startup
the hub creates the directory and sweeps leftover `*.sock` from a previous
generation.

**The inbound listener must stay a unix socket, never a TCP port.** With a unix
socket, "occupied" *is* the filesystem node, so `bind()` can `unlink` any
leftover first and cannot fail with `EADDRINUSE`. In TCP form, frequent
bind→close→rebind makes the kernel occasionally keep a closed `LISTEN` socket
unreclaimed; `SO_REUSEADDR` does not help on an active `LISTEN` and killing the
socket administratively is refused — the only remedy is rebooting the hub. That
failure recurred often enough to become a design invariant.

A bind failure (directory permissions, path too long, filesystem error =
configuration class) is logged as `ERROR` and degrades that worker to pure
command mode; its **next registration** retries. **A forwarding problem never
touches the command channel** — every forward path is fail-soft.

Tunnel messages: `fwd_open{id,port}` (hub→worker, dial request) / `fwd_ack{id}` /
`fwd_data{id,data}` (base64, ≤64KB raw per chunk, both directions) /
`fwd_close{id}` (either side; a close or error propagates). Data arriving before
the worker's upstream dial completes is buffered, capped at 4MB.

## Protocol (JSON-lines over one TCP connection)

- **Register**: the worker's first line is
  `{"type":"register","host":<name>,"token":…}`; the hub answers
  `{"type":"registered"}` or closes immediately and logs `DENY`. **The hub sends
  nothing before a valid registration**, so a port scan learns nothing. The token
  is compared in constant time and a non-string token is rejected without
  raising.
- **Heartbeat**: hub `ping` every 30s, worker `pong`; the hub evicts after >90s
  of silence, the worker self-heals (reconnect) after >100s; reconnect backoff is
  exponential 1→60s.
  **Eviction is usually a consequence of the peer being suspended, not a channel
  fault**: while a laptop sleeps, the worker process is frozen, so the hub's
  timer keeps running and the worker's does not. The `evicting` / `registered`
  pair therefore shows up 1–2s after the peer wakes — check for that before
  debugging the link. A `worker <name> disconnected` line can also lag the
  eviction by tens of seconds (measured 34–90s, median ~58s): that is the kernel
  giving up on the orphaned connection, not a second disconnect. A `disconnected`
  within ~1s and with no `evicting` line means the peer closed deliberately.
- **Exec**: `exec{id,cmd,timeout}` → `out`/`err` chunks → `result{id,exit}`;
  `cancel{id}` kills the process group. Every exec is its own session and
  process group (`start_new_session`) so a timeout or cancel can `killpg` the
  whole tree, and the worker runs its own timer with the same timeout (missing/0
  → 60s) so a lost cancel — or a dead hub — still terminates the job. One
  connection carries many concurrent execs keyed by `id`; a duplicate `id`
  reclaims ownership (the old process group is killed, and a generation check
  keeps the superseded thread from popping the new entry or emitting a late
  result).
- **Line limit 1MB**: an authenticated connection that keeps sending an
  unterminated oversized line is dropped rather than buffered without bound.
- **CLI ↔ hub**: the unix control socket (0600, dir 0700) speaks
  `{"op":"list"}` (reports each worker's `fwd_sock`, which is what the CLI's FWD
  column shows; null when it has no forward) and
  `{"op":"exec","worker":…,"cmd":[…],"timeout":N}`, streamed back as
  `{"t":"out"/"err","data"}` then `{"t":"done","exit":N,"timeout":bool}` or
  `{"t":"error","msg":…}`.

Both daemons keep the reader socket **blocking** on purpose: a socket timeout
would permanently poison the buffered reader, so a watchdog thread shuts the
socket down on hub silence instead. An upstream socket is closed with `shutdown`
before `close`, otherwise a thread blocked in `recv()` is never woken.

## Security and trust model

- **The only authentication is the shared token.** Holding it is equivalent to
  ssh trust across every online worker: anyone with it can run arbitrary
  commands as that machine's local user. Use it between your own machines only,
  and treat a leak as "all machines compromised" — rotate immediately (new
  random token → update the config face on every machine → restart every hub and
  worker).
- **Minimal attack surface**: command execution plus hub-authorised port
  forwarding, nothing else. `-f` file shipping is implemented entirely in the
  CLI (ssh stdin / base64 wrapping) and adds no protocol face.
- **The forward listeners are local unix sockets** (node 0600, dir 0700), so
  access is governed by filesystem permissions: only the hub user (and root) can
  connect. There is **no unauthenticated TCP port reachable from another
  machine**; if you expose a forward further, put your own authentication in
  front of it and remember that the upstream's own auth is the last line.
- Binding `0.0.0.0:8790` on the hub is deliberate (workers must be able to reach
  it from anywhere); the token is the only gate. The control face and the forward
  face are both local 0600 unix sockets and grant nothing extra.

## Tests

```bash
python3 test/fwd_unix_test.py       # expect: RESULT: PASS (19/19 passed), exit 0
```

A self-contained sandbox for the forwarding face: a temp directory, temp
loopback ports, a fresh random token per round and an explicitly started
**second** hub instance — it never touches a production port, a production
forward directory or the online workers, and can run alongside them.
`--rshd PATH` selects the hub under test (default: this repo's `rshd.py`),
`--keep` keeps the sandbox for log inspection.

Coverage A–G: startup sweep and directory permissions / binding over a leftover
node (dead socket and regular file) while workers outside the list stay in pure
command mode / an end-to-end tunnel / 20 register-disconnect cycles with no
residue / a bind failure degrading to `ERROR` with the command channel untouched
and self-healing on the next registration / `op list` reporting and clearing
`fwd_sock` / `AF_INET` appearing exactly once in `rshd.py` (the forward face must
not regress to TCP).

Judge by the trailing `RESULT:` summary line, not by counting `PASS:` lines: a
FAIL exits 1 and names the failed items, `SKIP:` means "not applicable in this
environment" (neither green nor red), and a missing summary means the script died
midway — also a failure.

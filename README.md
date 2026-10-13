# rsh — reverse command channel

Workers behind NAT/firewalls dial the hub and keep an outbound connection open. The hub sends commands and forwards connections over it.

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
at startup; the process environment always wins over the file, which makes
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
| `RSH_HUB` | hub address as the worker resolves it (worker) / ssh target for CLI nesting (CLI) | — (required on workers) |
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


```bash
rsh worker-a -- bash -lc 'hostname && uptime -s'   # ✅ wrapped in a shell
rsh worker-a -- 'hostname && uptime -s'            # ❌ one single command *name*
#   remote stderr: bash: line 1: hostname && uptime -s: command not found
```


```bash
rsh worker-a -f ./run.sh -- a b     # ✅ run.sh is bash; it can embed a heredoc:
                                    #    python3 - "$@" <<'PYEOF' … PYEOF
rsh worker-a -f ./tool.py -- a b    # ❌ executed by bash, not by python
```


Modes follow flags: there are no list/exec subcommands (usage error, exit 2). Commands follow --. Each argv word is shlex-quoted, so composite commands need bash -lc; an unwrapped quoted command string is treated as a command name and exits 127, an assembly error rather than a channel fault.

-f always runs bash, regardless of shebang; use a bash wrapper for Python. The reverse route inherits worker startup cwd; ssh routes cd to RSH_REMOTE_WS. Output streams in ≤64KB chunks with separate stdout/stderr. Exits: remote code, 124 timeout, 125 local/channel/file/payload error, 2 usage, 255 ssh failure.

On timeout the reverse route kills the remote process group. Direct ssh kills only local ssh, and the remote job may continue without SIGHUP; require the reverse route or an explicit remote timeout when cleanup is mandatory.

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
  cleans up. Payload cap 10MB (over it: exit 125) — for larger files use a
  host you can ssh to directly.

## Port forwarding

Online workers in RSH_FWD_HOSTS get <fwd-dir>/<worker>.sock (directory 0700, node 0600), tunnelling to worker 127.0.0.1:<fwd-target>. Paths derive from worker names; no per-worker overrides.

Registration opens the listener, disconnect/eviction closes and unlinks it. Same-name registration retargets the listener and drops old in-flight tunnels. Startup sweeps leftover *.sock. Listeners must remain unix sockets: unlink-before-bind avoids the unreclaimable TCP LISTEN/EADDRINUSE failure that SO_REUSEADDR and administrative close cannot fix.

Bind/configuration errors log ERROR and degrade only that worker to command mode; its next registration retries. Forward failures never stop command execution.

Messages: fwd_open{id,port}, fwd_ack{id}, fwd_data{id,data} (base64, ≤64KB raw chunks, either direction), fwd_close{id}. Pre-dial data buffers up to 4MB; close/error propagates.

## Protocol (JSON-lines over one TCP connection)

- Registration starts with {type:register,host:<name>,token:…}; success returns {type:registered}, invalid tokens close with DENY. Nothing is sent before authentication; compare tokens in constant time and reject non-strings.
- Hub ping every 30s, worker pong; hub evicts after >90s silence, worker reconnects after >100s, exponential backoff 1→60s. After suspend, eviction/registration usually appears 1–2s after wake. The old disconnected line may lag 34–90s (median~58s), a kernel teardown rather than a second disconnect; within~1s without evicting indicates deliberate close.
- exec{id,cmd,timeout} → out/err → result{id,exit}; cancel{id} kills the process group. Each exec is a new session/group; the worker enforces its own timeout (missing/0→60s), including when cancel/hub is lost. Concurrent execs use ids; duplicate id kills the prior group, and generation checks reject its late result/removal.
- Authenticated lines over 1MB without termination are dropped.
- Local control socket (node 0600, directory 0700): {op:list} reports fwd_sock/null; {op:exec,worker:…,cmd:[…],timeout:N} returns {t:out/err,data}, then {t:done,exit:N,timeout:bool} or {t:error,msg:…}.

Wire formats: `{"type":"register","host":<name>,"token":…}` · `{"type":"registered"}` · `{"op":"list"}` · `{"op":"exec","worker":…,"cmd":[…],"timeout":N}` · `{"t":"out"/"err","data"}` · `{"t":"done","exit":N,"timeout":bool}` · `{"t":"error","msg":…}`

Reader sockets stay blocking; a watchdog shuts them down on hub silence. shutdown precedes close so blocked recv threads wake.

## Security and trust model

- The shared token grants command execution as every online worker's local user. Use only trusted machines; a leak requires a new random token, configuration updates, and restart of every hub/worker.
- Command execution and hub-authorised forwarding are the protocol surface. File shipping stays in the CLI and adds no protocol operation.
- Control and forward unix sockets are 0600 in 0700 directories, accessible only to the hub user/root. Add authentication before exposing a forward; retain upstream authentication.
- Hub 0.0.0.0:8790 accepts worker connections; the token is its sole authentication gate.

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

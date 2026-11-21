# SecurityWizard

A self-hosted **security audit and hardening dashboard for Ubuntu and Debian servers**.
It scans the server, scores its security posture, explains every finding and its risk, and can apply fixes for you
with a preview, a backup, a rollback and a safety timer for changes that could lock you out.

* Runs on the server itself and listens on `127.0.0.1` only. Reach it through an SSH tunnel.
* Locked by default: a login is required, with generated credentials that you can change at any time.
* Understands container-heavy hosts (Docker, Coolify, Traefik, Kubernetes, WireGuard) instead of treating them as noise.
* English and Arabic interface (right-to-left aware), light and dark themes, no external assets at runtime.

## What it checks

| Area | Examples |
|---|---|
| Network and firewall | Detects the real firewall backend (nftables, iptables, ufw, firewalld), INPUT policy and final reject rule, listening sockets with their process, services that should be private (databases, Redis, Docker API) listening on all interfaces, IPv6, and published Docker ports that bypass the firewall (checked against the `DOCKER-USER` chain). |
| SSH | The *effective* configuration from `sshd -T` per listening port and user (Match blocks included), weak ciphers/MACs/key exchange, root and password login, `AllowUsers`/`AllowGroups`. |
| Kernel | `sysctl` hardening (rp_filter aware of Docker/WireGuard hosts, `kptr_restrict`, `bpf_jit_harden`, `ptrace_scope`, ...). |
| Privileges and filesystem | SUID/SGID files against a baseline and the package database, sudoers parsed properly (aliases, runas, tags, risky commands), sensitive file permissions, world-writable files without the sticky bit. |
| Access | `authorized_keys` inventory with fingerprints and restrictions, `docker` group members, sudoers inventory. |
| Docker | Per-container findings by name: `docker.sock` mounts, privileged, host PID/network, added capabilities, root without `no-new-privileges`, sensitive host mounts. |
| Logs and intrusion telemetry | Failed-login sources, fail2ban/CrowdSec, remote log shipping advice. |
| System | auditd, unattended upgrades, pending reboot and kernel mismatch, `/tmp` mount options, core dumps, time sync, AppArmor/SELinux, local systemd unit sandboxing, TLS certificate expiry on local ports. |

Every result shows what was checked, the current and recommended value, why it matters, the exact evidence, a manual
command you can copy, and reference links. A check is **PASS**, **WARNING**, **CRITICAL**, **INFO** or **SKIPPED**;
a skipped check always says exactly why (missing tool, no permission, timeout, ...).

## Quick start

```bash
git clone https://github.com/tamasri/SecurityWizard.git
cd SecurityWizard
sudo ./setup.sh install      # creates ./venv and installs the dependencies
sudo ./setup.sh run          # start in the foreground
# or install a hardened systemd service:
sudo ./setup.sh service
```

Open an SSH tunnel from your own machine and browse to <http://127.0.0.1:8443>:

```bash
ssh -L 8443:127.0.0.1:8443 user@your-server
```

### First login

The dashboard is locked. On the first start SecurityWizard generates a simple random username and password and shows
them **once**: in the console for `./setup.sh run`, in `journalctl -u securitywizard -n 50 --no-pager | grep -i -A3 initial`
for the service, and in the private file `<data dir>/initial-credentials.txt`.
After logging in a banner invites you to change them (use **Account**). Changing them is recommended but never forced.
Only a salted hash is stored; the file with the initial credentials is deleted as soon as you change them.

To supply your own credentials instead, set `SECURITYWIZARD_PASSWORD_HASH` (create one with
`echo -n 'your password' | python -m auth hash`) and optionally `SECURITYWIZARD_USERNAME`.

## Fixing findings safely

1. **Preview**: shows the exact commands and file diffs. Nothing is changed.
2. **Apply** (explicit confirmation): a timestamped backup is taken, the new content is validated first
   (`sshd -t`, `visudo -c`, `nft -c`, ...), then applied and checked again. Applying is idempotent.
3. **Dead-man switch**: SSH and firewall changes revert automatically after five minutes unless you press **Keep this change**,
   and are refused when they could cut off your current connection.
4. **Rollback**: restore any backup with one click.

Applying is **off by default**. The shipped systemd unit runs with `SECURITYWIZARD_DRY_RUN_ONLY=1`; remove that variable
to allow changes. `SECURITYWIZARD_READONLY=1` disables applying and rollback completely.
Every login attempt, preview, apply, rollback and credential change is written to an audit log.

## Configuration

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SECURITYWIZARD_PORT` | `8443` | Port to listen on. |
| `SECURITYWIZARD_BIND` | `127.0.0.1` | Address to bind. Keep it on loopback and use an SSH tunnel. |
| `SECURITYWIZARD_ALLOWED_HOSTS` | `127.0.0.1,localhost,[::1]` | Accepted `Host` headers (add your domain when you put a reverse proxy in front). |
| `SECURITYWIZARD_AUTH` | on | `0` turns the login off. Not recommended. |
| `SECURITYWIZARD_USERNAME` | `admin` | User name when the password comes from the environment. |
| `SECURITYWIZARD_PASSWORD_HASH` | unset | Password hash (argon2 or PBKDF2) instead of generated credentials. |
| `SECURITYWIZARD_PASSWORD_FILE` | unset | File containing that hash. |
| `SECURITYWIZARD_TOKEN` | unset | Static bearer token for automation. |
| `SECURITYWIZARD_DRY_RUN_ONLY` | unset | `1` allows previews only. |
| `SECURITYWIZARD_READONLY` | unset | `1` disables applying fixes and rollback entirely. |
| `SECURITYWIZARD_ALLOW_NONROOT` | unset | `1` allows running without root (limited visibility, no fixes). |
| `SECURITYWIZARD_BACKUP_DIR` | `/var/backups/securitywizard` | Backups, dead-man state. |
| `SECURITYWIZARD_DATA_DIR` | `<backup dir>/data` | Credentials and scan history. |
| `SECURITYWIZARD_AUDIT_LOG` | `<backup dir>/audit.log` | Audit log (JSON lines). |
| `SECURITYWIZARD_CONFIG` | unset | Path of the TOML configuration file. |
| `SECURITYWIZARD_WORKERS` | `8` | Checks run in parallel. |
| `SECURITYWIZARD_CHECK_TIMEOUT` | `60` | Seconds before a check module is reported as timed out. |

### Configuration file

Looked up in `$SECURITYWIZARD_CONFIG`, `./securitywizard.toml`, then `/etc/securitywizard/config.toml`.
It lets a hardened server reach a meaningful score by recording what is intentional:

```toml
[allow]
listeners = [ {port = 443, process = "traefik", reason = "HTTPS entrypoint"} ]
docker_sock_containers = [ {name = "coolify-proxy", reason = "Reverse proxy needs the socket"} ]
docker_public_ports = [ {port = 443, container = "coolify-proxy", reason = "Public HTTPS"} ]
docker_privileged = [ {name = "coolify-sentinel", reason = "Host metrics"} ]
sudo_rules = [ {user = "deploy", command = "/usr/local/bin/restart-app", reason = "Deploy hook"} ]
suid_files = [ {path = "/usr/local/bin/custom-su", reason = "Packaged by us"} ]

# A risk you accept: the finding becomes INFO, keeps its original status and your reason,
# and stops counting in the score. Entries can expire.
[[accepted_risk]]
check_id = "KRN-001"
reason = "Container networking needs loose reverse-path filtering"
expires = "2027-06-30"
match = "rp_filter"
```

## Threat model

* **Assets**: the server's configuration and everything it can change (firewall, SSH, sudoers, kernel settings).
* **Who can reach it**: nobody but local users, by default (`127.0.0.1`). Remote access is by SSH tunnel.
* **What an attacker gains** by reaching the dashboard: a full map of the server's weaknesses and, if fixes are enabled,
  the ability to change configuration as root. That is why it is locked by default, applying is off by default and every
  change is validated, backed up, audited and revertible.
* **Mitigations**: loopback bind, mandatory login with salted hashes, signed `HttpOnly`/`SameSite=Strict` sessions that
  end when credentials change, `Host` and `Origin` validation, a custom CSRF header, rate limits on login and apply,
  strict input validation (remediation ids come from an allowlist), no shell anywhere (argument lists only),
  a restrictive Content-Security-Policy, systemd sandboxing and a read-only mode.
* **Out of scope**: it does not defend the host against a user who already has root, and it cannot make an unsafe
  change safe: always read the preview.

## Architecture

```
browser ── FastAPI (main.py) ── auth.py, security.py        login, sessions, CSRF, rate limit, audit
                 │
                 ├── scanner.py ── checks_*.py              concurrent checks with per-module timeouts
                 │        └── common.py, envdetect.py        command runner, environment detection
                 │        └── config.py                      allowlists and accepted risks
                 ├── remediator.py ── actions_*.py          preview / apply / rollback, validators
                 │        └── deadman.py                    automatic revert unless confirmed
                 └── history.py, export.py                  scan history, diff, JSON/Markdown/SARIF/HTML
static/  templates/                                         dependency-free dashboard (EN/AR)
```

Parsers are kept apart from the checks so they can be tested with real command output:
`sudoers_parse.py`, `firewall.py`, `docker_ports.py`, `sshd_effective.py`.

## Development

```bash
python -m venv venv && . venv/bin/activate
pip install -r requirements-dev.txt
pytest                      # tests never touch the real system: commands and files are mocked
ruff check . && ruff format --check .
mypy .
bandit -c bandit.yaml -r . --exclude ./tests,./venv
pip-audit -r requirements.txt
```

A GitHub Actions workflow with the same jobs is included; it runs only when started manually.
A `Dockerfile` is provided with documented limits: a container cannot audit the host faithfully.

See [CHANGELOG.md](CHANGELOG.md) for what changed and [MIGRATION.md](MIGRATION.md) when upgrading from 1.x.

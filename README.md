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
| Privileges and filesystem | SUID/SGID files against a baseline and the package database, sudoers parsed properly (aliases, runas, tags, risky commands), sensitive file permissions, world-writable files without the sticky bit, writable systemd unit files, and PATH-hijack opportunities for root-run commands. |
| Access | `authorized_keys` inventory with fingerprints and restrictions, `docker` group members, sudoers inventory. |
| Docker | Per-container findings by name: `docker.sock` mounts, privileged, host PID/network, added capabilities, root without `no-new-privileges`, sensitive host mounts. |
| Logs and intrusion telemetry | Failed-login sources, fail2ban/CrowdSec, remote log shipping advice. |
| System | auditd, unattended upgrades, pending reboot and kernel mismatch, `/tmp` mount options, core dumps, time sync, AppArmor/SELinux, local systemd unit sandboxing, TLS certificate expiry on local ports. |
| TLS/certificates *(your own domains only, see below)* | Certificate chain validity and expiry, whether TLSv1/TLSv1.1 are still accepted, and the strength of the negotiated cipher, for 443, 465 and 993. |
| Web response headers *(your own domains only)* | CSP, HSTS (including its `max-age`), X-Frame-Options, X-Content-Type-Options and Referrer-Policy on the home page. |
| Resilience and availability | Config-only review (never a load test): Traefik/Nginx/Stalwart rate-limit, request-size and timeout settings, and fail2ban/CrowdSec jail scoping and ban thresholds. |

Every result shows what was checked, the current and recommended value, why it matters, the exact evidence, a manual
command you can copy, and reference links. A check is **PASS**, **WARNING**, **CRITICAL**, **INFO** or **SKIPPED**;
a skipped check always says exactly why (missing tool, no permission, timeout, ...).

## Authorized use and the active-check target allowlist

The checks above that are read-only, local configuration or system inspection run unconditionally, as on any
security scanner. The **TLS/certificate** and **web response header** checks are different: they make a network
request (a TLS handshake, or a single HTTPS GET) to a hostname. **SecurityWizard is built to audit infrastructure
you own or are authorized to test, never a third party, so these checks refuse to run against anything you have not
explicitly listed.**

Add every domain (and, for IP-based checks, CIDR) you want audited under `[pentest]` in `securitywizard.toml`:

```toml
[pentest]
targets = [
    {host = "example.com", reason = "primary web domain"},
    {host = "mail.example.com", reason = "mail server"},
    {cidr = "203.0.113.10/32", reason = "the server's public IPv4 address"},
]
```

Anything not listed is reported as **SKIPPED** with the reason "not in the \[pentest\] target allowlist", never
silently probed. Every run of an active check is written to the audit log (`check_id`, `target`, `result`,
`timestamp`) alongside logins and remediation actions.

This module is deliberately **not** a general-purpose pentesting or exploitation toolkit: there is no port scanner,
no credential testing against login forms, no mail-server open-relay or account-enumeration probe, and no traffic
generation of any kind. The resilience checks only read configuration files; SecurityWizard never sends a burst of
requests or connections to see how a service behaves under load.

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

Applying is **off by default** (see [Dry-run mode versus applying changes](#dry-run-mode-versus-applying-changes)).
Every login attempt, preview, apply, rollback and credential change is written to an audit log.

## Dry-run mode versus applying changes

One setting decides whether SecurityWizard may change the server: `SECURITYWIZARD_DRY_RUN_ONLY`.
**Dry-run is the default.** Only an explicit `0` (or `false`, `no`, `off`) allows changes; unset, `1` or any other value
keeps the server untouched. The shipped systemd unit and the Docker image also set it to `1` explicitly.

| | Dry-run (default) | Changes allowed (`SECURITYWIZARD_DRY_RUN_ONLY=0`) |
|---|---|---|
| Scanning, scoring, history, exports | Works, read-only commands only | Same |
| Preview of a fix (exact commands and file diffs) | Works, nothing is changed | Same |
| **Apply** a fix | Refused with "dry-run only"; the button is disabled and says why | Allowed after you confirm, when every condition below holds |
| **Rollback** of a backup | Refused; the button is disabled | Allowed |
| Backup before a change | None needed, nothing changes | Timestamped snapshot of every file the fix touches |
| Safety timer for SSH and firewall changes | Not used | Armed: the change reverts after 5 minutes unless you press **Keep this change** |
| Unconfirmed change left over after a restart | Still reverted (that is a safety action) | Reverted, or its timer re-armed |
| What the tool writes | Only its own files: scan history, audit log, credentials | Also the files of the fixes listed below |

`SECURITYWIZARD_READONLY=1` is stricter still: scanning works, but applying, rollback and keeping a change are refused
whatever `SECURITYWIZARD_DRY_RUN_ONLY` says.

### What it can and cannot change when changes are allowed

A change is applied only when **all** of these hold: dry-run is off, read-only mode is off, you are logged in and the
request carries the CSRF header, you ticked the confirmation, the process runs as root (or `SECURITYWIZARD_ALLOW_NONROOT=1`),
the fix exists in the built-in list below, the plan has no blockers and its anti-lockout check passes, and it is not
already in place. Nothing outside this list can be changed, because ids are checked against the list and every command
is a fixed argument list (no shell).

| Fix | What it touches |
|---|---|
| `ssh_permit_root_login`, `ssh_password_auth`, `ssh_pubkey_auth`, `ssh_max_auth_tries`, `ssh_empty_passwords`, `ssh_x11_forwarding` | One setting in `/etc/ssh/sshd_config` (or the drop-in in `/etc/ssh/sshd_config.d/` that sets it), checked with `sshd -t` before it is kept, then `systemctl reload ssh`. Refused when it could lock you out, for example when no authorized key exists. |
| `ufw_baseline` | `ufw default deny incoming`, `ufw default allow outgoing`, an allow rule for each detected SSH port, `ufw --force enable` (ufw updates its own rule files, which are backed up). Refused when ufw is missing or the SSH port cannot be determined. |
| `docker_user_isolation` | A marked block in `/etc/ufw/after.rules` for the `DOCKER-USER` chain, then `ufw reload`. Needs ufw and Docker. |
| `sysctl_baseline` | Writes `/etc/sysctl.d/99-securitywizard.conf` and runs `sysctl --system`. |
| `fix_perm_passwd`, `fix_perm_shadow`, `fix_perm_group`, `fix_perm_sudoers`, `fix_perm_sshd_config` | Mode and ownership of `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers` and `/etc/ssh/sshd_config` only. |

It **cannot** run arbitrary commands, install or remove packages, edit users, passwords or the content of sudoers,
touch containers or images, or delete files other than ones that a fix created and that a rollback restores.

The service unit confines it further: `NoNewPrivileges`, a read-only system (`ProtectSystem=strict`) with writes allowed
only in `/etc`, `/var/log` and the backup directory, `PrivateTmp`, read-only home directories, a short capability list and
only local and IP sockets. `/etc` has to stay writable because the fixes edit files there; a deployment that only needs
scanning should set `SECURITYWIZARD_READONLY=1`.

To allow changes on the service:

```bash
sudo systemctl edit securitywizard      # add the two lines below, save
#   [Service]
#   Environment=SECURITYWIZARD_DRY_RUN_ONLY=0
sudo systemctl restart securitywizard
```

## Configuration

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SECURITYWIZARD_PORT` | `8443` | Port to listen on. |
| `SECURITYWIZARD_BIND` | `127.0.0.1` | Address to bind. Keep it on loopback and use an SSH tunnel. |
| `SECURITYWIZARD_ALLOWED_HOSTS` | `127.0.0.1,localhost,[::1]` | Accepted `Host` headers (add your domain when you put a reverse proxy in front). |
| `SECURITYWIZARD_AUTH` | on | `0` turns the login off. Not recommended. |
| `SECURITYWIZARD_COOKIE_SECURE` | auto | `1` forces the `Secure` flag on the session cookie (it is set automatically over HTTPS or behind a proxy that sends `X-Forwarded-Proto: https`). |
| `SECURITYWIZARD_USERNAME` | `admin` | User name when the password comes from the environment. |
| `SECURITYWIZARD_PASSWORD_HASH` | unset | Password hash (argon2 or PBKDF2) instead of generated credentials. |
| `SECURITYWIZARD_PASSWORD_FILE` | unset | File containing that hash. |
| `SECURITYWIZARD_TOKEN` | unset | Static bearer token for automation. |
| `SECURITYWIZARD_DRY_RUN_ONLY` | `1` (dry-run) | Dry-run is the default; only an explicit `0` allows changes. |
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

# Domains/IPs the TLS and web-header checks are allowed to touch; see "Authorized use" above.
[pentest]
targets = [ {host = "example.com", reason = "primary web domain"} ]

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
pip install --require-hashes -r requirements-dev.txt   # hash-locked, see below
pytest                      # tests never touch the real system: commands and files are mocked
ruff check . && ruff format --check .
mypy .
bandit -c bandit.yaml -r . --exclude ./tests,./venv
pip-audit -r requirements.txt
```

Dependencies are locked with hashes: edit `requirements.in` / `requirements-dev.in` (exact versions) and regenerate the
lock files with `pip-compile --generate-hashes --strip-extras --allow-unsafe requirements.in` (and the same for
`requirements-dev.in`), ideally on the Python version you deploy with.

A GitHub Actions workflow with the same jobs is included; it runs only when started manually.
A `Dockerfile` is provided with documented limits: a container cannot audit the host faithfully.

See [CHANGELOG.md](CHANGELOG.md) for what changed and [MIGRATION.md](MIGRATION.md) when upgrading from 1.x.

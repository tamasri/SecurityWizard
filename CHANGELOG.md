# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-11-21

### Security
- The dashboard is **locked by default**. The first start generates a simple random username and password, shows them once
  (console, journal and a private file) and stores only a salted hash. A banner invites the user to change them; changing is optional.
- Sessions are signed, `HttpOnly`, `SameSite=Strict`, expire after 12 hours and end when credentials change.
- Configurable allowed hosts (`SECURITYWIZARD_ALLOWED_HOSTS`), `Origin` validation, a CSRF header, rate limits on login and
  apply, strict identifier validation, security headers and an audit log of every login, preview, apply, rollback and credential change.
- Read-only mode (`SECURITYWIZARD_READONLY=1`) and a hardened systemd unit.

### Fixed
- **Dry-run is now really the default.** Without `SECURITYWIZARD_DRY_RUN_ONLY` the tool used to allow changes; now only an
  explicit `0` does. Rollback is refused in dry-run mode too (automatic safety reverts still run).
- The dead-man switch was never armed for the real SSH and firewall fixes (it looked for the flag in the wrong place), and the
  anti-lockout check stored in each plan was never called; both are fixed and shown in the preview.
- **PRV-001** SUID/SGID hunter: `find` was called with its arguments in the wrong order and always skipped. It now scans local
  filesystems only, prunes pseudo and container paths, and compares with a baseline and the package database.
- **PRV-006** `/etc/ssh/sshd_config` mode 0644 is the distribution default and is no longer critical.
- **PRV-008** sudoers are parsed properly (aliases, runas, tags, negation): a single narrow command is INFO instead of a false `NOPASSWD: ALL`.
- **KRN-001** `rp_filter=2` is accepted on Docker, Kubernetes, WireGuard and multi-homed hosts, and strict mode is never suggested there.
- **LOG-001/LOG-002** the `chattr +a` remediation, which breaks logrotate, was removed.
- **NET-003** the real firewall backend (nftables, iptables, ufw, firewalld) is detected and the INPUT policy is evaluated.
- **NET-004** every published Docker port is checked against the `DOCKER-USER` chain, per container.
- **NET-001/NET-002** listeners are attributed to processes; private services on all interfaces and IPv6 are handled.
- **DOC-002..007** per-container findings with an allowlist. They crashed on hosts with containers (missing configuration lookup).
- Fix buttons are shown only when a remediation exists and are disabled, with an explanation, in dry-run-only and read-only mode.
- `setup.sh` no longer aborts when an unrelated apt repository is broken, verifies the installation before enabling the service,
  and creates the directories that systemd requires.
- Dead-man switch: a risky change can now actually be kept (it had no confirmation endpoint).
- `/api/scan/status` was shadowed by `/api/scan/{job_id}`; the scan endpoint blocked until the scan ended; dry-run, apply and
  rollback failed because the request model was used as the HTTP request; scans were never saved to the history.
- **Remediation never worked from the dashboard**: the API and the remediator accepted only ids shaped like `NET-001`
  while every registered action uses names such as `ssh_permit_root_login`, so every preview, apply and rollback was rejected.
  Snapshot ids (rollback) and dead-man tokens had the same mismatch. All three now match what the remediator creates.
- Actions that only run commands (the firewall baseline) were skipped as "already applied" and never ran.
- Dead-man switch: timers no longer keep the server from shutting down, several pending changes are tracked together, and a
  change that was never confirmed is reverted automatically when the service starts again after its deadline.
- `ACC-001`/`ACC-003` were never evaluated on a real host (misplaced `else`), users were looked up in the wrong `/etc/passwd`
  field, and `ACC-002` crashed on any sudoers rule.
- `PRV-006` still rated a world-writable-only `sshd_config` as fine and treated a `PasswordAuthentication yes` setting as a secret.
- Multi-homed host detection compared the word `via` instead of the gateway address.
- A `docker.sock` mount was reported twice, so allowlisting the container did not silence it.
- The NET-004 manual command inserted a blanket `DROP` at the top of `DOCKER-USER`, which would cut off every container;
  it now only filters new connections arriving on the public interface.
- The accepted-risk entries of the configuration file are now applied by the scanner (they were parsed but ignored).
- `run_cmd` results can be unpacked again (`rc, out, err`); many checks silently skipped because of it.
- `authorized_keys` parsing: options containing spaces (typical forced-command keys), RSA key size and OpenSSH style fingerprints.
- The score is no longer shown as 0% before the first scan, SKIPPED and INFO checks are excluded, and the formula is documented.

### Added
- Configuration file with allowlists and accepted risks (reason and optional expiry).
- Environment detection: Docker, Coolify, Kubernetes, WireGuard, cloud provider, fail2ban/CrowdSec, auditd, AppArmor/SELinux.
- Checks: effective SSH configuration via `sshd -T`, `authorized_keys` and sudoers inventory, docker group, auditd, unattended
  upgrades, pending reboot, mount options, core dumps, time sync, more `sysctl` keys, world-writable files, systemd unit sandboxing,
  TLS certificate expiry, failed-login sources.
- Remediation engine with typed validators, backups, rollback, idempotency, a dead-man switch and anti-lockout preconditions.
- Concurrent scans with per-module timeouts that never block the event loop.
- Scan history with diff, and export to JSON, Markdown, SARIF and HTML.
- New dependency-free dashboard in English and Arabic with filters, search, detail view and version footer.
- Tooling: `pyproject.toml`, pre-commit, a manually triggered CI workflow, a Dockerfile, and a pytest suite.

### Changed
- Dependencies upgraded to current releases; unused ones removed.
- Python 3.10 or newer is required (3.12 recommended).

## [1.0.0]
- First release.

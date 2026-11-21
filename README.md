# SecurityWizard

A self-hosted **Linux server security audit and hardening dashboard** for Ubuntu and Debian.
SecurityWizard scans your server, scores its security posture, explains each finding, and can apply
fixes for you, with a preview, a backup and a rollback for every change.

## Features

- **Six audit areas**
  - Network and firewall (UFW, plus the Docker firewall-bypass problem)
  - SSH configuration
  - Kernel hardening (`sysctl`)
  - Privileges and filesystem integrity (SUID/SGID files, world-writable paths, sensitive file permissions)
  - Docker runtime
  - Logs and intrusion telemetry (failed logins, fail2ban/crowdsec)
- **Clear results**: every check shows what it tests, the risk, the recommended value and a manual command.
- **Safe remediation**
  - Dry-run preview showing the exact commands and file diffs
  - Automatic timestamped backups before any change
  - One-click rollback
  - Anti-lockout guards for SSH and firewall changes
  - Explicit confirmation before anything is applied
- **Local web dashboard** with an overall security score and per-category results.

## Requirements

- Ubuntu or Debian
- Python 3 with `venv`
- Root privileges for a full scan and for applying fixes

## Install and run

```bash
git clone https://github.com/tamasri/SecurityWizard.git
cd SecurityWizard
sudo ./setup.sh install     # creates ./venv and installs dependencies
sudo ./setup.sh run         # starts the dashboard in the foreground
# or
sudo ./setup.sh service     # installs and starts a systemd unit (securitywizard.service)
```

The dashboard listens on `127.0.0.1:8443` only. To reach it from your own machine, use an SSH tunnel:

```bash
ssh -L 8443:127.0.0.1:8443 user@your-server
```

Then open <http://127.0.0.1:8443>.

## Configuration

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `SECURITYWIZARD_PORT` | `8443` | Port to listen on (always bound to 127.0.0.1) |
| `SECURITYWIZARD_BACKUP_DIR` | `/var/backups/securitywizard` | Where pre-change backups are stored |
| `SECURITYWIZARD_DRY_RUN_ONLY` | unset | Set to `1` to disable applying changes (preview only) |
| `SECURITYWIZARD_ALLOW_NONROOT` | unset | Set to `1` to allow running without root (limited visibility) |

## Project layout

| File | Role |
|---|---|
| `main.py` | FastAPI app and API routes |
| `scanner.py` | Runs all checks and computes the score |
| `checks_*.py` | Audit modules (network, ssh, kernel, privilege, docker, logs) |
| `remediator.py` | Preview, apply, backup and rollback engine |
| `actions_*.py` | Remediation definitions (network, ssh, system) |
| `common.py` | Shared helpers and result format |
| `templates/index.html` | Dashboard UI |
| `setup.sh` | Install, run and systemd helper |

## Security notes

- The dashboard has no login. It is meant to be reached only through an SSH tunnel; do not expose it publicly.
- Hardening changes can affect connectivity (SSH, firewall rules, Docker networking). Review the dry-run preview first,
  and try new changes on a test machine before applying them to a production server.
- Keep out-of-band access (console or recovery mode) available when changing SSH or firewall settings.

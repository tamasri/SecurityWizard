# Migrating from 1.x to 2.0

## What stays the same
* `SECURITYWIZARD_PORT`, `SECURITYWIZARD_BACKUP_DIR`, `SECURITYWIZARD_DRY_RUN_ONLY` and `SECURITYWIZARD_ALLOW_NONROOT` keep their meaning.
* The dashboard still binds to `127.0.0.1:8443` and is reached through an SSH tunnel.
* Existing backups in the backup directory can still be rolled back.

## What changes
1. **The dashboard now asks for a login.** On the first start 2.0 generates a random username and password and prints them once
   (console or `journalctl -u securitywizard`, and `<data dir>/initial-credentials.txt`). Log in, then change them from **Account**.
   - Scripts or proxies that call the API must log in first (`POST /api/login`) or use `SECURITYWIZARD_TOKEN`.
   - To keep the old open behaviour (not recommended) set `SECURITYWIZARD_AUTH=0`.
2. **Applying fixes is off by default.** Dry-run is the default everywhere; set `SECURITYWIZARD_DRY_RUN_ONLY=0` explicitly
   (`systemctl edit securitywizard`) if you want fixes to be applied. Rollback is refused in dry-run mode as well. Risky SSH
   and firewall changes then revert after five minutes unless you press **Keep this change**.
3. **Removed remediations.** The `chattr +a` actions for the auth log and syslog are gone because they break log rotation.
4. **Reverse proxies.** Add the public host name to `SECURITYWIZARD_ALLOWED_HOSTS`; requests for any other `Host` are refused.
5. **Python 3.10 or newer** is required. Re-run `sudo ./setup.sh install` to refresh the virtual environment; `setup.sh` now
   continues when an unrelated apt repository fails and verifies the installation before it enables the service.
6. **Re-run your first scan.** Several checks were corrected (SUID hunter, sudoers, rp_filter, firewall detection, Docker ports),
   so scores and findings will differ from 1.x. Use the configuration file (`securitywizard.toml`) to record what is intentional.

## New files and directories
* `<data dir>` (default `/var/backups/securitywizard/data`): `credentials.json` (hash only), scan history.
* `<backup dir>/audit.log`: JSON-lines audit log.
* Optional `/etc/securitywizard/config.toml` or `./securitywizard.toml`: allowlists and accepted risks.

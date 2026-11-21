#!/usr/bin/env bash
set -uo pipefail

usage() {
  cat <<EOF
Usage: sudo ./setup.sh [install|run|service]

  install  (default) Install Python deps into ./venv
  run      Start the dashboard on 127.0.0.1:8443
  service  Create and start the systemd unit
EOF
  exit 1
}

if [[ ${EUID} -ne 0 ]]; then
  echo "Error: must run as root (use: sudo $0 $*)" >&2
  usage
fi

DATA_DIR="${SECURITYWIZARD_DATA_DIR:-${SECURITYWIZARD_BACKUP_DIR:-/var/backups/securitywizard}/data}"

credentials_note() {
  cat <<EOF

The dashboard is protected by default. On the first start it generates a simple random username and
password and shows them ONCE:
  - in the console output of './setup.sh run'
  - for the service:  journalctl -u securitywizard -n 50 --no-pager | grep -i -A3 initial
  - in the private file ${DATA_DIR}/initial-credentials.txt
Log in with them, then change them from the Account menu (a banner reminds you, it is not forced).
EOF
}

cmd="${1:-install}"
case "$cmd" in
  install)
    apt-get update || echo "Warning: apt-get update reported errors; continuing anyway." >&2
    apt-get install -y python3 python3-venv python3-pip || {
      echo "Warning: first apt-get install attempt failed; retrying..." >&2
      apt-get install -y python3 python3-venv python3-pip || {
        echo "Error: failed to install python3, python3-venv, python3-pip." >&2
        exit 1
      }
    }
    echo "Note: install ufw separately if firewall management is desired: apt-get install -y ufw"
    python3 -m venv venv || {
      echo "Error: failed to create virtual environment at ./venv." >&2
      exit 1
    }
    if [[ ! -f ./venv/bin/python ]]; then
      echo "Error: venv python not found at ./venv/bin/python." >&2
      exit 1
    fi
    ./venv/bin/pip install --upgrade pip || {
      echo "Error: failed to upgrade pip." >&2
      exit 1
    }
    ./venv/bin/pip install -r requirements.txt || {
      echo "Error: failed to install requirements." >&2
      exit 1
    }
    ./venv/bin/python -c "import fastapi, uvicorn" || {
      echo "Error: fastapi or uvicorn import failed." >&2
      exit 1
    }
    ./venv/bin/python -c "import main" || {
      echo "Error: main module import failed." >&2
      exit 1
    }
    echo "Install complete."
    echo "Start the dashboard with: ./venv/bin/python main.py"
    echo "Reach it from your laptop with: ssh -L 8443:127.0.0.1:8443 user@server"
    echo "Then open http://127.0.0.1:8443 in your browser."
    credentials_note
    ;;
  run)
    credentials_note
    exec ./venv/bin/python main.py
    ;;
  service)
    if [[ ! -f ./venv/bin/python ]]; then
      echo "Error: venv not found at ./venv. Run './setup.sh install' first." >&2
      exit 1
    fi
    ./venv/bin/python -c "import fastapi, uvicorn" || {
      echo "Error: fastapi or uvicorn import failed. Run './setup.sh install' first." >&2
      exit 1
    }
    ./venv/bin/python -c "import main" || {
      echo "Error: main module import failed. Run './setup.sh install' first." >&2
      exit 1
    }
    # ProtectSystem=strict makes systemd refuse to start the unit when a ReadWritePaths directory is missing.
    mkdir -p /var/backups/securitywizard "${DATA_DIR}"
    chmod 700 /var/backups/securitywizard
    cat > /etc/systemd/system/securitywizard.service <<EOF
[Unit]
Description=SecurityWizard Security Dashboard
After=network.target

[Service]
Type=simple
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/venv/bin/python main.py
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ReadWritePaths=/var/backups/securitywizard /etc /var/log
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_NET_ADMIN CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
Environment=SECURITYWIZARD_DRY_RUN_ONLY=1

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable securitywizard.service
    systemctl start securitywizard.service
    echo "Service installed and started on 127.0.0.1:8443"
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      [[ -f "${DATA_DIR}/initial-credentials.txt" ]] && break
      sleep 1
    done
    if [[ -f "${DATA_DIR}/initial-credentials.txt" ]]; then
      echo
      cat "${DATA_DIR}/initial-credentials.txt"
    fi
    credentials_note
    ;;
  *)
    usage
    ;;
esac

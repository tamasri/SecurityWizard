#!/usr/bin/env bash
set -euo pipefail

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

cmd="${1:-install}"
case "$cmd" in
  install)
    apt-get update
    apt-get install -y python3 python3-venv python3-pip
    echo "Note: install ufw separately if firewall management is desired: apt-get install -y ufw"
    python3 -m venv venv
    ./venv/bin/pip install --upgrade pip
    ./venv/bin/pip install -r requirements.txt
    echo "Install complete."
    echo "Start the dashboard with: ./venv/bin/python main.py"
    echo "Reach it from your laptop with: ssh -L 8443:127.0.0.1:8443 user@server"
    echo "Then open http://127.0.0.1:8443 in your browser."
    ;;
  run)
    exec ./venv/bin/python main.py
    ;;
  service)
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

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable securitywizard.service
    systemctl start securitywizard.service
    echo "Service installed and started on 127.0.0.1:8443"
    ;;
  *)
    usage
    ;;
esac

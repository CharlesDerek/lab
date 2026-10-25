#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run with sudo.' >&2; exit 1; }
cd -- "$(dirname -- "$0")"
umask 077
chmod 700 ./athernex-endpoint
./athernex-endpoint installer-check /var/lib/athernex-endpoint ./athernex-endpoint
if systemctl cat athernex-endpoint.service >/dev/null 2>&1; then
  systemctl stop athernex-endpoint.service
fi
if systemctl cat athernex-protection.service >/dev/null 2>&1; then
  systemctl stop athernex-protection.service
  systemctl disable athernex-protection.service
fi
./athernex-endpoint installer-check /var/lib/athernex-endpoint ./athernex-endpoint --stopped
install -d -m 700 /var/lib/athernex-endpoint
install -d -m 755 /opt/athernex-endpoint
install -m 755 ./athernex-endpoint /opt/athernex-endpoint/athernex-endpoint
install -m 755 ./athernex-endpoint /opt/athernex-endpoint/athernex-controller
install -m 755 ./athernex-endpoint /opt/athernex-endpoint/athernex-launcher
/opt/athernex-endpoint/athernex-endpoint enroll ./bootstrap.json /var/lib/athernex-endpoint
/opt/athernex-endpoint/athernex-endpoint provision-antivirus ./bootstrap.json /var/lib/athernex-endpoint
cat > /etc/systemd/system/athernex-endpoint.service <<'UNIT'
[Unit]
Description=Athernex managed endpoint
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/opt/athernex-endpoint/athernex-launcher launch /var/lib/athernex-endpoint /opt/athernex-endpoint/athernex-controller /opt/athernex-endpoint/athernex-endpoint
Restart=on-failure
RestartSec=15
UMask=0077
NoNewPrivileges=true
MemoryMax=4G
TasksMax=128
TimeoutStopSec=20
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable athernex-endpoint
systemctl restart athernex-endpoint
if /opt/athernex-endpoint/athernex-endpoint protection-enabled /var/lib/athernex-endpoint; then
  attempts=0
  until /opt/athernex-endpoint/athernex-endpoint protection-status /var/lib/athernex-endpoint --require-active >/dev/null; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 65 ]; then
      /opt/athernex-endpoint/athernex-endpoint protection-status /var/lib/athernex-endpoint >&2
      echo 'Installed, but native blocking did not become healthy. Review athernex-endpoint.service and endpoint protection status.' >&2
      exit 1
    fi
    sleep 5
  done
fi
rm -- ./bootstrap.json
echo 'Installed. Review protection health in the portal and local policy in /var/lib/athernex-endpoint/config.json. Existing antivirus is preserved.'

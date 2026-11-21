#!/bin/sh
# Install or reinstall udm-conditioner on the UDM. Run on the UDM itself:
#
#   sh /persistent/udm-conditioner/install.sh
#
# Everything lives in /persistent, which survives reboots and firmware updates. The systemd unit
# is copied into /etc, which a firmware update may reset - rerun this script afterwards.
set -eu
D=/persistent/udm-conditioner
cd "$D"

if [ ! -f cert.pem ] || [ ! -f key.pem ]; then
  san_ip=$(ip -4 -o addr show scope global 2>/dev/null | awk 'NR==1 { sub(/\/.*/, "", $4); print $4 }')
  if [ -n "$san_ip" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout key.pem -out cert.pem \
      -subj "/CN=udm-conditioner" -addext "subjectAltName=IP:${san_ip}" >/dev/null 2>&1
  else
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout key.pem -out cert.pem \
      -subj "/CN=udm-conditioner" >/dev/null 2>&1
  fi
fi
chmod 600 key.pem
python3 -m py_compile udm_conditioner.py

install -m 644 udm-conditioner.service /etc/systemd/system/udm-conditioner.service
systemctl daemon-reload
systemctl enable udm-conditioner >/dev/null 2>&1
systemctl restart udm-conditioner

i=0
while [ $i -lt 20 ]; do
  systemctl is-active -q udm-conditioner && break
  i=$((i + 1)); sleep 0.5
done
systemctl --no-pager --lines=5 status udm-conditioner | sed -n '1,12p'

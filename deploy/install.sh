#!/bin/bash
# Render deploy/ templates and install them on the Pi. Run as root on the Pi,
# from the repo root: sudo deploy/install.sh
#
# Deliberately does NOT apply netplan or reboot: both can cut off the session
# that is running this. It prints what to do instead.
set -euo pipefail
cd "$(dirname "$0")"
[ -f secrets.env ] || { echo "missing deploy/secrets.env (see secrets.env.example)"; exit 1; }
set -a; . ./secrets.env; set +a
radios=$(ls /sys/class/net | grep '^wlx' | tr '\n' ' ' || true)
: "${WPA_PASSPHRASE:?WPA_PASSPHRASE must be set in secrets.env}"
: "${AP1_IFACE:?AP1_IFACE must be set in secrets.env - radios present: $radios}"
: "${AP2_IFACE:?AP2_IFACE must be set in secrets.env - radios present: $radios}"
SSID1=${SSID1:-test-a}
SSID2=${SSID2:-test-b}
ETH0_MAC=${ETH0_MAC:-$(cat /sys/class/net/eth0/address)}
HOST_IP=${HOST_IP:-$(ip -4 -o addr show br0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)}
HOST_IP=${HOST_IP:-$(ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1)}
KEYS="SSID1 SSID2 WPA_PASSPHRASE AP1_IFACE AP2_IFACE ETH0_MAC HOSTNAME HOST_IP"
export KEYS SSID1 SSID2 WPA_PASSPHRASE AP1_IFACE AP2_IFACE ETH0_MAC HOSTNAME HOST_IP

# Placeholders can appear in file contents and in paths - the hostapd configs
# and their unit drop-ins are named after each radio's interface.
subst () {
  python3 -c 'import os, sys
text = sys.argv[1]
for key in os.environ["KEYS"].split():
    text = text.replace("@@%s@@" % key, os.environ[key])
print(text)' "$1"
}
render () {  # $1 = template path under deploy/, $2 = destination
  python3 - "$1" "$2" <<'PY'
import os, sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src).read()
for key in os.environ["KEYS"].split():
    text = text.replace("@@%s@@" % key, os.environ[key])
if "@@" in text:
    sys.exit("unrendered placeholder left in " + src)
open(dst, "w").write(text)
PY
}

while IFS= read -r f; do
  rel=${f#./}
  dst="/$(subst "${rel%.template}")"
  mkdir -p "$(dirname "$dst")"
  if [[ "$rel" == *.template ]]; then render "$rel" "$dst"; else cp "$rel" "$dst"; fi
  echo "installed $dst"
done < <(find ./etc ./usr -type f)

chmod 600 /etc/hostapd/*.conf /etc/netplan/50-cloud-init.yaml
chmod 755 /usr/local/bin/ap-watchdog.sh /usr/local/bin/loadmon.sh

while IFS= read -r line; do
  grep -qxF "$line" /boot/firmware/config.txt || { echo "$line" >> /boot/firmware/config.txt; echo "appended to config.txt: $line"; }
done < boot/firmware/config.txt.append

systemctl daemon-reload
# One hostapd@<iface> instance per radio. The template binds each instance to its
# radio's device, so it starts when that radio appears and stops if it is
# unplugged, independently of the other. The single-instance hostapd.service is
# masked so it can never start alongside them.
systemctl mask hostapd >/dev/null 2>&1 || true
systemctl enable "hostapd@$AP1_IFACE" "hostapd@$AP2_IFACE" ap-watchdog.timer udm-conditioner >/dev/null 2>&1
echo
echo "Installed. Still to do by hand, because each can drop this session:"
echo "  netplan apply            (bridge config)"
echo "  systemctl restart hostapd@$AP1_IFACE hostapd@$AP2_IFACE udm-conditioner systemd-journald"
echo "  reboot                   (config.txt changes)"

# deploy/

Everything installed on the Pi outside `/opt/udm-conditioner`, laid out by
destination path. `install.sh` renders the `*.template` files and copies the rest.

```sh
cp deploy/secrets.env.example deploy/secrets.env   # fill in WPA_PASSPHRASE
sudo deploy/install.sh
```

`secrets.env` is gitignored. Templates carry `@@NAME@@` placeholders - in file
contents and in file names - for the Wi-Fi passphrase, the two SSIDs, and values
tied to one physical Pi: the eth0 MAC (pinned on `br0` so the DHCP reservation
still resolves the host name), each USB radio's MAC-derived interface name, and
the host name and address Caddy serves.

## What each piece is for

| Path | Purpose |
| --- | --- |
| `etc/netplan/50-cloud-init.yaml` | `br0` bridge over `eth0`, keeping eth0's MAC |
| `etc/cloud/cloud.cfg.d/99-disable-network-config.cfg` | stop cloud-init regenerating the netplan file |
| `etc/hostapd/<AP1_IFACE>.conf`, `<AP2_IFACE>.conf` | the two APs: `test-a` on ch 149 and `test-b` on ch 36, both **20 MHz**, **U-APSD off**, same password |
| `etc/systemd/system/hostapd@<iface>.service.d/override.conf` | one hostapd instance per radio: start after networkd, always restart; bound to its radio so it follows plug and unplug |
| `etc/systemd/system/udm-conditioner.service` (+ `.d/`) | the API, pointed at the AP interface |
| `etc/caddy/Caddyfile` | HTTPS on 443 with Caddy's internal CA |
| `usr/local/bin/ap-watchdog.sh` + `ap-watchdog.{service,timer}` | radio fault recovery for both radios, every minute, each confined to its own AP |
| `usr/local/bin/loadmon.sh` | 150 s power and PHY-rate sampler for load tests |
| `etc/systemd/system.conf.d/10-watchdog.conf` | hardware watchdog, 30 s |
| `etc/systemd/journald.conf.d/10-size-limits.conf` | journal capped at 200 MB |
| `etc/logrotate.d/caddy` | rotation for Caddy file logs if enabled |
| `etc/modprobe.d/blacklist-brcmfmac.conf` | keep the onboard radio driver unloaded |
| `boot/firmware/config.txt.append` | disable onboard Wi-Fi; raise the USB current cap |

## Settings that look like tuning and are not

- **20 MHz, U-APSD off.** At 40 MHz with U-APSD on, stations fell to the 6 Mbit
  PHY floor 3-4 times a minute under two-camera load. Here: none.
- **`usb_max_current_enable=1`.** No third-party charger offers the 5 V/5 A PD
  profile, so the Pi otherwise caps USB at 600 mA, which the radio exceeds under
  load. Redundant once the official 27 W supply is fitted.
- **The watchdog only deauths a device that is receiving.** A camera's video goes
  client->AP, so a low AP->client rate on a camera is harmless; an earlier
  version that ignored direction disconnected healthy cameras.

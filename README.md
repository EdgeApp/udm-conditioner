# udm-conditioner

Per-device network conditioner: bandwidth cap, added latency, jitter and loss for any device,
selected by IP address, through an HTTP API fast enough to drive from a test loop. Nothing in it
is specific to any one application.

There are two builds, serving the same API:

- **`udm/` - current.** Runs on the UniFi Dream Machine Pro itself and shapes devices on
  dedicated test VLANs. Python standard library only.
- **`src/` + `deploy/` - the original Raspberry Pi 5 build**: a transparent bridge with its own
  USB Wi-Fi access points. Retired 2026-09-11. Its MT7921AU adapters' firmware hung roughly once
  an hour per adapter under test load, which is not reliable enough for test infrastructure.

See [docs/API.md](docs/API.md) for the API.

## Why test VLANs

The gateway can shape only traffic its CPU sees. Devices on the same VLAN are switched in
hardware, so their traffic never reaches it - measured: 5.26 MB of video crossed the network
while 9.4 KB crossed the shaper. UniFi APs do see that traffic, but their kernels have no
`sch_netem`, so they cannot add latency.

The Pi build solved this by standing in the path. The UDM build solves it by giving devices
under test their own VLANs: traffic between a test VLAN and any other network is routed, so it
passes through the gateway's kernel, where `tc` can condition it. Bonjour discovery still works
across the networks through the UDM's mDNS proxy.

## UDM build

- A `clsact` hook on each test VLAN's bridge (`br5`, `br6`) with catch-all `basic` filters that
  redirect egress (toward the devices) to `ifb-cond-dn` and ingress (from them) to
  `ifb-cond-up`. The main LAN's `br0` is never touched, and the service refuses to start if told
  to shape it.
- All queueing on the IFB pair, as on the Pi: 32 pre-built HTB classes, each with its own netem
  child. A shape change is a class change + qdisc change + per-device `u32` filter, batched into
  a single `tc` invocation - ~5 ms. A device that stays on its slot keeps its filter.
- The UDM's kernel (4.19) has no `cls_flower` and no `cls_matchall`. The hooks use `basic`
  rather than `u32` because `u32` filters on one `clsact`'s ingress and egress share their hash
  tables there, so each direction's hook is listed under the other and a missing one cannot be
  told apart.
- UniFi recreates a VLAN's bridge when that network is saved, which drops its hooks. Each call
  compares kernel interface indexes (a file read, no `tc`) and re-attaches a recreated bridge;
  a full check with `tc` runs every 5 s.
- Stopping the service removes its hooks and IFB devices, leaving the gateway as it found it.

Install or update by copying `udm/` to `/persistent/udm-conditioner` on the gateway, then
running `sh /persistent/udm-conditioner/install.sh` there. Before the first start, set
`COND_IFACES` in the unit to that gateway's test VLAN bridges.

Everything lives in `/persistent/udm-conditioner`, which survives firmware updates. The systemd
unit is copied into `/etc`, which a firmware update may reset. Afterwards, run
`sh /persistent/udm-conditioner/install.sh` on the gateway.

## Pi build design (retired)

- `clsact` hook on each radio listed in `GSC_IFACE` - a filter attachment point, not a root
  qdisc, so the Wi-Fi driver keeps its own fq_codel/airtime queueing.
- All queueing on two IFB devices, `ifb-cond-dn` and `ifb-cond-up`, shared by every radio, so
  one IP-keyed slot table serves them all.
- Radios are hot-pluggable: an absent one is skipped, and the reconciler re-attaches a returning
  one's hooks without rebuilding the tree.
- 32 pre-built HTB classes, each with its own netem child, created once at startup. A shape
  change is a class change + qdisc change + `flower` filter replace, batched into a single `tc`
  invocation - ~5 ms.
- netem queue depth is computed from the bandwidth-delay product. The default 1000-packet limit
  tail-drops at low rate with high delay, which makes a link look broken rather than slow.

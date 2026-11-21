#!/usr/bin/env python3
"""udm-conditioner: per-device network conditioning on a UniFi Dream Machine.

The same declarative shaping API as the Pi build, running on the gateway itself. The UDM routes
traffic between VLANs in software, so a device on a test VLAN talking to anything on another
network passes through the kernel here, where tc can condition it. Traffic within one VLAN is
switched in hardware and never arrives, which is why devices under test live on their own
VLANs.

Only the Python standard library is used: the UDM ships Python 3 but no Node and no pip.

The kernel has no cls_flower and no cls_matchall, so where the Pi build used those this uses
cls_basic with no match for the catch-all hooks, and u32 `match ip dst|src` for the per-device
filters. Not u32 for the hooks: u32 filters on one clsact's ingress and egress share their hash
tables on this kernel, so each direction's hook shows up under the other.
"""
import ipaddress
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

VERSION = "1.1.0"
PORT = int(os.environ.get("COND_PORT", "10443"))
HOST = os.environ.get("COND_HOST", "0.0.0.0")
CERT = os.environ.get("COND_CERT", "/persistent/udm-conditioner/cert.pem")
KEY = os.environ.get("COND_KEY", "/persistent/udm-conditioner/key.pem")

# Interfaces to shape, each optionally labelled with the name clients should see:
# "br10:test-a,br20:test-b". These are bridges on the gateway, never the main LAN.
IFACES = []
LABELS = {}
for _part in re.split(r"[\s,]+", os.environ.get("COND_IFACES", "").strip()):
    if _part:
        _name, _, _label = _part.partition(":")
        IFACES.append(_name)
        LABELS[_name] = _label or None

MTU = 1500
SLOTS = 32
DEV_DOWN = "ifb-cond-dn"
DEV_UP = "ifb-cond-up"
UNCAPPED_KBIT = 10_000_000
TARGET_BUFFER_SEC = 0.15
# Slot N's per-device filter sits alone at prio FILTER_PRIO_BASE + N, so it can be removed by
# priority. u32 has no equivalent of flower's stable per-filter handle to replace in place.
FILTER_PRIO_BASE = 10
MODULES = ["sch_netem", "sch_htb", "ifb", "act_mirred", "cls_u32", "cls_basic", "sch_ingress"]
HISTORY_MAX = 500
# The active shapes, rewritten on every change so a restart of the service puts them back: the
# stop tears every hook and IFB down, and other agents' devices must not come back unshaped.
# /run is a tmpfs, so a reboot still starts clean.
STATE = os.environ.get("COND_STATE", "/run/udm-conditioner/shapes.json")
LEASES = "/run/dnsmasq.lease"
# tc -force keeps going past these, which are expected when clearing a slot that has no filter.
# This tc reports one such delete as three lines: the error, "We have an error talking to the
# kernel" and "Command failed -:N". A real failure still surfaces through its own first line.
BENIGN_TC_ERRORS = re.compile(
    r"Cannot find|No such file|not found|RTNETLINK answers: Invalid argument|error talking to the kernel|Command failed",
    re.I)


# --- tc plumbing ---------------------------------------------------------------------------

def run(args, stdin=None):
    p = subprocess.run(args, input=stdin, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def quiet(args):
    """Run a command whose failure is expected when the object does not exist."""
    run(args)


def must(args):
    rc, out, err = run(args)
    if rc != 0:
        raise RuntimeError(f"{' '.join(args)}: {err.strip() or out.strip()}")
    return out


def tc_batch(lines):
    """Apply a batch of tc commands in one invocation. Returns (durationMs, stderr)."""
    if not lines:
        return 0.0, ""
    started = time.perf_counter()
    _, _, err = run(["tc", "-force", "-batch", "-"], stdin="\n".join(lines) + "\n")
    return (time.perf_counter() - started) * 1000, err


def class_id(slot):
    return f"1:{slot}"


def netem_handle(slot):
    return f"{100 + slot}:"


def filter_prio(slot):
    return FILTER_PRIO_BASE + slot


def mbit_to_kbit(mbit):
    """Megabits (fractional allowed) to whole kbit, which is what tc consumes."""
    return UNCAPPED_KBIT if mbit <= 0 else max(1, round(mbit * 1000))


def burst_bytes(rate_kbit):
    """HTB burst: about 1 ms of the configured rate, floored at one MTU plus headroom."""
    return max(MTU + 100, -(-(rate_kbit * 1000) // 8 // 1000))


def quantum_bytes(rate_kbit):
    """HTB quantum, set explicitly rather than left to r2q, which warns past 200000."""
    per_sec = rate_kbit * 1000 / 8
    return int(min(200000, max(MTU, -(-per_sec // 10))))


def netem_limit(rate_kbit, delay_ms, jitter_ms):
    """netem queue depth in packets: the delay line plus a queue sized for a target latency.

    Too small and a low rate with high delay tail-drops everything, so the link looks broken
    rather than slow. Too large and the queue becomes seconds of bufferbloat, so TCP's loss
    signal arrives far too late and throughput oscillates.
    """
    bytes_per_sec = rate_kbit * 1000 / 8
    delay_line = bytes_per_sec * ((delay_ms + jitter_ms) / 1000) / MTU
    queue = bytes_per_sec * TARGET_BUFFER_SEC / MTU
    return int(min(200000, max(32, -(-(delay_line + queue) // 1))))


def netem_args(p):
    parts = []
    if p["delayMs"] > 0 or p["jitterMs"] > 0:
        parts.append(f"delay {fmt(p['delayMs'])}ms")
        if p["jitterMs"] > 0:
            parts.append(f"{fmt(p['jitterMs'])}ms")
    if p["lossPct"] > 0:
        parts.append(f"loss {fmt(p['lossPct'])}%")
    parts.append(f"limit {netem_limit(p['rateKbit'], p['delayMs'], p['jitterMs'])}")
    return " ".join(parts)


def fmt(n):
    return str(int(n)) if float(n).is_integer() else str(n)


def uncapped_slot_lines(dev, slot):
    b = burst_bytes(UNCAPPED_KBIT)
    return [
        f"class change dev {dev} parent 1: classid {class_id(slot)} htb rate {UNCAPPED_KBIT}kbit "
        f"ceil {UNCAPPED_KBIT}kbit burst {b}b cburst {b}b quantum {quantum_bytes(UNCAPPED_KBIT)}",
        f"qdisc change dev {dev} parent {class_id(slot)} handle {netem_handle(slot)} netem limit 1000",
    ]


# Each slot has a class on both IFBs. Downstream carries traffic toward the device, upstream
# traffic from it, and each side of a slot is shaped independently.
SIDES = (("down", DEV_DOWN), ("up", DEV_UP))


def sides_for(direction):
    """The sides a request entry sets."""
    return {"both": ("down", "up"), "down": ("down",), "up": ("up",)}[direction]


def filter_lines(dev, slot, ip):
    """Point one IFB's per-device filter for a slot at `ip`, or remove it when `ip` is None.

    A side with no shape has no filter, so that traffic is classified into the default and
    passes unshaped - rather than being matched into a slot that is merely uncapped.
    """
    prio = filter_prio(slot)
    lines = [f"filter delete dev {dev} parent 1: prio {prio}"]
    if ip is not None:
        match = f"dst {ip}/32" if dev == DEV_DOWN else f"src {ip}/32"
        lines.append(f"filter add dev {dev} parent 1: protocol ip prio {prio} u32 match ip {match} flowid {class_id(slot)}")
    return lines


def side_lines(dev, slot, params):
    b = burst_bytes(params["rateKbit"])
    return [
        f"class change dev {dev} parent 1: classid {class_id(slot)} htb rate {params['rateKbit']}kbit "
        f"ceil {params['rateKbit']}kbit burst {b}b cburst {b}b quantum {quantum_bytes(params['rateKbit'])}",
        f"qdisc change dev {dev} parent {class_id(slot)} handle {netem_handle(slot)} netem {netem_args(params)}",
    ]


def build_batch(plans, previous):
    """tc batch moving the live configuration to `plans`.

    `previous` maps each slot in use to the IP its filter on each side points at:
    {slot: {"down": ip or None, "up": ip or None}}. A side whose filter is unchanged keeps it, so
    reapplying a shape never interrupts classification. Slots no longer wanted lose their filters
    and are reset.
    """
    lines = []
    wanted = {p["slot"] for p in plans}
    for p in plans:
        slot = p["slot"]
        for side, dev in SIDES:
            params = p[side]
            # A side left unshaped keeps no cap, so a reused slot cannot carry the previous rate.
            lines += side_lines(dev, slot, params) if params else uncapped_slot_lines(dev, slot)
            target = p["ip"] if params else None
            if previous.get(slot, {}).get(side) != target:
                lines += filter_lines(dev, slot, target)
    for slot in previous:
        if slot in wanted:
            continue
        for _side, dev in SIDES:
            lines += filter_lines(dev, slot, None)
            lines += uncapped_slot_lines(dev, slot)
    return lines


# --- baseline: IFB tree and hooks -------------------------------------------------------------

def present_ifaces():
    return [i for i in IFACES if os.path.exists(f"/sys/class/net/{i}")]


def attach_hooks(iface):
    """Funnel one bridge's routed traffic through the IFB pair.

    clsact is a filter attachment point, not a root qdisc, so nothing UniFi puts on the bridge
    is displaced. Egress on the bridge is traffic toward its devices; ingress is traffic from
    them. Every bridge feeds the same pair, so a device's shaping is found by IP alone.
    """
    quiet(["tc", "qdisc", "del", "dev", iface, "clsact"])
    must(["tc", "qdisc", "add", "dev", iface, "clsact"])
    for hook, dev in (("egress", DEV_DOWN), ("ingress", DEV_UP)):
        must(["tc", "filter", "add", "dev", iface, hook, "protocol", "all", "prio", "1",
              "basic", "action", "mirred", "egress", "redirect", "dev", dev])


def build_ifb_tree():
    for dev in (DEV_DOWN, DEV_UP):
        must(["ip", "link", "add", dev, "type", "ifb"])
        must(["ip", "link", "set", dev, "txqueuelen", "2000"])
        must(["ip", "link", "set", dev, "up"])
    b = burst_bytes(UNCAPPED_KBIT)
    q = quantum_bytes(UNCAPPED_KBIT)
    lines = []
    for dev in (DEV_DOWN, DEV_UP):
        lines.append(f"qdisc add dev {dev} root handle 1: htb default 9999")
        # burst/cburst must be explicit: given a rate and no burst, HTB derives a zero-depth
        # bucket and throttles hard no matter how high the rate is.
        lines.append(f"class add dev {dev} parent 1: classid 1:9999 htb rate {UNCAPPED_KBIT}kbit "
                     f"ceil {UNCAPPED_KBIT}kbit burst {b}b cburst {b}b quantum {q}")
        for slot in range(1, SLOTS + 1):
            lines.append(f"class add dev {dev} parent 1: classid {class_id(slot)} htb rate {UNCAPPED_KBIT}kbit "
                         f"ceil {UNCAPPED_KBIT}kbit burst {b}b cburst {b}b quantum {q}")
            lines.append(f"qdisc add dev {dev} parent {class_id(slot)} handle {netem_handle(slot)} netem limit 1000")
    _, err = tc_batch(lines)
    if re.search(r"Error|Cannot", err, re.I):
        raise RuntimeError(f"Failed to build shaping tree: {err.strip()}")


def teardown_baseline():
    for iface in present_ifaces():
        quiet(["tc", "qdisc", "del", "dev", iface, "clsact"])
    for dev in (DEV_DOWN, DEV_UP):
        quiet(["ip", "link", "del", dev])


def build_baseline():
    for m in MODULES:
        quiet(["modprobe", m])
    teardown_baseline()
    build_ifb_tree()
    for iface in present_ifaces():
        attach_hooks(iface)


def ifb_tree_intact():
    for dev in (DEV_DOWN, DEV_UP):
        rc, out, _ = run(["tc", "qdisc", "show", "dev", dev])
        if rc != 0 or "htb" not in out:
            return False
    return True


def unhooked_ifaces():
    """Present bridges whose hooks are missing.

    UniFi recreates a VLAN's bridge when that network's settings are saved, which drops its
    hooks while the IFB tree and every active shape survive.
    """
    missing = []
    for iface in present_ifaces():
        _, egress, _ = run(["tc", "filter", "show", "dev", iface, "egress"])
        _, ingress, _ = run(["tc", "filter", "show", "dev", iface, "ingress"])
        if DEV_DOWN not in egress or DEV_UP not in ingress:
            missing.append(iface)
    return missing


def iface_subnets():
    """The IPv4 subnet of each shaped bridge, read live."""
    nets = {}
    for iface in present_ifaces():
        _, out, _ = run(["ip", "-4", "-o", "addr", "show", "dev", iface])
        m = re.search(r"inet (\S+)", out)
        if m:
            nets[iface] = ipaddress.ip_interface(m.group(1)).network
    return nets


# --- request validation ---------------------------------------------------------------------

IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def as_ip(raw):
    if not isinstance(raw, str):
        raise ValueError(f"Expected an IPv4 address, got {json.dumps(raw)}")
    m = IPV4.match(raw)
    if not m:
        raise ValueError(f'Expected an IPv4 address, got "{raw}"')
    if any(int(o) > 255 for o in m.groups()):
        raise ValueError(f'Invalid IPv4 address "{raw}"')
    return raw


def as_non_negative(raw, field):
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise ValueError(f"Expected a number for {field}, got {json.dumps(raw)}")
    if raw != raw or raw in (float("inf"), float("-inf")) or raw < 0:
        raise ValueError(f"Expected a number >= 0 for {field}, got {raw}")
    return raw


def as_direction(raw):
    """Which side of a device's link an entry sets: from the device, toward it, or both.

    A device's link carries what it sends and what it receives, and each side is shaped on its
    own. `up` or `down` sets that side and, with merge, leaves the other as it was, so a call can
    squeeze what a Director publishes without starving the cameras feeding it. Different upload
    and download values take two entries, in one request or two.
    """
    if raw is None:
        return "both"
    if raw not in ("both", "up", "down"):
        raise ValueError('Expected direction to be "both", "up" or "down"')
    return raw


SHAPE_FIELDS = ("ip", "latencyMs", "jitterMs", "mbit", "lossPct", "direction")
REQUEST_FIELDS = ("shapes", "merge")


def reject_unknown(raw, allowed, where):
    """A misspelled field would otherwise be silently read as its default - zero, which clears."""
    unknown = [k for k in raw if k not in allowed]
    if unknown:
        raise ValueError(f"Unknown field {json.dumps(unknown[0])} in {where}; expected {', '.join(allowed)}")


def as_shape(raw, index=0):
    if not isinstance(raw, dict):
        raise ValueError("Expected each shape to be an object")
    reject_unknown(raw, SHAPE_FIELDS, f"shapes[{index}]")
    mbit = as_non_negative(raw.get("mbit", 0), "mbit")  # 0 or omitted = uncapped
    params = {
        "rateKbit": mbit_to_kbit(mbit),
        "delayMs": as_non_negative(raw.get("latencyMs", 0), "latencyMs"),
        "jitterMs": as_non_negative(raw.get("jitterMs", 0), "jitterMs"),
        "lossPct": as_non_negative(raw.get("lossPct", 0), "lossPct"),
    }
    unshaped = mbit <= 0 and params["delayMs"] <= 0 and params["jitterMs"] <= 0 and params["lossPct"] <= 0
    # params None means "this side is unshaped": the entry clears the sides it names.
    return {"ip": as_ip(raw.get("ip")), "direction": as_direction(raw.get("direction", "both")),
            "params": None if unshaped else params}


def as_shape_request(raw):
    if not isinstance(raw, dict) or not isinstance(raw.get("shapes"), list):
        raise ValueError('Expected a body of the form {"shapes": [...]}')
    reject_unknown(raw, REQUEST_FIELDS, "the request")
    merge = raw.get("merge", False)
    if not isinstance(merge, bool):
        raise ValueError("Expected merge to be a boolean")
    return [as_shape(s, i) for i, s in enumerate(raw["shapes"])], merge


# --- shaper ---------------------------------------------------------------------------------

def read_ifindex(name):
    """A netdev's kernel index, or None if it does not exist. A plain file read, so it costs
    microseconds - cheap enough to check on every call."""
    try:
        with open(f"/sys/class/net/{name}/ifindex") as f:
            return int(f.read())
    except (OSError, ValueError):
        return None


class Shaper:
    """Owns the live shaping state. Every mutation holds one lock, so concurrent API calls can
    never interleave halfway through a tc batch."""

    def __init__(self):
        self.lock = threading.Lock()
        self.active = {}  # ip -> {slot, ip, down, up, appliedAtMs}; a side is its params or None
        self.slot_of_ip = {}
        self.subnets = {}  # iface -> network, refreshed by the reconciler
        # Kernel indexes of the IFB pair and of each bridge as it was when hooked. UniFi
        # recreates a VLAN's bridge when its network is saved, which gives it a new index, so
        # comparing indexes detects a lost hook without launching tc.
        self.ifb_index = None
        self.hooked_index = {}

    def record_indexes(self):
        self.ifb_index = (read_ifindex(DEV_DOWN), read_ifindex(DEV_UP))
        self.hooked_index = {i: read_ifindex(i) for i in present_ifaces()}
        self.subnets = iface_subnets()

    def rebuild(self):
        build_baseline()
        self.active, self.slot_of_ip = {}, {}
        self.record_indexes()
        self.save()

    def init(self):
        with self.lock:
            self.rebuild()

    @staticmethod
    def sides_of(a):
        return {"down": a["down"], "up": a["up"]}

    def assign_slots(self, desired):
        """One slot per IP, kept while the IP stays shaped. `desired` maps ip -> sides."""
        warnings, plans = [], []
        used = {self.slot_of_ip[ip] for ip in desired if ip in self.slot_of_ip}
        for ip, sides in desired.items():
            slot = self.slot_of_ip.get(ip)
            if slot is None:
                slot = next((c for c in range(1, SLOTS + 1) if c not in used), None)
            if slot is None:
                warnings.append(f"No free slot for {ip}; {SLOTS} shapes is the maximum")
                continue
            used.add(slot)
            plans.append({"slot": slot, "ip": ip, "down": sides["down"], "up": sides["up"]})
        return plans, warnings

    def previous_filters(self):
        return {a["slot"]: {side: a["ip"] if a[side] else None for side, _dev in SIDES}
                for a in self.active.values()}

    def commit(self, plans):
        now_ms = int(time.time() * 1000)
        self.active = {p["ip"]: {**p, "appliedAtMs": now_ms} for p in plans}
        self.slot_of_ip = {p["ip"]: p["slot"] for p in plans}
        self.save()

    def save(self):
        """Write the active shapes to STATE. A failure is logged, never fatal: shaping is live
        either way, and only a later restart would lose it."""
        try:
            os.makedirs(os.path.dirname(STATE), exist_ok=True)
            tmp = f"{STATE}.tmp"
            with open(tmp, "w") as f:
                json.dump({"shapes": [{"ip": ip, **self.sides_of(a)} for ip, a in self.active.items()]}, f)
            os.replace(tmp, STATE)
        except OSError as e:
            log(f"could not save shaping state to {STATE}: {e}")

    def restore(self, saved):
        """Reapply shapes from load_state(), as ip -> sides. Returns how many were applied."""
        with self.lock:
            plans, warnings = self.assign_slots(saved)
            _, err = tc_batch(build_batch(plans, self.previous_filters()))
            warnings += [l for l in err.strip().splitlines() if l and not BENIGN_TC_ERRORS.search(l)]
            self.commit(plans)
            for w in warnings:
                log(f"restore: {w}")
            return len(plans)

    def quick_repair(self, warnings):
        """Per-call integrity check using kernel indexes only. Caller holds the lock.

        Returns the sides that were active before a rebuild, as ip -> sides, so the caller can
        restore them; anything subtler than a recreated device is left to the reconciler's full
        check.
        """
        if (read_ifindex(DEV_DOWN), read_ifindex(DEV_UP)) != self.ifb_index or None in self.ifb_index:
            warnings.append("Shaping tree was missing and has been rebuilt")
            previous = {ip: self.sides_of(a) for ip, a in self.active.items()}
            self.rebuild()
            return previous
        for iface in IFACES:
            index = read_ifindex(iface)
            if index is not None and index != self.hooked_index.get(iface):
                attach_hooks(iface)
                self.hooked_index[iface] = index
                self.subnets = iface_subnets()
                warnings.append(f"Re-attached shaping hooks to {iface}")
        return {}

    def set_shapes(self, shapes, merge=False):
        """Declarative by default: the entries become the complete active set. With merge, only
        the sides the entries name are touched. Entries apply in order, each setting the sides
        its direction names; an entry with no conditioning clears those sides. An IP with
        neither side shaped is cleared."""
        with self.lock:
            started = time.perf_counter()
            warnings = []
            restored = self.quick_repair(warnings)
            before = set(self.active) | set(restored)

            # With merge, everything already in force stays - including shapes that a rebuild
            # just wiped and quick_repair handed back. Without it, the request is the whole set.
            desired = {}
            if merge:
                desired = {ip: dict(sides) for ip, sides in restored.items()}
                desired.update({ip: self.sides_of(a) for ip, a in self.active.items()})
            for s in shapes:
                sides = desired.setdefault(s["ip"], {"down": None, "up": None})
                for side in sides_for(s["direction"]):
                    sides[side] = s["params"]
            desired = {ip: sides for ip, sides in desired.items() if sides["down"] or sides["up"]}
            cleared = [ip for ip in before if ip not in desired]

            for ip in desired:
                if not any(ipaddress.ip_address(ip) in n for n in self.subnets.values()):
                    where = ", ".join(f"{i} {n}" for i, n in self.subnets.items()) or "none present"
                    warnings.append(f"{ip} is not on a shaped network ({where}); its traffic never reaches the shaper")

            plans, slot_warnings = self.assign_slots(desired)
            warnings += slot_warnings
            batch = build_batch(plans, self.previous_filters())
            tc_ms, err = tc_batch(batch)
            warnings += [l for l in err.strip().splitlines() if l and not BENIGN_TC_ERRORS.search(l)]

            self.commit(plans)
            return {"applied": list(self.active.values()), "cleared": sorted(cleared),
                    "applyDurationMs": (time.perf_counter() - started) * 1000,
                    "tcDurationMs": tc_ms, "commands": batch, "warnings": warnings}

    def clear(self):
        return self.set_shapes([], False)

    def reset(self):
        with self.lock:
            teardown_baseline()
            self.rebuild()

    def list(self):
        return [{**applied_view(a), "appliedAtMs": a["appliedAtMs"]} for a in self.active.values()]

    def interfaces(self):
        present = set(present_ifaces())
        unhooked = set(unhooked_ifaces())
        nets = iface_subnets()
        return [{"name": i, "ssid": LABELS.get(i), "subnet": str(nets[i]) if i in nets else None,
                 "present": i in present, "hooked": i in present and i not in unhooked} for i in IFACES]

    def intact(self):
        return ifb_tree_intact() and not unhooked_ifaces()

    def reconcile_forever(self, interval=5):
        """Keep the apparatus whole while UniFi reprovisions around it. This is the full check,
        with tc: it also catches hooks removed from a bridge that kept its index."""
        while True:
            time.sleep(interval)
            try:
                with self.lock:
                    self.subnets = iface_subnets()
                    if ifb_tree_intact():
                        for iface in unhooked_ifaces():
                            attach_hooks(iface)
                            self.hooked_index[iface] = read_ifindex(iface)
                            log(f"reconciler: re-attached shaping hooks to {iface}")
                        continue
                    log("reconciler: shaping tree missing, rebuilding")
                    previous = {ip: self.sides_of(a) for ip, a in self.active.items()}
                    self.rebuild()
                    if previous:
                        plans, _ = self.assign_slots(previous)
                        _, err = tc_batch(build_batch(plans, {}))
                        if not [l for l in err.strip().splitlines() if l and not BENIGN_TC_ERRORS.search(l)]:
                            self.commit(plans)
                        log(f"reconciler: reapplied {len(plans)} shape(s)")
            except Exception as e:  # keep reconciling whatever happened this round
                log(f"reconciler failed: {e}")


def load_state():
    """The shapes STATE recorded, as ip -> sides, or {} when there is none or it is unreadable."""
    try:
        with open(STATE) as f:
            raw = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        log(f"ignoring unreadable shaping state {STATE}: {e}")
        return {}
    saved = {}
    try:
        for entry in raw["shapes"]:
            sides = {}
            for side, _dev in SIDES:
                params = entry.get(side)
                sides[side] = None if not params else {
                    "rateKbit": int(params["rateKbit"]),
                    "delayMs": as_non_negative(params["delayMs"], "delayMs"),
                    "jitterMs": as_non_negative(params["jitterMs"], "jitterMs"),
                    "lossPct": as_non_negative(params["lossPct"], "lossPct"),
                }
            if sides["down"] or sides["up"]:
                saved[as_ip(entry["ip"])] = sides
    except (KeyError, TypeError, ValueError) as e:
        log(f"ignoring malformed shaping state {STATE}: {e}")
        return {}
    return saved


# --- devices --------------------------------------------------------------------------------

def devices():
    """Clients on the shaped networks: the gateway's neighbour table joined with DHCP leases.

    The gateway routes for these networks, so unlike the Pi's bridge it already knows every
    active client's address without sweeping.
    """
    leases = {}
    try:
        for line in open(LEASES):
            f = line.split()
            if len(f) >= 4:
                # A client can appear more than once, and a later line may lack the name.
                prior = leases.get(f[1].lower(), {}).get("hostname")
                leases[f[1].lower()] = {"ip": f[2], "hostname": (None if f[3] == "*" else f[3]) or prior}
    except OSError:
        pass
    nets = iface_subnets()
    out, seen = [], set()
    for iface in present_ifaces():
        _, neigh, _ = run(["ip", "-4", "neigh", "show", "dev", iface])
        for line in neigh.splitlines():
            m = re.match(r"^(\S+)\s+lladdr\s+(\S+)\s+(\S+)", line.strip())
            if not m:
                continue
            ip, mac, state = m.group(1), m.group(2).lower(), m.group(3)
            seen.add(mac)
            out.append({"mac": mac, "ip": ip, "ipSource": "arp", "state": state, "iface": iface,
                        "ssid": LABELS.get(iface), "hostname": leases.get(mac, {}).get("hostname")})
    for mac, l in leases.items():
        if mac in seen:
            continue
        for iface, net in nets.items():
            if ipaddress.ip_address(l["ip"]) in net:
                out.append({"mac": mac, "ip": l["ip"], "ipSource": "lease", "state": None, "iface": iface,
                            "ssid": LABELS.get(iface), "hostname": l["hostname"]})
    return out


# --- HTTP -----------------------------------------------------------------------------------

def log(msg):
    print(msg, flush=True)


shaper = Shaper()
started_at = time.time()
history = []
history_lock = threading.Lock()


def side_view(params):
    if not params:
        return None
    return {"latencyMs": params["delayMs"], "jitterMs": params["jitterMs"],
            "mbit": None if params["rateKbit"] >= UNCAPPED_KBIT else params["rateKbit"] / 1000,
            "lossPct": params["lossPct"]}


def applied_view(a):
    """One device's shaping, per side. A side that is null passes unshaped."""
    delay = sum(a[side]["delayMs"] for side, _dev in SIDES if a[side])
    return {"ip": a["ip"], "slot": a["slot"], "down": side_view(a["down"]), "up": side_view(a["up"]),
            "expectedRttDeltaMs": delay}


class Handler(BaseHTTPRequestHandler):
    server_version = f"udm-conditioner/{VERSION}"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass  # mutations are logged as shape-call lines; GETs are not worth the journal space

    def send_json(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        self.response_body, self.status = body, status

    def read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n == 0:
            return {}
        try:
            return json.loads(self.rfile.read(n))
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")

    def dispatch(self, method):
        url = urlparse(self.path)
        path = url.path.rstrip("/") or "/"
        body = None
        try:
            if method in ("POST", "DELETE"):
                body = self.read_body()
            route = ROUTES.get((method, path))
            if route is None:
                self.send_json(404, {"ok": False, "error": f"No route {method} {path}"})
            else:
                route(self, body, parse_qs(url.query))
        except ValueError as e:
            self.send_json(400, {"ok": False, "error": str(e)})
        except Exception as e:
            self.send_json(500, {"ok": False, "error": str(e)})
        if method != "GET":
            record(self, method, path, body)

    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def do_DELETE(self):
        self.dispatch("DELETE")


def record(h, method, path, body):
    """Every call that changes shaping, kept for GET /v1/history and written to the journal as a
    shape-call line. Several agents may share this API; this is how to tell who shaped what."""
    rb = getattr(h, "response_body", {}) or {}
    now = time.time()
    entry = {"atMs": int(now * 1000), "at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + "Z",
             "method": method, "path": path, "client": h.client_address[0], "status": getattr(h, "status", None),
             "merge": (body or {}).get("merge") if isinstance(body, dict) else None,
             "requested": (body or {}).get("shapes") if isinstance(body, dict) else None,
             "applied": rb.get("applied"), "cleared": rb.get("cleared"),
             "applyDurationMs": rb.get("applyDurationMs"), "error": rb.get("error")}
    with history_lock:
        history.append(entry)
        del history[:-HISTORY_MAX]
    log(f"shape-call {json.dumps(entry)}")


def r_health(h, _body, _q):
    ifaces = shaper.interfaces()
    h.send_json(200, {"ok": True, "version": VERSION, "iface": ",".join(IFACES), "interfaces": ifaces,
                      "radios": ifaces, "uptimeMs": int((time.time() - started_at) * 1000),
                      "treeIntact": shaper.intact(), "activeCount": len(shaper.list()), "maxSlots": SLOTS})


def r_get_shape(h, _body, _q):
    h.send_json(200, {"shapes": shaper.list()})


def r_post_shape(h, body, _q):
    shapes, merge = as_shape_request(body)
    r = shaper.set_shapes(shapes, merge)
    h.send_json(200, {"ok": True, "merge": merge, "cleared": r["cleared"],
                      "applied": [applied_view(a) for a in r["applied"]],
                      "applyDurationMs": round(r["applyDurationMs"], 2), "tcDurationMs": round(r["tcDurationMs"], 2),
                      "commandCount": len(r["commands"]), "warnings": r["warnings"]})


def r_delete_shape(h, _body, _q):
    r = shaper.clear()
    h.send_json(200, {"ok": True, "cleared": r["cleared"], "applyDurationMs": round(r["applyDurationMs"], 2),
                      "warnings": r["warnings"]})


def r_reset(h, _body, _q):
    shaper.reset()
    h.send_json(200, {"ok": True, "rebuilt": True})


def r_devices(h, _body, _q):
    d = devices()
    h.send_json(200, {"iface": ",".join(IFACES), "count": len(d), "devices": d})


def r_stats(h, _body, _q):
    _, down, _ = run(["tc", "-s", "class", "show", "dev", DEV_DOWN])
    _, up, _ = run(["tc", "-s", "class", "show", "dev", DEV_UP])
    h.send_json(200, {"shapes": shaper.list(), "raw": {"down": down, "up": up}})


def r_history(h, _body, q):
    try:
        limit = max(1, min(HISTORY_MAX, int(q.get("limit", ["50"])[0])))
    except ValueError:
        limit = 50
    with history_lock:
        entries = list(reversed(history[-limit:]))
        count = len(history)
    h.send_json(200, {"count": count, "entries": entries})


ROUTES = {
    ("GET", "/v1/health"): r_health,
    ("GET", "/v1/shape"): r_get_shape,
    ("POST", "/v1/shape"): r_post_shape,
    ("DELETE", "/v1/shape"): r_delete_shape,
    ("POST", "/v1/reset"): r_reset,
    ("GET", "/v1/devices"): r_devices,
    ("GET", "/v1/stats"): r_stats,
    ("GET", "/v1/history"): r_history,
}


class TLSServer(ThreadingHTTPServer):
    """TLS handshakes happen in each request's thread, so a slow or stalled client can never
    hold up accept() for everyone else."""
    daemon_threads = True

    def __init__(self, addr, handler, context):
        super().__init__(addr, handler)
        self.context = context

    def finish_request(self, request, client_address):
        request.settimeout(15)
        try:
            request = self.context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            request.close()
            return
        super().finish_request(request, client_address)


def main():
    if "--teardown" in sys.argv:
        teardown_baseline()
        return
    if not IFACES:
        sys.exit("Set COND_IFACES to the test VLAN bridges, for example br10:test-a,br20:test-b.")
    if "br0" in IFACES:
        sys.exit("Refusing to shape br0: that is the main LAN. Shape only the test VLANs' bridges.")
    saved = load_state()  # read before init, which rebuilds the tree and records it empty
    shaper.init()
    if saved:
        log(f"restored {shaper.restore(saved)} shape(s) from {STATE}")
    threading.Thread(target=shaper.reconcile_forever, daemon=True).start()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    server = TLSServer((HOST, PORT), Handler, ctx)
    log(f"udm-conditioner {VERSION} listening on https://{HOST}:{PORT}, shaping {', '.join(IFACES)}")
    server.serve_forever()


if __name__ == "__main__":
    main()

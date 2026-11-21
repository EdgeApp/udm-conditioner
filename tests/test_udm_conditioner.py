"""Tests for udm/udm_conditioner.py against a fake tc.

Run from the repository root: python3 -m unittest discover -s tests

The fake applies each batch line to a model of the two IFBs - per-device filters, HTB rates and
netem arguments - so a test checks what the kernel would end up holding, not the exact lines.
"""
import ipaddress
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "udm"))
import udm_conditioner as uc  # noqa: E402

A = "192.0.2.10"
B = "192.0.2.20"


class FakeTc:
    def __init__(self):
        self.filters = {}  # (dev, prio) -> (direction match, ip, flowid)
        self.rates = {}  # (dev, classid) -> kbit
        self.netem = {}  # (dev, classid) -> netem arguments
        self.batches = []

    def batch(self, lines):
        self.batches.append(lines)
        for line in lines:
            self.apply(line)
        return 0.0, ""

    def apply(self, line):
        m = re.match(r"filter delete dev (\S+) parent 1: prio (\d+)$", line)
        if m:
            self.filters.pop((m.group(1), int(m.group(2))), None)
            return
        m = re.match(r"filter add dev (\S+) parent 1: protocol ip prio (\d+) u32 match ip (dst|src) (\S+)/32 flowid (\S+)$", line)
        if m:
            key = (m.group(1), int(m.group(2)))
            assert key not in self.filters, f"duplicate filter: {line}"
            self.filters[key] = (m.group(3), m.group(4), m.group(5))
            return
        m = re.match(r"class change dev (\S+) parent 1: classid (\S+) htb rate (\d+)kbit ", line)
        if m:
            self.rates[(m.group(1), m.group(2))] = int(m.group(3))
            return
        m = re.match(r"qdisc change dev (\S+) parent (\S+) handle \S+ netem (.*)$", line)
        if m:
            self.netem[(m.group(1), m.group(2))] = m.group(3)
            return
        raise AssertionError(f"unexpected tc line: {line}")

    def side(self, dev, ip):
        """(kbit, netem args) applied to ip on one IFB, or None when no filter classifies it."""
        found = [(p, f) for (d, p), f in self.filters.items() if d == dev and f[1] == ip]
        if not found:
            return None
        assert len(found) == 1, found
        _prio, (match, _ip, flowid) = found[0]
        assert match == ("dst" if dev == uc.DEV_DOWN else "src")
        return self.rates[(dev, flowid)], self.netem[(dev, flowid)]

    def down(self, ip):
        return self.side(uc.DEV_DOWN, ip)

    def up(self, ip):
        return self.side(uc.DEV_UP, ip)

    def filter_lines_in_last_batch(self):
        return [l for l in self.batches[-1] if l.startswith("filter")]


class ShaperTest(unittest.TestCase):
    def setUp(self):
        self.tc = FakeTc()
        self.ifindex = 1
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        patches = [
            mock.patch.object(uc, "STATE", os.path.join(self.dir.name, "run", "shapes.json")),
            mock.patch.object(uc, "log", lambda msg: None),
            mock.patch.object(uc, "tc_batch", self.tc.batch),
            mock.patch.object(uc, "read_ifindex", lambda name: self.ifindex),
            mock.patch.object(uc, "present_ifaces", lambda: []),
            mock.patch.object(uc, "iface_subnets", lambda: {"br10": ipaddress.ip_network("192.0.2.0/24")}),
            mock.patch.object(uc, "build_baseline", lambda: None),
            mock.patch.object(uc, "IFACES", []),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.shaper = uc.Shaper()
        self.shaper.init()

    def post(self, body):
        shapes, merge = uc.as_shape_request(body)
        return self.shaper.set_shapes(shapes, merge)

    def test_both_sets_each_side_alike(self):
        self.post({"shapes": [{"ip": A, "mbit": 2, "latencyMs": 50}]})
        self.assertEqual(self.tc.down(A), (2000, "delay 50ms limit 34"))
        self.assertEqual(self.tc.up(A), (2000, "delay 50ms limit 34"))

    def test_merge_sets_one_side_and_keeps_the_other(self):
        self.post({"merge": True, "shapes": [{"ip": A, "direction": "down", "mbit": 20, "latencyMs": 40}]})
        self.post({"merge": True, "shapes": [{"ip": A, "direction": "up", "mbit": 1, "lossPct": 5}]})
        self.assertEqual(self.tc.down(A), (20000, "delay 40ms limit 317"))
        self.assertEqual(self.tc.up(A), (1000, "loss 5% limit 32"))
        [view] = self.shaper.list()
        self.assertEqual(view["down"], {"latencyMs": 40, "jitterMs": 0, "mbit": 20, "lossPct": 0})
        self.assertEqual(view["up"], {"latencyMs": 0, "jitterMs": 0, "mbit": 1, "lossPct": 5})
        self.assertEqual(view["expectedRttDeltaMs"], 40)

    def test_two_entries_for_one_ip_combine_in_one_request(self):
        r = self.post({"shapes": [
            {"ip": A, "direction": "down", "mbit": 50},
            {"ip": A, "direction": "up", "mbit": 5, "latencyMs": 10},
        ]})
        self.assertEqual(len(r["applied"]), 1)
        self.assertEqual(self.tc.down(A)[0], 50000)
        self.assertEqual(self.tc.up(A), (5000, "delay 10ms limit 67"))

    def test_later_entries_override_earlier_ones_for_their_sides(self):
        self.post({"shapes": [
            {"ip": A, "mbit": 10},
            {"ip": A, "direction": "up", "mbit": 1},
        ]})
        self.assertEqual(self.tc.down(A)[0], 10000)
        self.assertEqual(self.tc.up(A)[0], 1000)

    def test_one_side_only_leaves_the_other_unclassified(self):
        self.post({"shapes": [{"ip": A, "direction": "up", "mbit": 3}]})
        self.assertIsNone(self.tc.down(A))
        self.assertEqual(self.tc.up(A)[0], 3000)
        [view] = self.shaper.list()
        self.assertIsNone(view["down"])

    def test_empty_entry_with_direction_clears_that_side_only(self):
        self.post({"shapes": [{"ip": A, "mbit": 4}]})
        r = self.post({"merge": True, "shapes": [{"ip": A, "direction": "up"}]})
        self.assertEqual(r["cleared"], [])
        self.assertEqual(self.tc.down(A)[0], 4000)
        self.assertIsNone(self.tc.up(A))
        r = self.post({"merge": True, "shapes": [{"ip": A}]})
        self.assertEqual(r["cleared"], [A])
        self.assertIsNone(self.tc.down(A))
        self.assertEqual(self.tc.filters, {})
        self.assertEqual(self.shaper.list(), [])

    def test_clearing_the_last_side_clears_the_ip(self):
        self.post({"shapes": [{"ip": A, "direction": "down", "mbit": 4}]})
        r = self.post({"merge": True, "shapes": [{"ip": A, "direction": "down"}]})
        self.assertEqual(r["cleared"], [A])
        self.assertEqual(self.tc.filters, {})

    def test_without_merge_the_request_is_the_whole_set(self):
        self.post({"shapes": [{"ip": A, "mbit": 4}, {"ip": B, "direction": "up", "mbit": 2}]})
        r = self.post({"shapes": [{"ip": B, "direction": "down", "mbit": 8}]})
        self.assertEqual(r["cleared"], [A])
        self.assertIsNone(self.tc.down(A))
        self.assertEqual(self.tc.down(B)[0], 8000)
        # Without merge, B's earlier upload shape is not carried over.
        self.assertIsNone(self.tc.up(B))

    def test_merge_leaves_other_devices_alone(self):
        self.post({"shapes": [{"ip": A, "mbit": 4}]})
        self.post({"merge": True, "shapes": [{"ip": B, "direction": "down", "mbit": 9}]})
        self.assertEqual(self.tc.down(A)[0], 4000)
        self.assertEqual(self.tc.up(A)[0], 4000)
        self.assertEqual(self.tc.down(B)[0], 9000)

    def test_changing_one_side_never_touches_the_other_sides_filter(self):
        self.post({"shapes": [{"ip": A, "mbit": 4}]})
        self.post({"merge": True, "shapes": [{"ip": A, "direction": "up", "mbit": 1}]})
        self.assertEqual(self.tc.filter_lines_in_last_batch(), [])
        self.post({"merge": True, "shapes": [{"ip": A, "direction": "up"}]})
        self.assertTrue(all(uc.DEV_UP in l for l in self.tc.filter_lines_in_last_batch()))

    def test_a_reused_slot_carries_nothing_from_its_last_device(self):
        self.post({"shapes": [{"ip": A, "mbit": 4, "latencyMs": 100}]})
        self.post({"shapes": []})
        self.post({"shapes": [{"ip": B, "direction": "up", "mbit": 2}]})
        [view] = self.shaper.list()
        self.assertEqual(view["slot"], 1)
        self.assertIsNone(self.tc.down(A))
        self.assertIsNone(self.tc.down(B))
        self.assertEqual(self.tc.rates[(uc.DEV_DOWN, "1:1")], uc.UNCAPPED_KBIT)
        self.assertEqual(self.tc.netem[(uc.DEV_DOWN, "1:1")], "limit 1000")

    def test_a_rebuild_restores_each_side_under_merge(self):
        self.post({"shapes": [{"ip": A, "direction": "down", "mbit": 6}, {"ip": A, "direction": "up", "mbit": 2}]})
        self.tc.filters.clear()  # the tree was rebuilt behind the shaper's back
        self.ifindex = 2
        r = self.post({"merge": True, "shapes": [{"ip": B, "mbit": 3}]})
        self.assertIn("Shaping tree was missing and has been rebuilt", r["warnings"])
        self.assertEqual(self.tc.down(A)[0], 6000)
        self.assertEqual(self.tc.up(A)[0], 2000)
        self.assertEqual(self.tc.down(B)[0], 3000)

    def restart(self):
        """What the service does on a restart: the old tree is gone, then main() loads and restores."""
        saved = uc.load_state()
        self.tc = FakeTc()
        uc.tc_batch = self.tc.batch  # the patch is undone in cleanup
        self.shaper = uc.Shaper()
        self.shaper.init()
        return self.shaper.restore(saved) if saved else 0

    def test_a_restart_relatches_every_side(self):
        self.post({"shapes": [
            {"ip": A, "direction": "down", "mbit": 6, "latencyMs": 30},
            {"ip": A, "direction": "up", "mbit": 2, "lossPct": 1},
            {"ip": B, "direction": "up", "jitterMs": 5, "latencyMs": 10},
        ]})
        before = sorted(self.shaper.list(), key=lambda v: v["ip"])
        self.assertEqual(self.restart(), 2)
        after = sorted(self.shaper.list(), key=lambda v: v["ip"])
        strip = lambda views: [{k: v for k, v in x.items() if k != "appliedAtMs"} for x in views]
        self.assertEqual(strip(after), strip(before))
        self.assertEqual(self.tc.down(A), (6000, "delay 30ms limit 90"))
        self.assertEqual(self.tc.up(A), (2000, "loss 1% limit 32"))
        self.assertIsNone(self.tc.down(B))
        self.assertTrue(self.tc.up(B)[1].startswith("delay 10ms 5ms "))

    def test_a_restart_after_clearing_restores_nothing(self):
        self.post({"shapes": [{"ip": A, "mbit": 6}]})
        self.post({"shapes": []})
        self.assertEqual(self.restart(), 0)
        self.assertEqual(self.tc.filters, {})

    def test_unreadable_state_is_ignored(self):
        os.makedirs(os.path.dirname(uc.STATE), exist_ok=True)
        with open(uc.STATE, "w") as f:
            f.write('{"shapes": [{"ip": "nope"}]}')
        self.assertEqual(uc.load_state(), {})
        with open(uc.STATE, "w") as f:
            f.write("not json")
        self.assertEqual(uc.load_state(), {})

    def test_ip_off_the_shaped_networks_warns(self):
        r = self.post({"shapes": [{"ip": "203.0.113.5", "direction": "up", "mbit": 1}]})
        self.assertTrue(any("not on a shaped network" in w for w in r["warnings"]))


class ValidationTest(unittest.TestCase):
    def test_unknown_shape_field_is_rejected(self):
        with self.assertRaisesRegex(ValueError, r'Unknown field "latency" in shapes\[1\]'):
            uc.as_shape_request({"shapes": [{"ip": A}, {"ip": A, "latency": 50}]})

    def test_unknown_request_field_is_rejected(self):
        with self.assertRaisesRegex(ValueError, r'Unknown field "merged"'):
            uc.as_shape_request({"merged": True, "shapes": []})

    def test_bad_direction_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "direction"):
            uc.as_shape_request({"shapes": [{"ip": A, "direction": "upload"}]})

    def test_null_direction_means_both(self):
        [s], _ = uc.as_shape_request({"shapes": [{"ip": A, "direction": None, "mbit": 1}]})
        self.assertEqual(s["direction"], "both")


if __name__ == "__main__":
    unittest.main()

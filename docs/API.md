# Conditioner API

HTTPS on port 10443 on the gateway, with a self-signed certificate made at install. Clients
must either trust that certificate or skip verification (`curl -k`). No authentication yet.

Base path: `/v1`. The retired Raspberry Pi build served the same API.

## Concepts

Devices under test join one of two test SSIDs, each on its own VLAN:

| SSID | Subnet | Gateway bridge |
| --- | --- | --- |
| `test-a` | `192.0.2.0/24` | `br10` |
| `test-b` | `198.51.100.0/24` | `br20` |

The gateway routes between VLANs in software, so traffic between a test-VLAN device and anything
on another network — the main LAN, the other test VLAN, the internet — passes
through its kernel and can be conditioned. Traffic between two devices on the **same** test VLAN
is switched by the AP and switch, never reaches the gateway, and cannot be shaped.

A shape targets a device's IP. An IP outside the test subnets is accepted, but the response
carries a warning: its traffic never reaches the shaper.

When both ends of a flow are shaped - one device on each test VLAN - both shapes apply: the
sender's upload shape and the receiver's download shape stack.

`POST /v1/shape` is **declarative** by default: the array you send becomes the complete set of
active shapes, and any IP not in the array is returned to unshaped. This makes repeated calls
safe and free of state drift - you never need to clear before setting.

Pass `"merge": true` to touch only the IPs you list and leave every other device's shaping alone.

Each device has two sides, shaped independently: **download** (`down`, traffic toward the
device) and **upload** (`up`, traffic from it). An entry's `direction` says which sides it sets.
To give upload and download different values, send two entries for the same IP - in one request,
or in two requests with `merge`.

Shaping survives a restart of the service: the active shapes are saved to
`/run/udm-conditioner/shapes.json` on every change and reapplied at startup. A reboot of the
gateway starts with nothing shaped.

## `POST /v1/shape`

```jsonc
{
  "shapes": [
    { "ip": "192.0.2.10", "latencyMs": 120, "mbit": 1.5 },
    { "ip": "192.0.2.20", "latencyMs": 0,   "mbit": 10  }
  ]
}
```

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `ip` | IPv4 string | required | Device to shape |
| `direction` | `"both"`, `"down"` or `"up"` | `"both"` | Which sides this entry sets |
| `latencyMs` | number ≥ 0 | `0` | Delay added to each side the entry sets |
| `jitterMs` | number ≥ 0 | `0` | Uniform jitter, giving `latencyMs ± jitterMs` |
| `mbit` | number ≥ 0 | `0` | Bandwidth cap, fractions allowed. `0` = uncapped |
| `lossPct` | number ≥ 0 | `0` | Random packet loss percentage |

Top-level alongside `shapes`:

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `merge` | boolean | `false` | Only touch the listed IPs and sides, leaving others alone |

Any other field, at either level, is rejected with a 400 rather than ignored: a misspelled
`latency` would otherwise read as zero and clear the shape.

### Different upload and download

Entries apply in order, each setting only the sides its `direction` names. These two are the
same - 50 Mbit down, 5 Mbit and 10 ms up:

```sh
# one request
curl -sk -X POST https://gateway.example:10443/v1/shape -H 'Content-Type: application/json' \
  -d '{"merge":true,"shapes":[
        {"ip":"192.0.2.10","direction":"down","mbit":50},
        {"ip":"192.0.2.10","direction":"up","mbit":5,"latencyMs":10}
      ]}'

# two requests; the second leaves the download side as the first set it
curl -sk -X POST https://gateway.example:10443/v1/shape -H 'Content-Type: application/json' \
  -d '{"merge":true,"shapes":[{"ip":"192.0.2.10","direction":"down","mbit":50}]}'
curl -sk -X POST https://gateway.example:10443/v1/shape -H 'Content-Type: application/json' \
  -d '{"merge":true,"shapes":[{"ip":"192.0.2.10","direction":"up","mbit":5,"latencyMs":10}]}'
```

An entry replaces every value on the sides it sets, so a field it omits returns to its default
there. A side no entry has set is not shaped at all. Without `merge`, an IP's sides come only
from this request's entries.

### Removing shaping

An entry naming an IP with no conditioning on it - `{ "ip": "..." }`, or every field zero - means
"these sides are unshaped", and clears anything already applied to them. With no `direction`
that is both sides; `{ "ip": "...", "direction": "up" }` clears only the upload side. A device
with neither side shaped is cleared. Combine that with `merge`
to undo one device without disturbing the rest:

```sh
# clear 192.0.2.10, leave every other shaped device exactly as it was
curl -sk -X POST https://gateway.example:10443/v1/shape -H 'Content-Type: application/json' \
  -d '{"merge":true,"shapes":[{"ip":"192.0.2.10"}]}'
```

Without `merge`, that same call also clears everything you did not list, because the array is
the complete desired state. Clearing an IP that was never shaped is a harmless no-op, and
shaping and clearing can be mixed in one call:

```sh
curl -sk -X POST https://gateway.example:10443/v1/shape -H 'Content-Type: application/json' \
  -d '{"merge":true,"shapes":[
        {"ip":"192.0.2.10"},
        {"ip":"192.0.2.20","latencyMs":250,"mbit":0.5}
      ]}'
```

**`latencyMs` is one-way, per side, so with `direction` `both` round-trip latency rises by
roughly `2 × latencyMs`.** A `latencyMs` of 100 produces about 200 ms of added ping time -
measured 211 ms against a 9 ms baseline. The response returns `expectedRttDeltaMs`, the two
sides' delays added together, so this is never ambiguous.

Response:

```jsonc
{
  "ok": true,
  "merge": false,
  "cleared": ["192.0.2.20"],  // IPs returned to fully unshaped by this call
  "applied": [                 // every shaped device after this call, each side or null
    { "ip": "192.0.2.10", "slot": 1,
      "down": { "latencyMs": 120, "jitterMs": 0, "mbit": 1.5, "lossPct": 0 },
      "up":   { "latencyMs": 120, "jitterMs": 0, "mbit": 1.5, "lossPct": 0 },
      "expectedRttDeltaMs": 240 }
  ],
  "applyDurationMs": 6.1,      // whole request, server side
  "tcDurationMs": 5.4,         // time inside the single tc invocation
  "commandCount": 8,
  "warnings": []               // e.g. an IP that is not on a test VLAN
}
```

A side that is `null` passes unshaped. `mbit` is `null` on a side with latency, jitter or loss
but no cap.

Up to **32** devices may be shaped simultaneously. Beyond that the extra shapes are dropped and
named in `warnings`.

## Other endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/health` | `{ ok, version, iface, interfaces, radios, uptimeMs, treeIntact, activeCount, maxSlots }` |
| `GET` | `/v1/shape` | Current active shapes, each as in `applied` above plus `appliedAtMs` |
| `DELETE` | `/v1/shape` | Clear all shaping |
| `POST` | `/v1/reset` | Tear down and rebuild the whole tc tree |
| `GET` | `/v1/devices` | Clients on the test VLANs, with IP, network, SSID and hostname |
| `GET` | `/v1/stats` | Raw `tc -s class` counters for both directions |
| `GET` | `/v1/history` | Every shaping change, newest first: time, caller IP, request, result. `?limit=N` |

`interfaces` in `/v1/health` lists each shaped bridge with `name`, `ssid`, `subnet`, `present`
and `hooked` (shaping is attached to it). `radios` is the same list under the Pi build's name.

`GET /v1/devices` is how a test agent discovers what it can shape without hard-coding
addresses. It joins the gateway's neighbour table with its DHCP leases. Each device has `mac`,
`ip`, `iface`, `ssid`, `hostname`, `state`, and `ipSource`: `arp` for a live neighbour entry,
`lease` for a DHCP lease with no live entry.

## Examples

```sh
# What can I shape?
curl -sk https://gateway.example:10443/v1/devices

# Degrade one device, leave another alone
curl -sk -X POST https://gateway.example:10443/v1/shape -H 'Content-Type: application/json' \
  -d '{"shapes":[{"ip":"192.0.2.10","latencyMs":150,"jitterMs":30,"mbit":1.5}]}'

# Back to normal
curl -sk -X DELETE https://gateway.example:10443/v1/shape
```

## Performance

Measured 2026-09-11 over HTTPS from a wired Mac on the main LAN, a new TLS connection per call:

| | |
| --- | --- |
| HTTPS round-trip, p50 | 22 ms |
| HTTPS round-trip, max | 43 ms |
| Server-side apply | ~6–15 ms |
| Inside `tc` | ~5–13 ms |

Comfortably inside a 100 ms budget, so an agent can sweep conditions in a tight loop. The qdisc
tree is built once at startup with 32 pre-made slots; a shape change is a `tc class change`
plus a `tc qdisc change`, plus a filter when the slot's device changes, all issued in a single
batched `tc` invocation. No teardown, no rebuild, and changing one device never disturbs another.

## History

Every call that changes shaping (`POST /v1/shape`, `DELETE /v1/shape`, `POST /v1/reset`,
including rejected ones) is recorded with its time, the caller's IP, the shapes it asked for and
what was applied or cleared. The last 500 are served by `GET /v1/history`; every one is also
written to the gateway's journal as a `shape-call` JSON line, which survives restarts:

```sh
journalctl -u udm-conditioner --no-pager | grep shape-call
```

When several agents share the conditioner, this is how to tell who shaped what.

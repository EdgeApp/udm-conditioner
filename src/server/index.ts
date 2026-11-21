import dgram from 'dgram'
import express from 'express'

import { Shaper } from '../shaper'
import { SLOTS } from '../tc/plan'
import { run, tc } from '../tc/tcClient'
import { asShapeRequest } from '../types'

const PORT = Number(process.env.GSC_PORT ?? 9393)
const HOST = process.env.GSC_HOST ?? '127.0.0.1'
// One or more AP radios, comma- or space-separated. Shaping follows a device by
// IP whichever radio it has joined.
const IFACES = (process.env.GSC_IFACE ?? 'wlan0').split(/[\s,]+/).filter(iface => iface !== '')

const shaper = new Shaper(IFACES)
const startedAt = Date.now()

const app = express()
app.use(express.json({ limit: '256kb' }))

/**
 * Record of every call that changes shaping.
 *
 * Several agents can drive this API at once, and when a camera drops the first
 * question is whether someone shaped it. Each mutation is kept in memory for
 * GET /v1/history and written to the journal as a `shape-call` line, which
 * survives restarts. The caller is taken from X-Forwarded-For, since every
 * request arrives through Caddy.
 */
interface HistoryEntry {
  atMs: number
  at: string
  method: string
  path: string
  client: string
  status: number
  merge?: unknown
  requested?: unknown
  applied?: unknown
  cleared?: unknown
  applyDurationMs?: unknown
  error?: unknown
}
const HISTORY_MAX = 500
const history: HistoryEntry[] = []

const clientOf = (req: express.Request): string => {
  const header = req.headers['x-forwarded-for']
  const first = (Array.isArray(header) ? header[0] : header)?.split(',')[0]?.trim()
  return first != null && first !== '' ? first : req.socket.remoteAddress ?? 'unknown'
}

app.use((req, res, next) => {
  if (req.method === 'GET') {
    next()
    return
  }
  const atMs = Date.now()
  const originalJson = res.json.bind(res)
  let responseBody: any
  res.json = ((body: unknown) => {
    responseBody = body
    return originalJson(body)
  }) as typeof res.json
  res.on('finish', () => {
    const entry: HistoryEntry = {
      atMs,
      at: new Date(atMs).toISOString(),
      method: req.method,
      path: req.path,
      client: clientOf(req),
      status: res.statusCode,
      merge: req.body?.merge,
      requested: req.body?.shapes,
      applied: responseBody?.applied,
      cleared: responseBody?.cleared,
      applyDurationMs: responseBody?.applyDurationMs,
      error: responseBody?.error
    }
    history.push(entry)
    if (history.length > HISTORY_MAX) history.shift()
    console.log(`shape-call ${JSON.stringify(entry)}`)
  })
  next()
})

const wrap =
  (fn: (req: express.Request, res: express.Response) => Promise<void>) =>
  (req: express.Request, res: express.Response, next: express.NextFunction) => {
    fn(req, res).catch(next)
  }

app.get(
  '/v1/health',
  wrap(async (_req, res) => {
    res.json({
      ok: true,
      version: '1.0.0',
      iface: IFACES.join(','),
      radios: await shaper.radios(),
      uptimeMs: Date.now() - startedAt,
      treeIntact: await shaper.intact(),
      activeCount: shaper.list().length,
      maxSlots: SLOTS
    })
  })
)

app.get('/v1/shape', (_req, res) => {
  res.json({ shapes: shaper.list() })
})

/**
 * Declarative: the posted array becomes the complete set of active shapes.
 * Any IP not listed is returned to unshaped. Safe to call repeatedly.
 */
app.post(
  '/v1/shape',
  wrap(async (req, res) => {
    const body = asShapeRequest(req.body)
    const result = await shaper.setShapes(body.shapes, body.merge)
    res.json({
      ok: true,
      merge: body.merge,
      cleared: result.cleared,
      applied: result.applied.map(a => ({
        ip: a.ip,
        latencyMs: a.delayMs,
        jitterMs: a.jitterMs,
        mbit: a.rateKbit >= 10_000_000 ? null : a.rateKbit / 1000,
        lossPct: a.lossPct,
        slot: a.slot,
        expectedRttDeltaMs: a.delayMs * 2
      })),
      applyDurationMs: Number(result.applyDurationMs.toFixed(2)),
      tcDurationMs: Number(result.tcDurationMs.toFixed(2)),
      commandCount: result.commands.length,
      warnings: result.warnings
    })
  })
)

app.delete(
  '/v1/shape',
  wrap(async (_req, res) => {
    const result = await shaper.clear()
    res.json({
      ok: true,
      cleared: result.cleared,
      applyDurationMs: Number(result.applyDurationMs.toFixed(2)),
      warnings: result.warnings
    })
  })
)

app.post(
  '/v1/reset',
  wrap(async (_req, res) => {
    await shaper.reset()
    await shaper.init()
    res.json({ ok: true, rebuilt: true })
  })
)

let lastSweepMs = 0

/**
 * Last known IP per MAC.
 *
 * A station that has been idle for a few seconds may not answer the sweep in
 * time, and a momentarily blank IP makes the device look unshapeable to a
 * caller. The address rarely changes, so remembering it is far more useful than
 * reporting null - the response marks whether the value came from the live
 * neighbour table or from here.
 */
const ipCache = new Map<string, string>()

/**
 * Populate the neighbour table for the bridge subnet.
 *
 * This box is an L2 bridge, so it only learns a client's IP when that client
 * happens to address the Pi itself. Associated stations therefore often have a
 * MAC and no IP, which is useless to a caller trying to discover what it can
 * shape. Poking each address with a stray UDP datagram makes the kernel ARP for
 * it, which fills in the table.
 */
const sweepSubnet = async (): Promise<void> => {
  const now = Date.now()
  if (now - lastSweepMs < 15000) return
  lastSweepMs = now

  const addr = await run('ip', ['-4', '-o', 'addr', 'show', 'dev', 'br0'])
  const m = /inet (\d+\.\d+\.\d+)\.\d+\/(\d+)/.exec(addr)
  if (m == null || m[2] !== '24') return
  const prefix = m[1]

  const sock = dgram.createSocket('udp4')
  await new Promise<void>(resolve => sock.bind(resolve))
  const payload = Buffer.alloc(1)
  // Paced rather than blasted. Sending all 254 at once forces a burst of ARP
  // broadcast, which goes out over the air at the lowest basic rate and spikes
  // radio transmit current hard enough to brown out a Pi on a 15W supply -
  // two 2-second undervoltage events were traced to exactly this. Spreading
  // the same work over a couple of seconds costs nothing and draws evenly.
  for (let pass = 0; pass < 2; pass++) {
    for (let host = 1; host <= 254; host++) {
      sock.send(payload, 9, `${prefix}.${host}`, () => undefined)
      if (host % 16 === 0) await new Promise(resolve => setTimeout(resolve, 60))
    }
    await new Promise(resolve => setTimeout(resolve, 600))
  }
  sock.close()
}

app.get(
  '/v1/devices',
  wrap(async (_req, res) => {
    // `iw` rather than `hostapd_cli`: it needs no hostapd control socket, so
    // this keeps working regardless of how hostapd was configured.
    // Every radio's stations. A radio that is unplugged just yields none.
    const dumpAll = async (): Promise<Array<{ iface: string; ssid: string | null; dump: string }>> =>
      await Promise.all(
        IFACES.map(async iface => {
          const info = await run('iw', ['dev', iface, 'info'])
          return {
            iface,
            ssid: /^\s*ssid\s+(.+)$/m.exec(info)?.[1].trim() ?? null,
            dump: await run('iw', ['dev', iface, 'station', 'dump'])
          }
        })
      )
    let radios = await dumpAll()
    let neigh = await run('ip', ['neigh', 'show', 'dev', 'br0'])

    // If any associated station is missing an IP, resolve and re-read.
    const macsInDump = radios.reduce((n, r) => n + (r.dump.match(/^Station\s+\S+/gm) ?? []).length, 0)
    const macsResolved = (neigh.match(/lladdr/g) ?? []).length
    if (macsInDump > macsResolved) {
      await sweepSubnet()
      neigh = await run('ip', ['neigh', 'show', 'dev', 'br0'])
      radios = await dumpAll()
    }

    const macToIp = new Map<string, string>()
    for (const line of neigh.split('\n')) {
      const m = /^(\S+)\s+lladdr\s+(\S+)/.exec(line.trim())
      if (m != null) {
        macToIp.set(m[2].toLowerCase(), m[1])
        ipCache.set(m[2].toLowerCase(), m[1])
      }
    }

    const num = (v: string): number | null => {
      const f = parseFloat(v)
      return Number.isFinite(f) ? f : null
    }

    const devices: Array<Record<string, unknown>> = []
    for (const { iface, ssid, dump } of radios) {
      let current: Record<string, unknown> | null = null
      for (const raw of dump.split('\n')) {
        const station = /^Station\s+(\S+)/.exec(raw.trim())
        if (station != null) {
          const mac = station[1].toLowerCase()
          const live = macToIp.get(mac)
          current = {
            mac,
            ip: live ?? ipCache.get(mac) ?? null,
            ipSource: live != null ? 'arp' : ipCache.has(mac) ? 'cached' : null,
            iface,
            ssid,
            signalDbm: null,
            txMbit: null,
            rxMbit: null,
            connectedSec: null,
            inactiveMs: null
          }
          devices.push(current)
          continue
        }
        if (current == null) continue
        const kv = /^([^:]+):\s*(.+)$/.exec(raw.trim())
        if (kv == null) continue
        const key = kv[1].trim()
        const value = kv[2].trim()
        if (key === 'signal') current.signalDbm = num(value)
        else if (key === 'tx bitrate') current.txMbit = num(value)
        else if (key === 'rx bitrate') current.rxMbit = num(value)
        else if (key === 'connected time') current.connectedSec = num(value)
        else if (key === 'inactive time') current.inactiveMs = num(value)
      }
    }

    res.json({ iface: IFACES.join(','), count: devices.length, devices })
  })
)

app.get(
  '/v1/stats',
  wrap(async (_req, res) => {
    const down = await tc(['-s', 'class', 'show', 'dev', 'ifb-cond-dn'])
    const up = await tc(['-s', 'class', 'show', 'dev', 'ifb-cond-up'])
    res.json({ shapes: shaper.list(), raw: { down, up } })
  })
)

/** Most recent shaping changes first. ?limit=N, default 50. */
app.get('/v1/history', (req, res) => {
  const limit = Math.max(1, Math.min(HISTORY_MAX, Number(req.query.limit ?? 50) || 50))
  res.json({ count: history.length, entries: history.slice(-limit).reverse() })
})

app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const message = String(err?.message ?? err)
  const isValidation = /Expected|Invalid|Cannot read/i.test(message)
  res.status(isValidation ? 400 : 500).json({ ok: false, error: message })
})

const main = async (): Promise<void> => {
  await shaper.init()
  shaper.startReconciler()
  app.listen(PORT, HOST, () => {
    console.log(`udm-conditioner listening on ${HOST}:${PORT}, shaping ${IFACES.join(', ')}`)
  })
}

main().catch(err => {
  console.error('Fatal:', err)
  process.exit(1)
})

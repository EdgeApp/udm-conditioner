import { Shape } from '../types'

export const MTU = 1500
/** Number of pre-built shaping slots. Bounds how many devices can be shaped at once. */
export const SLOTS = 32

export const DEV_DOWN = 'ifb-cond-dn'
export const DEV_UP = 'ifb-cond-up'

/** Rate used for a slot that is not capping anything. */
export const UNCAPPED_KBIT = 10_000_000

export interface SlotPlan {
  slot: number
  ip: string
  rateKbit: number
  delayMs: number
  jitterMs: number
  lossPct: number
}

export const classId = (slot: number): string => `1:${slot}`
export const netemHandle = (slot: number): string => `${100 + slot}:`

/** Megabits (fractional allowed) to whole kbit, which is what tc consumes. */
export const mbitToKbit = (mbit: number): number =>
  mbit <= 0 ? UNCAPPED_KBIT : Math.max(1, Math.round(mbit * 1000))

/**
 * HTB burst: about 1 ms of the configured rate, floored at one MTU so a very
 * low rate can still emit a full packet.
 */
export const burstBytes = (rateKbit: number): number =>
  Math.max(MTU + 100, Math.ceil((rateKbit * 1000) / 8 / 1000))

/**
 * HTB quantum, set explicitly rather than left to r2q.
 *
 * HTB derives quantum from rate/r2q and warns once it exceeds 200000, which it
 * does for any high rate. Clamping here keeps the kernel quiet and the DRR
 * behaviour sane.
 */
export const quantumBytes = (rateKbit: number): number => {
  const perSec = (rateKbit * 1000) / 8
  return Math.min(200000, Math.max(MTU, Math.ceil(perSec / 10)))
}

/** How much standing queue a shaped link is allowed, in seconds of its rate. */
const TARGET_BUFFER_SEC = 0.15

/**
 * netem queue depth, in packets.
 *
 * Two things share this budget: the delay line, which must hold every packet
 * in flight for `delay + jitter`, and the queue that absorbs the excess when
 * the source sends faster than the cap.
 *
 * Both matter, in opposite directions. Too small and a low rate with high
 * delay tail-drops everything, so the link looks broken rather than slow. Too
 * large and the queue becomes seconds of bufferbloat: TCP's loss signal
 * arrives far too late, so throughput oscillates and drops arrive in bursts.
 * A flat 1000-packet floor caused exactly that here — at 1.5 Mbit it is about
 * 8 seconds of buffer, and a 4 Mbit source against a 1.5 Mbit cap racked up
 * 65k drops.
 *
 * So size the delay line from the requested delay, and the queue from a target
 * standing latency, rather than picking a constant.
 */
export const netemLimit = (rateKbit: number, delayMs: number, jitterMs: number): number => {
  const bytesPerSec = (rateKbit * 1000) / 8
  const delayLinePackets = (bytesPerSec * ((delayMs + jitterMs) / 1000)) / MTU
  const queuePackets = (bytesPerSec * TARGET_BUFFER_SEC) / MTU
  const total = Math.ceil(delayLinePackets + queuePackets)
  return Math.min(200000, Math.max(32, total))
}

export const shapeToSlotPlan = (shape: Shape, slot: number): SlotPlan => ({
  slot,
  ip: shape.ip,
  rateKbit: mbitToKbit(shape.mbit),
  delayMs: shape.latencyMs,
  jitterMs: shape.jitterMs,
  lossPct: shape.lossPct
})

const netemArgs = (p: SlotPlan): string => {
  const parts: string[] = []
  if (p.delayMs > 0 || p.jitterMs > 0) {
    parts.push(`delay ${p.delayMs}ms`)
    if (p.jitterMs > 0) parts.push(`${p.jitterMs}ms`)
  }
  if (p.lossPct > 0) parts.push(`loss ${p.lossPct}%`)
  parts.push(`limit ${netemLimit(p.rateKbit, p.delayMs, p.jitterMs)}`)
  return parts.join(' ')
}

/**
 * Build the tc batch that moves the live configuration to `plans`.
 *
 * `activeSlots` are the slots currently carrying a filter; any of those not in
 * `plans` get their filters removed and their class reset. Everything is one
 * batch so a whole multi-device change lands in a single tc invocation.
 */
export const buildBatch = (plans: SlotPlan[], activeSlots: number[]): string[] => {
  const lines: string[] = []
  const wanted = new Set(plans.map(p => p.slot))

  for (const p of plans) {
    const burst = burstBytes(p.rateKbit)
    for (const dev of [DEV_DOWN, DEV_UP]) {
      lines.push(
        `class change dev ${dev} parent 1: classid ${classId(p.slot)} htb ` +
          `rate ${p.rateKbit}kbit ceil ${p.rateKbit}kbit burst ${burst}b cburst ${burst}b ` +
          `quantum ${quantumBytes(p.rateKbit)}`
      )
      lines.push(
        `qdisc change dev ${dev} parent ${classId(p.slot)} handle ${netemHandle(p.slot)} netem ${netemArgs(p)}`
      )
    }
    // Downstream: traffic toward the device. Upstream: traffic from the device.
    lines.push(
      `filter replace dev ${DEV_DOWN} parent 1: protocol ip prio 1 handle ${p.slot} ` +
        `flower dst_ip ${p.ip}/32 classid ${classId(p.slot)}`
    )
    lines.push(
      `filter replace dev ${DEV_UP} parent 1: protocol ip prio 1 handle ${p.slot} ` +
        `flower src_ip ${p.ip}/32 classid ${classId(p.slot)}`
    )
  }

  for (const slot of activeSlots) {
    if (wanted.has(slot)) continue
    lines.push(`filter delete dev ${DEV_DOWN} parent 1: protocol ip prio 1 handle ${slot} flower`)
    lines.push(`filter delete dev ${DEV_UP} parent 1: protocol ip prio 1 handle ${slot} flower`)
    for (const dev of [DEV_DOWN, DEV_UP]) {
      lines.push(
        `class change dev ${dev} parent 1: classid ${classId(slot)} htb ` +
          `rate ${UNCAPPED_KBIT}kbit ceil ${UNCAPPED_KBIT}kbit burst ${burstBytes(UNCAPPED_KBIT)}b ` +
          `cburst ${burstBytes(UNCAPPED_KBIT)}b quantum ${quantumBytes(UNCAPPED_KBIT)}`
      )
      lines.push(
        `qdisc change dev ${dev} parent ${classId(slot)} handle ${netemHandle(slot)} netem limit 1000`
      )
    }
  }

  return lines
}

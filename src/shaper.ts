import {
  attachHooks,
  baselineIntact,
  buildBaseline,
  ifbTreeIntact,
  presentIfaces,
  teardownBaseline,
  unhookedIfaces
} from './tc/baseline'
import { buildBatch, SLOTS, SlotPlan, shapeToSlotPlan, UNCAPPED_KBIT } from './tc/plan'
import { tcBatch } from './tc/tcClient'
import { Shape } from './types'

export interface AppliedShape extends SlotPlan {
  appliedAtMs: number
}

export interface ApplyResult {
  applied: AppliedShape[]
  cleared: string[]
  applyDurationMs: number
  tcDurationMs: number
  commands: string[]
  warnings: string[]
}

/**
 * Owns the live shaping state.
 *
 * Every mutation runs through one promise chain, so concurrent API calls can
 * never interleave halfway through a tc batch.
 */
export class Shaper {
  private readonly ifaces: string[]
  private active = new Map<string, AppliedShape>() // ip -> applied
  private slotOfIp = new Map<string, number>()
  private queue: Promise<unknown> = Promise.resolve()

  constructor(ifaces: string[]) {
    this.ifaces = ifaces
  }

  async init(): Promise<void> {
    await this.serialize(async () => {
      await buildBaseline(this.ifaces)
      this.active.clear()
      this.slotOfIp.clear()
    })
  }

  private serialize<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.queue.then(fn, fn)
    this.queue = next.catch(() => undefined)
    return next
  }

  private assignSlots(shapes: Shape[]): { plans: SlotPlan[]; warnings: string[] } {
    const warnings: string[] = []
    const used = new Set<number>()
    const plans: SlotPlan[] = []

    // Keep an IP on the slot it already occupies so its filter is replaced in
    // place rather than torn down and rebuilt.
    for (const shape of shapes) {
      const existing = this.slotOfIp.get(shape.ip)
      if (existing != null) used.add(existing)
    }
    for (const shape of shapes) {
      let slot = this.slotOfIp.get(shape.ip)
      if (slot == null) {
        for (let candidate = 1; candidate <= SLOTS; candidate++) {
          if (!used.has(candidate)) {
            slot = candidate
            break
          }
        }
      }
      if (slot == null) {
        warnings.push(`No free slot for ${shape.ip}; ${SLOTS} shapes is the maximum`)
        continue
      }
      used.add(slot)
      plans.push(shapeToSlotPlan(shape, slot))
    }
    return { plans, warnings }
  }

  /** The Shape that would reproduce an already-applied entry. */
  private static toShape(applied: AppliedShape): Shape {
    return {
      ip: applied.ip,
      latencyMs: applied.delayMs,
      jitterMs: applied.jitterMs,
      mbit: applied.rateKbit >= UNCAPPED_KBIT ? 0 : applied.rateKbit / 1000,
      lossPct: applied.lossPct
    }
  }

  /** True when a shape asks for no conditioning at all. */
  private static isUnshaped(shape: Shape): boolean {
    return (
      shape.mbit <= 0 && shape.latencyMs <= 0 && shape.jitterMs <= 0 && shape.lossPct <= 0
    )
  }

  /**
   * Apply `shapes`.
   *
   * Declarative by default: the array becomes the complete active set. With
   * `merge`, only the listed IPs are touched. In either mode an entry naming an
   * IP with no conditioning on it clears that device.
   */
  async setShapes(shapes: Shape[], merge = false): Promise<ApplyResult> {
    return await this.serialize(async () => {
      const started = process.hrtime.bigint()
      const warnings: string[] = []

      if (!(await ifbTreeIntact())) {
        warnings.push('Shaping tree was missing and has been rebuilt')
        await buildBaseline(this.ifaces)
        this.active.clear()
        this.slotOfIp.clear()
      } else {
        for (const iface of await unhookedIfaces(this.ifaces)) {
          await attachHooks(iface)
          warnings.push(`Re-attached shaping hooks to ${iface}`)
        }
      }

      const desired = new Map<string, Shape>()
      if (merge) {
        for (const applied of this.active.values()) {
          desired.set(applied.ip, Shaper.toShape(applied))
        }
      }
      const cleared: string[] = []
      for (const shape of shapes) {
        if (Shaper.isUnshaped(shape)) {
          if (desired.delete(shape.ip) || this.active.has(shape.ip)) cleared.push(shape.ip)
          continue
        }
        desired.set(shape.ip, shape)
      }
      if (!merge) {
        for (const ip of this.active.keys()) {
          if (!desired.has(ip) && !cleared.includes(ip)) cleared.push(ip)
        }
      }

      const { plans, warnings: slotWarnings } = this.assignSlots([...desired.values()])
      warnings.push(...slotWarnings)

      const activeSlots = [...this.slotOfIp.values()]
      const batch = buildBatch(plans, activeSlots)
      const result = await tcBatch(batch)
      if (result.stderr.trim() !== '') {
        for (const line of result.stderr.trim().split('\n')) {
          // Deleting a filter that was never installed is expected on the
          // first clear of a slot; anything else is worth surfacing.
          if (!/Cannot find|No such file|RTNETLINK answers: Invalid argument/i.test(line)) {
            warnings.push(line)
          }
        }
      }

      const appliedAtMs = Date.now()
      this.active = new Map()
      this.slotOfIp = new Map()
      const applied: AppliedShape[] = []
      for (const p of plans) {
        const entry: AppliedShape = { ...p, appliedAtMs }
        this.active.set(p.ip, entry)
        this.slotOfIp.set(p.ip, p.slot)
        applied.push(entry)
      }

      return {
        applied,
        cleared,
        applyDurationMs: Number(process.hrtime.bigint() - started) / 1e6,
        tcDurationMs: result.durationMs,
        commands: batch,
        warnings
      }
    })
  }

  async clear(): Promise<ApplyResult> {
    return await this.setShapes([], false)
  }

  async reset(): Promise<void> {
    await this.serialize(async () => {
      await teardownBaseline(this.ifaces)
      this.active.clear()
      this.slotOfIp.clear()
    })
  }

  list(): AppliedShape[] {
    return [...this.active.values()]
  }

  get(ip: string): AppliedShape | undefined {
    return this.active.get(ip)
  }

  async intact(): Promise<boolean> {
    return await baselineIntact(this.ifaces)
  }

  /** Each configured radio: whether it exists, and whether its hooks are on. */
  async radios(): Promise<Array<{ name: string; present: boolean; hooked: boolean }>> {
    const present = new Set(presentIfaces(this.ifaces))
    const unhooked = new Set(await unhookedIfaces(this.ifaces))
    return this.ifaces.map(name => ({
      name,
      present: present.has(name),
      hooked: present.has(name) && !unhooked.has(name)
    }))
  }

  /**
   * Keep the apparatus whole as radios come and go.
   *
   * Unplugging a USB radio destroys its netdev and the hooks on it, but the IFB
   * tree and every active shape survive, so a returning radio only needs its
   * hooks re-attached - which leaves shaping on the other radios untouched. A
   * missing radio is simply skipped. Only if the IFB tree itself is gone is the
   * whole thing rebuilt and the previous shapes reapplied.
   */
  startReconciler(intervalMs = 10000): NodeJS.Timeout {
    return setInterval(() => {
      this.serialize(async () => {
        if (await ifbTreeIntact()) {
          for (const iface of await unhookedIfaces(this.ifaces)) {
            await attachHooks(iface)
            console.log(`reconciler: re-attached shaping hooks to ${iface}`)
          }
          return
        }
        console.log('reconciler: shaping tree missing, rebuilding')
        const previous = [...this.active.values()].map(a => Shaper.toShape(a))
        await buildBaseline(this.ifaces)
        this.active.clear()
        this.slotOfIp.clear()
        if (previous.length > 0) {
          const { plans } = this.assignSlots(previous)
          const result = await tcBatch(buildBatch(plans, []))
          if (result.stderr.trim() === '') {
            const appliedAtMs = Date.now()
            for (const plan of plans) {
              this.active.set(plan.ip, { ...plan, appliedAtMs })
              this.slotOfIp.set(plan.ip, plan.slot)
            }
          }
          console.log(`reconciler: reapplied ${plans.length} shape(s)`)
        }
      }).catch(err => console.error('reconciler failed:', err))
    }, intervalMs)
  }
}

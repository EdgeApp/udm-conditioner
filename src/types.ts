import { asArray, asBoolean, asNumber, asObject, asOptional, asString, Cleaner } from 'cleaners'

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

export const asIp: Cleaner<string> = raw => {
  const s = asString(raw)
  const m = IPV4.exec(s)
  if (m == null) throw new TypeError(`Expected an IPv4 address, got "${s}"`)
  for (let i = 1; i <= 4; i++) {
    const octet = Number(m[i])
    if (octet > 255) throw new TypeError(`Invalid IPv4 address "${s}"`)
  }
  return s
}

/** A non-negative finite number. */
const asNonNegative: Cleaner<number> = raw => {
  const n = asNumber(raw)
  if (!Number.isFinite(n) || n < 0) throw new TypeError(`Expected a number >= 0, got ${n}`)
  return n
}

/**
 * One device's condition.
 *
 * `latencyMs` is added in EACH direction, so round-trip latency rises by
 * roughly 2 * latencyMs. `mbit` accepts fractions, e.g. 1.5.
 *
 * An entry with no conditioning on it at all — just an `ip`, or every field
 * zero — means "this device is unshaped", and clears anything already applied
 * to it.
 */
export const asShape = asObject({
  ip: asIp,
  latencyMs: asOptional(asNonNegative, 0),
  jitterMs: asOptional(asNonNegative, 0),
  mbit: asOptional(asNonNegative, 0), // 0 or omitted = uncapped
  lossPct: asOptional(asNonNegative, 0)
})
export type Shape = ReturnType<typeof asShape>

/**
 * `merge: false` (the default) is declarative: the posted array becomes the
 * complete set of active shapes and any IP not listed is returned to normal.
 *
 * `merge: true` touches only the IPs listed, leaving every other device's
 * shaping alone. That is what makes a bare `{ ip }` entry mean "undo this one
 * device" rather than "undo everything except this one".
 */
export const asShapeRequest = asObject({
  shapes: asArray(asShape),
  merge: asOptional(asBoolean, false)
})
export type ShapeRequest = ReturnType<typeof asShapeRequest>

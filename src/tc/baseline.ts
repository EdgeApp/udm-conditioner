import { execFile } from 'child_process'
import { existsSync } from 'fs'
import { promisify } from 'util'

import { burstBytes, classId, DEV_DOWN, DEV_UP, netemHandle, quantumBytes, SLOTS } from './plan'
import { tcBatch } from './tcClient'

const execFileAsync = promisify(execFile)

const quiet = async (cmd: string, args: string[]): Promise<void> => {
  try {
    await execFileAsync(cmd, args)
  } catch {
    /* expected when the object does not exist */
  }
}

const UNCAPPED_KBIT = 10_000_000
const MODULES = [
  'sch_netem',
  'sch_htb',
  'ifb',
  'act_mirred',
  'cls_flower',
  'cls_matchall',
  'sch_ingress'
]

/**
 * The configured radios that exist right now.
 *
 * A USB radio can be unplugged at any moment, which destroys its netdev. One
 * missing radio must not stop the others from being shaped, so everything below
 * works on whichever radios are present and skips the rest.
 */
export const presentIfaces = (ifaces: string[]): string[] =>
  ifaces.filter(iface => existsSync(`/sys/class/net/${iface}`))

/**
 * Funnel one radio's traffic through the IFB pair.
 *
 * The radio gets a `clsact` hook, which is a filter attachment point rather
 * than a root qdisc, so the Wi-Fi driver keeps its own fq_codel / airtime
 * queueing intact; replacing the radio's root qdisc degrades the link in ways
 * that would contaminate every measurement taken through it.
 *
 * Every radio feeds the same pair, and the per-IP filters live on the pair, so a
 * device's shaping follows it whichever radio it joins.
 */
export const attachHooks = async (iface: string): Promise<void> => {
  await quiet('tc', ['qdisc', 'del', 'dev', iface, 'clsact'])
  await execFileAsync('tc', ['qdisc', 'add', 'dev', iface, 'clsact'])
  await execFileAsync('tc', [
    'filter', 'add', 'dev', iface, 'egress', 'protocol', 'all', 'prio', '1',
    'matchall', 'action', 'mirred', 'egress', 'redirect', 'dev', DEV_DOWN
  ])
  await execFileAsync('tc', [
    'filter', 'add', 'dev', iface, 'ingress', 'protocol', 'all', 'prio', '1',
    'matchall', 'action', 'mirred', 'egress', 'redirect', 'dev', DEV_UP
  ])
}

/** The IFB pair with its uncapped default class and the per-slot classes. */
const buildIfbTree = async (): Promise<void> => {
  for (const dev of [DEV_DOWN, DEV_UP]) {
    await execFileAsync('ip', ['link', 'add', dev, 'type', 'ifb'])
    await execFileAsync('ip', ['link', 'set', dev, 'txqueuelen', '2000'])
    await execFileAsync('ip', ['link', 'set', dev, 'up'])
  }

  const lines: string[] = []
  for (const dev of [DEV_DOWN, DEV_UP]) {
    lines.push(`qdisc add dev ${dev} root handle 1: htb default 9999`)
    // burst/cburst must be set explicitly. Given a rate but no burst, HTB
    // derives a token-bucket depth of zero, and then throttles hard no matter
    // how high the rate is - unshaped traffic through this class was being held
    // to a couple of Mbit with millions of overlimit events.
    lines.push(
      `class add dev ${dev} parent 1: classid 1:9999 htb rate ${UNCAPPED_KBIT}kbit ` +
        `ceil ${UNCAPPED_KBIT}kbit burst ${burstBytes(UNCAPPED_KBIT)}b ` +
        `cburst ${burstBytes(UNCAPPED_KBIT)}b quantum ${quantumBytes(UNCAPPED_KBIT)}`
    )
    for (let slot = 1; slot <= SLOTS; slot++) {
      lines.push(
        `class add dev ${dev} parent 1: classid ${classId(slot)} htb ` +
          `rate ${UNCAPPED_KBIT}kbit ceil ${UNCAPPED_KBIT}kbit burst ${burstBytes(UNCAPPED_KBIT)}b ` +
          `quantum ${quantumBytes(UNCAPPED_KBIT)}`
      )
      lines.push(
        `qdisc add dev ${dev} parent ${classId(slot)} handle ${netemHandle(slot)} netem limit 1000`
      )
    }
  }
  const built = await tcBatch(lines)
  if (/Error|Cannot/i.test(built.stderr)) {
    throw new Error(`Failed to build shaping tree: ${built.stderr}`)
  }
}

/** Build the whole apparatus: the IFB tree, then hooks on every present radio. */
export const buildBaseline = async (ifaces: string[]): Promise<void> => {
  for (const m of MODULES) await quiet('modprobe', [m])
  await teardownBaseline(ifaces)
  await buildIfbTree()
  for (const iface of presentIfaces(ifaces)) await attachHooks(iface)
}

export const teardownBaseline = async (ifaces: string[]): Promise<void> => {
  for (const iface of presentIfaces(ifaces)) {
    await quiet('tc', ['qdisc', 'del', 'dev', iface, 'clsact'])
  }
  await quiet('ip', ['link', 'del', DEV_DOWN])
  await quiet('ip', ['link', 'del', DEV_UP])
}

/** True when the IFB pair and its slot tree exist. */
export const ifbTreeIntact = async (): Promise<boolean> => {
  try {
    for (const dev of [DEV_DOWN, DEV_UP]) {
      const { stdout } = await execFileAsync('tc', ['qdisc', 'show', 'dev', dev])
      if (!stdout.includes('htb')) return false
    }
    return true
  } catch {
    return false
  }
}

/**
 * Present radios whose hooks are missing.
 *
 * Typically a radio that was just plugged back in: unplugging destroys the
 * netdev and its hooks with it, while the IFB tree - and every active shape -
 * survives untouched.
 */
export const unhookedIfaces = async (ifaces: string[]): Promise<string[]> => {
  const missing: string[] = []
  for (const iface of presentIfaces(ifaces)) {
    try {
      const { stdout: egress } = await execFileAsync('tc', ['filter', 'show', 'dev', iface, 'egress'])
      const { stdout: ingress } = await execFileAsync('tc', ['filter', 'show', 'dev', iface, 'ingress'])
      if (!egress.includes('matchall') || !ingress.includes('matchall')) missing.push(iface)
    } catch {
      missing.push(iface)
    }
  }
  return missing
}

export const baselineIntact = async (ifaces: string[]): Promise<boolean> =>
  (await ifbTreeIntact()) && (await unhookedIfaces(ifaces)).length === 0

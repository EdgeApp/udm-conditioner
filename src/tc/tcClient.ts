import { execFile } from 'child_process'
import { promisify } from 'util'

const execFileAsync = promisify(execFile)

export interface BatchResult {
  lines: string[]
  durationMs: number
  stderr: string
}

/**
 * Apply a batch of tc commands in a single tc invocation.
 *
 * `-force` keeps going past individual failures, which matters because
 * clearing a slot deletes filters that may already be gone.
 */
export const tcBatch = async (lines: string[]): Promise<BatchResult> => {
  if (lines.length === 0) return { lines, durationMs: 0, stderr: '' }
  const started = process.hrtime.bigint()
  let stderr = ''
  try {
    const child = execFileAsync('tc', ['-force', '-batch', '-'])
    child.child.stdin?.end(lines.join('\n') + '\n')
    const out = await child
    stderr = out.stderr
  } catch (err: any) {
    stderr = String(err?.stderr ?? err?.message ?? err)
  }
  const durationMs = Number(process.hrtime.bigint() - started) / 1e6
  return { lines, durationMs, stderr }
}

export const tc = async (args: string[]): Promise<string> => {
  const { stdout } = await execFileAsync('tc', args)
  return stdout
}

export const run = async (cmd: string, args: string[]): Promise<string> => {
  try {
    const { stdout } = await execFileAsync(cmd, args)
    return stdout
  } catch {
    return ''
  }
}

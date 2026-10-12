/**
 * The deterministic predicate: does this tool result carry a sandbox denial the
 * harness failed to classify?
 *
 * Every condition is checked against the **value the tool returned**, never
 * against the rendered text — the rendered text is the thing that is wrong, and
 * the whole point is to disagree with it on evidence rather than on prose.
 *
 * The order matters, and each step fails closed:
 *
 * 1. **The shape is a foreground shell result.** `exitCode`, `stdout.text`,
 *    `stderr.text` and a `sandbox` object. A background job or any other shape is
 *    left alone rather than guessed at.
 * 2. **The harness did not already classify it.** `sandbox.denied` must be
 *    exactly `false`. `true` means the harness saw a denial and said so; a value
 *    that is not a boolean at all means this is not the shape this plugin was
 *    written against — both are left alone.
 * 3. **The mode confines.** `danger-full-access` is the one mode that enforces
 *    nothing, so nothing under it can be a policy denial. The test is the
 *    negation of that single name, which is how the harness itself defines a
 *    confining mode (`ConfinedSandboxMode = Exclude<SandboxMode,
 *    'danger-full-access'>`), so a mode added later is treated as confining
 *    rather than silently dropping out of coverage.
 * 4. **The command failed.** A non-zero exit, as the harness's own matcher
 *    requires — a tool that swallowed the failure and exited 0 is not reporting
 *    a denial, whatever its output says.
 * 5. **It was not killed.** A timeout, an abort, or a signal means the exit
 *    status is ours, not the program's; text that happens to contain a dialect
 *    substring in that state is not evidence that a file effect was refused.
 * 6. **The signature is on stdout and not on stderr.** The first half is the
 *    defect; the second half is what keeps this plugin from second-guessing the
 *    harness — when the signature is on stderr, the harness's own classifier saw
 *    it, and its answer stands.
 *
 * @module @argszero/dsh-stdout-denial-guard/classify
 */

import { matchesSignature } from './signatures.ts'

/** The one mode that enforces nothing. */
const UNCONFINED_MODE = 'danger-full-access'

/** Why a result was left alone, or that it was classified. */
export type Reason =
  /** Not a foreground shell result, or a stream without text. */
  | 'not-shell-shape'
  /** `sandbox.denied` is true, or is not a boolean. */
  | 'denied-not-false'
  /** The call ran under `danger-full-access`, or without a usable mode. */
  | 'not-confined'
  /** Zero exit: the command did not report a failure. */
  | 'zero-exit'
  /** Timed out, aborted, or killed by a signal — the exit status is ours. */
  | 'killed'
  /** No dialect signature anywhere on stdout. */
  | 'no-stdout-signature'
  /** The harness's own stderr matcher already matches this result. */
  | 'stderr-signature'
  /** The denial the harness missed. */
  | 'classified'

/** The facts a classification is computed from. */
export interface ShellFacts {
  /** The stdout text, exactly as the tool reported it. */
  readonly stdout: string
  /** The stderr text, exactly as the tool reported it. */
  readonly stderr: string
  /** The command's exit status. */
  readonly exitCode: number
  /** The sandbox mode the call ran under. */
  readonly mode: string
}

/** One classification: the denial, its mode, and the substring that proved it. */
export interface Verdict {
  /** The confining mode the call ran under. */
  readonly mode: string
  /** The dialect substring that matched — the evidence, reported verbatim. */
  readonly signature: string
}

/** A classification attempt: the verdict, or why there is none. */
export interface Diagnosis {
  readonly reason: Reason
  readonly facts?: ShellFacts
  readonly verdict?: Verdict
}

/** A non-null, non-array object. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** The `text` of a stream-shaped object, or `undefined`. */
function streamText(value: unknown): string | undefined {
  if (!isRecord(value)) return undefined
  const text = value['text']
  return typeof text === 'string' ? text : undefined
}

/**
 * Read the shell facts out of a tool value, or `undefined` when the value is not
 * the shape this plugin recognizes.
 *
 * The narrowing is total: anything the plugin cannot prove about the value ends
 * the read rather than defaulting a field. A default here would be a fabricated
 * fact, and the response to a fabricated fact is a marker the model cannot trust.
 * @param value - the canonical tool value.
 * @returns the facts, or `undefined` when the shape does not match.
 */
export function readShellFacts(value: unknown): ShellFacts | undefined {
  if (!isRecord(value)) return undefined
  const exitCode = value['exitCode']
  if (typeof exitCode !== 'number' || !Number.isFinite(exitCode)) return undefined
  const sandbox = value['sandbox']
  if (!isRecord(sandbox)) return undefined
  const mode = sandbox['mode']
  if (typeof mode !== 'string' || mode === '') return undefined
  const stdout = streamText(value['stdout'])
  const stderr = streamText(value['stderr'])
  if (stdout === undefined || stderr === undefined) return undefined
  return { stdout, stderr, exitCode, mode }
}

/**
 * Diagnose one tool value.
 *
 * Returns the verdict **and** the facts it was computed from, or the single
 * reason no verdict exists. The reason is not decoration: it is what lets the
 * report tool answer "how much of this deployment did you actually look at, and
 * what did you decide about the rest", which is the difference between a guard
 * that is quiet because nothing happened and one that is quiet because it is not
 * running.
 * @param value - the canonical tool value.
 * @param signatures - the dialect substrings to match.
 * @returns the diagnosis.
 */
export function diagnose(value: unknown, signatures: readonly string[]): Diagnosis {
  const facts = readShellFacts(value)
  if (facts === undefined) return { reason: 'not-shell-shape' }

  const sandbox = (value as Record<string, unknown>)['sandbox'] as Record<string, unknown>
  if (sandbox['denied'] !== false) return { reason: 'denied-not-false', facts }
  if (facts.mode === UNCONFINED_MODE) return { reason: 'not-confined', facts }

  if (facts.exitCode <= 0) return { reason: 'zero-exit', facts }
  if ((value as Record<string, unknown>)['timedOut'] === true) return { reason: 'killed', facts }
  if ((value as Record<string, unknown>)['aborted'] === true) return { reason: 'killed', facts }
  if (typeof (value as Record<string, unknown>)['signal'] === 'string') return { reason: 'killed', facts }

  const signature = signatures.find(candidate => matchesSignature(facts.stdout, [candidate]))
  if (signature === undefined) return { reason: 'no-stdout-signature', facts }
  if (matchesSignature(facts.stderr, signatures)) return { reason: 'stderr-signature', facts }

  return { reason: 'classified', facts, verdict: { mode: facts.mode, signature } }
}

/**
 * The denial the harness missed, if this value carries one.
 * @param value - the canonical tool value.
 * @param signatures - the dialect substrings to match.
 * @returns the verdict, or `undefined`.
 */
export function classify(value: unknown, signatures: readonly string[]): Verdict | undefined {
  return diagnose(value, signatures).verdict
}

/**
 * Rebuild the value with `sandbox.denied` set, preserving every other field.
 *
 * The plugin never renders anything itself: the tool's own `output.render` is
 * what produces the model-facing marker, and `tools/post-execute` re-runs it for
 * a `value` replacement. So the only thing to do here is tell the truth about the
 * field the renderer reads.
 * @param value - the canonical tool value that was classified.
 * @param mode - the confining mode to record.
 * @returns a new value with the denial recorded.
 */
export function markDenied(value: unknown, mode: string): Record<string, unknown> {
  const source = value as Record<string, unknown>
  const sandbox = source['sandbox'] as Record<string, unknown>
  return { ...source, sandbox: { ...sandbox, mode, denied: true } }
}

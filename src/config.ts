/**
 * The plugin's configuration.
 *
 * Defaults are chosen so that mounting the plugin restores the behaviour the
 * harness already has when its classifier works, rather than inventing a new one:
 * `mark` re-classifies a denial the harness's stderr-only matcher could not see,
 * and lets the tool's own renderer print the marker the model was taught to read.
 *
 * @module @argszero/dsh-stdout-denial-guard/config
 */

import { DIALECT_NAMES, isDialect, signaturesFor } from './signatures.ts'
import type { Dialect } from './signatures.ts'

/** How the plugin responds to a denial it found on stdout. */
export type GuardMode = 'mark' | 'report' | 'off'

/** The plugin's user-facing configuration. Every field is optional. */
export interface Config {
  /** Response posture. Defaults to `mark`. */
  mode?: GuardMode
  /**
   * Runner dialects to match, by name. Defaults to every dialect, because the
   * runner is not on the result the plugin sees.
   */
  dialects?: readonly string[]
  /** Extra substrings to match, added to the dialect set. */
  signatures?: readonly string[]
  /**
   * Attach the same-turn escalation hint when the tool advertises escalation.
   * Defaults to `true`.
   */
  hint?: boolean
  /** Register the read-only report tool. Defaults to `true`. */
  report?: boolean
  /** How many classifications the in-memory report retains. Defaults to 50. */
  maxReported?: number
  /** Cap on the length of the injected notice. Defaults to 2000 characters. */
  noticeMaxChars?: number
}

/** The configuration with every default resolved. */
export interface Settings {
  readonly mode: GuardMode
  readonly dialects: readonly Dialect[]
  readonly signatures: readonly string[]
  readonly hint: boolean
  readonly report: boolean
  readonly maxReported: number
  readonly noticeMaxChars: number
}

/** What {@link normalizeConfig} produced, and what it had to reject to do so. */
export interface Normalized {
  readonly settings: Settings
  /** Dialect names the caller listed that this plugin does not know. */
  readonly rejectedDialects: readonly string[]
  /**
   * Whether every dialect name the caller listed was unknown, so the request
   * collapsed to nothing. **Not** set by an explicitly empty list: `dialects: []`
   * is how a deployment turns matching off without unmounting and is taken as
   * deliberate, while a list of typos reaches the same empty set by accident and
   * looks identical from the outside.
   */
  readonly emptyDialects: boolean
  /** Signature entries that are empty or whitespace, which match nothing. */
  readonly emptySignatures: readonly string[]
}

/**
 * The default configuration.
 *
 * Deliberately **not** exported as the plugin's `Config`: cordis validates a
 * mounted plugin's `Config` through `Config['~standard'].validate`, and a plain
 * defaults object has no `~standard`, so naming one makes the mount throw
 * `Cannot read properties of undefined (reading 'validate')` before `apply` runs.
 * The defaults reach a mount through `apply(ctx, config = {})` instead.
 */
export const defaultConfig: Config = {
  mode: 'mark',
  dialects: [...DIALECT_NAMES],
  signatures: [],
  hint: true,
  report: true,
  maxReported: 50,
  noticeMaxChars: 2000,
}

const MODES: readonly GuardMode[] = ['mark', 'report', 'off']

/** A positive integer, or the fallback. */
function positive(value: number | undefined, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback
}

/**
 * Resolve a user configuration into settings.
 *
 * Unknown dialect names are **reported and dropped**, never silently honoured: a
 * typo in this list is the difference between a plugin that recognises the
 * deployment's runner and one that recognises nothing — and the failure is
 * invisible, because a set that matches nothing also never produces a false
 * positive. Rejecting to an empty set is not an error (it is how a deployment
 * turns matching off without unmounting) but it is reported, so that a list of
 * typos cannot be mistaken for a deliberate choice.
 * @param config - the raw configuration.
 * @returns the settings and whatever had to be rejected.
 */
export function normalizeConfig(config: Config = {}): Normalized {
  const requested = config.dialects ?? [...DIALECT_NAMES]
  const dialects: Dialect[] = []
  const rejectedDialects: string[] = []
  for (const name of requested) {
    if (isDialect(name)) {
      if (!dialects.includes(name)) dialects.push(name)
    } else rejectedDialects.push(String(name))
  }

  const extra: string[] = []
  const emptySignatures: string[] = []
  for (const signature of config.signatures ?? []) {
    if (typeof signature === 'string' && signature.trim() !== '') {
      if (!extra.includes(signature)) extra.push(signature)
    } else emptySignatures.push(String(signature))
  }

  const mode = config.mode ?? defaultConfig.mode!
  return {
    settings: {
      mode: MODES.includes(mode) ? mode : defaultConfig.mode!,
      dialects,
      // The composed set: the selected dialects' own substrings first, then the
      // caller's extras. Composing here rather than in the listener is what keeps
      // one definition of "what this plugin matches" — `settings.signatures` is
      // the whole set, never a fragment of it. Deduplicated across the two halves,
      // not within each: a caller who restates a dialect's own wording means the
      // same thing as the dialect, and listing it twice would make a set that
      // reports its size as a count of distinct substrings into a set that does
      // not.
      signatures: [...new Set([...signaturesFor(dialects), ...extra])],
      hint: config.hint ?? true,
      report: config.report ?? true,
      maxReported: positive(config.maxReported, 50),
      noticeMaxChars: positive(config.noticeMaxChars, 2000),
    },
    rejectedDialects,
    emptyDialects: requested.length > 0 && dialects.length === 0,
    emptySignatures,
  }
}

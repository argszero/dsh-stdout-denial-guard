/**
 * The denial dialect each runner's kernel speaks — mirrored, because the
 * harness keeps the original to itself.
 *
 * `@deepseek-ai/dsh-sandbox-local` carries the table as a module-private `const`
 * (`packages/sandbox/sandbox-local/src/index.ts`):
 *
 * ```js
 * const DENIAL_SIGNATURES = {
 *   bwrap: ['read-only file system'],
 *   landlock: ['permission denied'],
 *   seatbelt: ['operation not permitted'],
 *   'windows-acl': ['access is denied', 'access to the path', 'permission denied', 'operation not permitted'],
 *   runnerCommand: ['read-only file system', 'permission denied'],
 * } as const satisfies Record<SelectedRunner['runner'] | 'runnerCommand', readonly string[]>
 * ```
 *
 * It is not exported — not from that module, and not from the package, whose
 * `exports` map publishes only `.` — so a consumer outside `dsh-sandbox-local`
 * has exactly two options: mirror the table, or invent a classification that
 * disagrees with the harness in cases the harness already handles. This mirrors
 * it.
 *
 * The mirror is the plugin's **calibration surface**, and the reason it is a
 * separate module with its own test rather than a literal inside the classifier:
 * a table that silently drifts from the one the harness enforces is a plugin that
 * classifies denials the harness does not, in a vocabulary the model was taught
 * to read. `test/signatures.spec.mjs` pins every entry.
 *
 * Each runner is carried because the harness picks the table by the runner it
 * selected at confine time, and this plugin sees only the result — the runner is
 * not on the value. So the default is the union of the runs' dialects, and
 * `config.dialects` narrows it for a deployment that knows its own runner.
 *
 * @module @argszero/dsh-stdout-denial-guard/signatures
 */

/** The runner dialects, keyed as the harness keys them. */
export const DIALECTS = {
  bwrap: ['read-only file system'],
  landlock: ['permission denied'],
  seatbelt: ['operation not permitted'],
  'windows-acl': [
    'access is denied',
    'access to the path',
    'permission denied',
    'operation not permitted',
  ],
} as const satisfies Record<string, readonly string[]>

/** The name of one runner dialect. */
export type Dialect = keyof typeof DIALECTS

/** Every dialect name, in the table's own order. */
export const DIALECT_NAMES = Object.keys(DIALECTS) as readonly Dialect[]

/**
 * Whether a name is a dialect this plugin knows.
 * @param value - the candidate name.
 * @returns `true` when the name addresses a table entry.
 */
export function isDialect(value: unknown): value is Dialect {
  return typeof value === 'string' && Object.hasOwn(DIALECTS, value)
}

/**
 * The default signature set: every runner dialect, unioned.
 *
 * Only the runner dialects — deliberately **not** the harness's `runnerCommand`
 * entry, which is its launcher-failure vocabulary rather than a denial dialect.
 * A launcher failure means the command did not run, and the harness already
 * ranks it above a denial and throws `SandboxUnavailableError`; treating its
 * wording as a file-effect denial here would invent a denial the runner never
 * reported.
 * @returns the supported substrings, in dialect order.
 */
export function defaultSignatures(): readonly string[] {
  const all: string[] = []
  for (const dialect of DIALECT_NAMES) {
    for (const signature of DIALECTS[dialect]) {
      if (!all.includes(signature)) all.push(signature)
    }
  }
  return all
}

/**
 * The signatures of the named dialects.
 * @param dialects - the dialects to union.
 * @returns the supported substrings, in dialect order.
 */
export function signaturesFor(dialects: readonly Dialect[]): readonly string[] {
  const all: string[] = []
  for (const dialect of dialects) {
    for (const signature of DIALECTS[dialect]) {
      if (!all.includes(signature)) all.push(signature)
    }
  }
  return all
}

/**
 * Whether a stream's text carries any signature.
 *
 * Case-insensitive, because the dialects are: the harness compares the same way,
 * and a kernel that capitalizes `Permission denied` is reporting the same event.
 * An empty signature is skipped rather than treated as a wildcard — a config
 * entry that is a typo must match nothing, not everything.
 * @param text - the stream text, as the tool reported it.
 * @param signatures - the substrings to look for.
 * @returns `true` when at least one non-empty signature occurs in the text.
 */
export function matchesSignature(text: string, signatures: readonly string[]): boolean {
  if (text === '') return false
  const lowered = text.toLowerCase()
  return signatures.some(signature => signature !== '' && lowered.includes(signature.toLowerCase()))
}

/**
 * Defect injection: mutate the source, rebuild, run the suite, and require that
 * the mutation is caught. An arm whose mutation leaves the suite green is
 * SILENT — it proves nothing about the suite, and this harness reports it as a
 * failure of itself rather than hiding it.
 *
 * The suite imports `lib/*.js`, not `src/*.ts`, so every arm **emits** first: a
 * mutation that is never compiled is a mutation the suite cannot see, and one
 * that does not compile is reported as TYPEFAIL, because it never reached the
 * suite either.
 *
 * Every arm is a defect this package could plausibly have shipped — one
 * distinction it exists to make, removed with one edit. The arms that matter
 * most are the ones where the guard would still *look* like it works:
 *
 * - the **stream** (`stdout` asked for `stderr`) — this is the upstream defect
 *   itself, reproduced inside the repair. The guard would classify nothing and
 *   report a clean deployment, which is exactly the failure it exists to fix.
 * - the **write back** — a guard that finds the denial and never records it
 *   passes every "was it seen" arm and repairs nothing.
 * - the **probe** — reading escalation off the parameter spec instead of the
 *   normalized `properties` makes the hint never attach, in a composition that
 *   advertises it. That was a real bug in this package during development.
 * - the **stand-downs** — overriding a block or a spill to add a marker is a far
 *   worse bug than a missed marker.
 * - the **denominator** — a report that cannot tell "nothing was missed" from
 *   "nothing ran" is the reason the counters exist.
 * - the **fail-open** — a guard whose bug breaks working tool calls is worse
 *   than the failure it prevents.
 *
 * ```sh
 * node scripts/inject-defects.mjs                 # every arm
 * node scripts/inject-defects.mjs --filter=stdout # a subset
 * ```
 *
 * @module scripts/inject-defects
 */

import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const TSC = resolve(ROOT, 'node_modules/typescript/bin/tsc')

/** Each arm names the one distinction it removes, and the file it lives in. */
const MUTATIONS = [
  {
    name: 'stream: the signature is looked for on stderr, which is the harness\'s own job',
    file: 'src/classify.ts',
    edits: [['  const signature = signatures.find(candidate => matchesSignature(facts.stdout, [candidate]))',
      '  const signature = signatures.find(candidate => matchesSignature(facts.stderr, [candidate]))']],
  },
  {
    name: 'stand-down: a signature the harness already matched on stderr is classified anyway',
    file: 'src/classify.ts',
    // `false as boolean`, not `false`: a literal `false` makes the branch
    // unreachable, and TypeScript types unreachable code by its *declared* type —
    // so the narrowing that `if (facts === undefined) return` performed is lost
    // and the arm fails to compile (`exactOptionalPropertyTypes`). An opaque
    // predicate keeps the branch reachable, which is what makes it a mutation of
    // the behaviour rather than of the type.
    edits: [['  if (matchesSignature(facts.stderr, signatures)) return { reason: \'stderr-signature\', facts }',
      '  if (matchesSignature(facts.stderr, signatures) && (false as boolean)) return { reason: \'stderr-signature\', facts }']],
  },
  {
    name: 'already handled: a denial the harness recorded is classified a second time',
    file: 'src/classify.ts',
    edits: [['  if (sandbox[\'denied\'] !== false) return { reason: \'denied-not-false\', facts }',
      '  if (sandbox[\'denied\'] === true) return { reason: \'denied-not-false\', facts }']],
  },
  {
    name: 'mode: nothing under danger-full-access can be a policy denial, but it is classified',
    file: 'src/classify.ts',
    edits: [['  if (facts.mode === UNCONFINED_MODE) return { reason: \'not-confined\', facts }',
      '  if (facts.mode === \'__never__\') return { reason: \'not-confined\', facts }']],
  },
  {
    name: 'exit: a command that swallowed its own failure is treated as denied',
    file: 'src/classify.ts',
    edits: [['  if (facts.exitCode <= 0) return { reason: \'zero-exit\', facts }',
      '  if (facts.exitCode < 0) return { reason: \'zero-exit\', facts }']],
  },
  {
    name: 'killed: a timed-out call\'s text is taken as evidence of a refusal',
    file: 'src/classify.ts',
    edits: [['  if ((value as Record<string, unknown>)[\'timedOut\'] === true) return { reason: \'killed\', facts }',
      '  if ((value as Record<string, unknown>)[\'timedOut\'] === false) return { reason: \'killed\', facts }']],
  },
  {
    name: 'shape: a stream that carries no text is read as an empty one',
    file: 'src/classify.ts',
    edits: [['  const stdout = streamText(value[\'stdout\'])\n  const stderr = streamText(value[\'stderr\'])\n  if (stdout === undefined || stderr === undefined) return undefined',
      '  const stdout = streamText(value[\'stdout\']) ?? \'\'\n  const stderr = streamText(value[\'stderr\']) ?? \'\'\n  if (false) return undefined']],
  },
  {
    name: 'write back: the denial is found and the field is left false',
    file: 'src/classify.ts',
    edits: [['  return { ...source, sandbox: { ...sandbox, mode, denied: true } }',
      '  return { ...source, sandbox: { ...sandbox, mode, denied: false } }']],
  },
  {
    name: 'write back: the registry\'s own value is mutated instead of copied',
    file: 'src/classify.ts',
    edits: [['  return { ...source, sandbox: { ...sandbox, mode, denied: true } }',
      '  ;(source[\'sandbox\'] as Record<string, unknown>)[\'denied\'] = true\n  return source']],
  },
  {
    name: 'table: an empty signature becomes a wildcard that matches everything',
    file: 'src/signatures.ts',
    edits: [['  return signatures.some(signature => signature !== \'\' && lowered.includes(signature.toLowerCase()))',
      '  return signatures.some(signature => lowered.includes(signature.toLowerCase()))']],
  },
  {
    name: 'table: a kernel that capitalizes its refusal is not recognised',
    file: 'src/signatures.ts',
    edits: [['  const lowered = text.toLowerCase()', '  const lowered = text']],
  },
  {
    name: 'table: a narrowed dialect set lists a shared substring twice',
    file: 'src/signatures.ts',
    edits: [['export function signaturesFor(dialects: readonly Dialect[]): readonly string[] {\n  const all: string[] = []\n  for (const dialect of dialects) {\n    for (const signature of DIALECTS[dialect]) {\n      if (!all.includes(signature)) all.push(signature)',
      'export function signaturesFor(dialects: readonly Dialect[]): readonly string[] {\n  const all: string[] = []\n  for (const dialect of dialects) {\n    for (const signature of DIALECTS[dialect]) {\n      all.push(signature)']],
  },
  {
    name: 'config: a caller\'s extra signature replaces the dialect set',
    file: 'src/config.ts',
    edits: [['      signatures: [...new Set([...signaturesFor(dialects), ...extra])],', '      signatures: [...extra],']],
  },
  {
    name: 'config: a dialect name this plugin does not know is matched anyway',
    file: 'src/config.ts',
    edits: [['    } else rejectedDialects.push(String(name))',
      '    } else if (!dialects.includes(name as Dialect)) dialects.push(name as Dialect)']],
  },
  {
    name: 'config: an unconfigured mount matches nothing',
    file: 'src/config.ts',
    edits: [['  const requested = config.dialects ?? [...DIALECT_NAMES]', '  const requested = config.dialects ?? []']],
  },
  {
    name: 'config: a mode this plugin does not implement is taken as configured',
    file: 'src/config.ts',
    edits: [['      mode: MODES.includes(mode) ? mode : defaultConfig.mode!,', '      mode,']],
  },
  {
    name: 'config: a bound is honoured without being a positive integer',
    file: 'src/config.ts',
    edits: [['  return typeof value === \'number\' && Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback',
      '  return typeof value === \'number\' ? value : fallback']],
  },
  {
    name: 'config: a deliberately empty dialect list is reported as a list of typos',
    file: 'src/config.ts',
    edits: [['    emptyDialects: requested.length > 0 && dialects.length === 0,', '    emptyDialects: dialects.length === 0,']],
  },
  {
    name: 'config: an empty signature entry is accepted instead of dropped',
    file: 'src/config.ts',
    edits: [['    if (typeof signature === \'string\' && signature.trim() !== \'\') {', '    if (typeof signature === \'string\') {']],
  },
  {
    name: 'probe: escalation is read off the parameter spec instead of the normalized schema',
    file: 'src/index.ts',
    edits: [['    const properties = (definition.parameters as Record<string, unknown> | undefined)?.[\'properties\']',
      '    const properties = definition.parameters as unknown as Record<string, unknown>']],
  },
  {
    name: 'probe: the escalation hint is attached even when the configuration turns it off',
    file: 'src/index.ts',
    edits: [['  const hint = settings.hint && escalationAvailable(ctx, exec.name)', '  const hint = escalationAvailable(ctx, exec.name)']],
  },
  {
    name: 'stand-down: a call another listener blocked is un-blocked to carry a marker',
    file: 'src/index.ts',
    // The mutation has to keep returning on the non-accept path: that early
    // return is also what narrows `inner` to the `accept` variant for the
    // `inner.content` read below it, so a predicate-shaped mutation is a type
    // error rather than a behaviour change. Replacing the *decision* keeps the
    // narrowing and is the defect itself.
    edits: [['  if (inner.kind !== \'accept\') return pass()',
      '  if (inner.kind !== \'accept\') return { decision: { kind: \'accept\', value: markDenied(result.value, \'workspace-write\') as never } }']],
  },
  {
    name: 'stand-down: a result another listener replaced the content of is overwritten',
    file: 'src/index.ts',
    edits: [['  if (Object.hasOwn(inner, \'content\') && inner.content !== undefined) {', '  if (false) {']],
  },
  {
    name: 'mode: report rewrites the result it exists to measure',
    file: 'src/index.ts',
    edits: [['  if (settings.mode === \'report\') {', '  if (String(settings.mode) === \'_report\') {']],
  },
  {
    name: 'mode: off mounts the listener anyway',
    file: 'src/index.ts',
    edits: [['  const active = settings.mode !== \'off\'', '  const active = true']],
  },
  {
    name: 'mode: the report tool is missing in exactly the posture it exists to explain',
    file: 'src/index.ts',
    edits: [['    const tool = settings.report ? ctx.tools.register(reportTool(ledger, settings)) : undefined',
      '    const tool = settings.report && active ? ctx.tools.register(reportTool(ledger, settings)) : undefined']],
  },
  {
    name: 'report tool: the report is registered even when the report is switched off',
    file: 'src/index.ts',
    edits: [['    const tool = settings.report ? ctx.tools.register(reportTool(ledger, settings)) : undefined',
      '    const tool = ctx.tools.register(reportTool(ledger, settings))']],
  },
  {
    name: 'report tool: clearing is asked for and not done',
    file: 'src/index.ts',
    edits: [['      if (clear) ledger.clear()', '      if (false) ledger.clear()']],
  },
  {
    name: 'fail-open: a failure while classifying is thrown at the caller',
    file: 'src/index.ts',
    edits: [['          ctx.logger.warn(`stdout-denial-guard: failed while classifying a result, leaving it untouched: ${String(error)}`)\n          return inner',
      '          throw error']],
  },
  {
    name: 'fail-open: a failure while classifying is swallowed quietly',
    file: 'src/index.ts',
    edits: [['          ctx.logger.warn(`stdout-denial-guard: failed while classifying a result, leaving it untouched: ${String(error)}`)',
      '          void error']],
  },
  {
    name: 'ledger: no inspection is counted',
    file: 'src/index.ts',
    edits: [['  ledger.inspect(inspection.reason)', '  ledger.inspect(inspection.reason)\n  ledger.inspect(inspection.reason === \'classified\' ? \'zero-exit\' : \'zero-exit\')']],
  },
  {
    name: 'ledger: an inspection is not counted at all',
    file: 'src/ledger.ts',
    edits: [['      inspected += 1', '      inspected += 0']],
  },
  {
    name: 'ledger: a classification is not counted',
    file: 'src/ledger.ts',
    edits: [['      if (reason === \'classified\') classified += 1', '      if (reason === \'classified\') classified += 0']],
  },
  {
    name: 'ledger: the retained window is unbounded',
    file: 'src/ledger.ts',
    edits: [['      if (events.length > maxReported) events.length = maxReported',
      '      if (events.length > 10_000_000) events.length = maxReported']],
  },
  {
    name: 'ledger: the retained list keeps the oldest events instead of the newest',
    file: 'src/ledger.ts',
    edits: [['      events.unshift(event)', '      events.push(event)']],
  },
  {
    name: 'ledger: a dropped event is not reported',
    file: 'src/ledger.ts',
    edits: [['        truncated: total > events.length,', '        truncated: false,']],
  },
  {
    name: 'ledger: clearing forgets the counts but keeps the events',
    file: 'src/ledger.ts',
    edits: [['      for (const reason of REASONS) reasons[reason] = 0\n      events.length = 0',
      '      for (const reason of REASONS) reasons[reason] = 0']],
  },
  {
    name: 'ledger: a snapshot aliases the live state',
    file: 'src/ledger.ts',
    edits: [['        reasons: { ...reasons },\n        events: [...events],', '        reasons,\n        events,']],
  },
  {
    name: 'report: the denominator is the classification count',
    file: 'src/advice.ts',
    edits: [['  lines.push(`tool results inspected: ${snapshot.inspected}`)',
      '  lines.push(`tool results inspected: ${snapshot.classified}`)']],
  },
  {
    name: 'report: a reason is rendered with no label',
    file: 'src/advice.ts',
    edits: [['  killed: \'timed out, was aborted, or was killed by a signal\',', '  killed: \'\',']],
  },
  {
    name: 'clamp: an over-long notice is truncated without saying so',
    file: 'src/advice.ts',
    edits: [['  return text.length <= max ? text : `${text.slice(0, Math.max(0, max - 1))}…`', '  return text.slice(0, max)']],
  },
]

const argv = process.argv.slice(2)
const filter = argv.find(argument => argument.startsWith('--filter='))?.slice('--filter='.length)

/**
 * Run one command, capturing whether it succeeded.
 *
 * The timeout is not decoration: an arm can leave the suite waiting on
 * something, and a mutant that never terminates is a mutant the suite cannot
 * report on. It is killed here and counted as caught, which is what it is — the
 * suite never reaches its assertions because the code under test never returns.
 */
function run(command, args) {
  try {
    execFileSync(command, args, { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'], timeout: 300_000 })
    return { ok: true, output: '' }
  } catch (error) {
    return { ok: false, output: `${error.stdout ?? ''}${error.stderr ?? ''}` }
  }
}

/** Emit the compiled artifact the suite actually imports. */
function build() {
  return run(process.execPath, [TSC])
}

/** Run every spec in the suite. */
function test() {
  return run(process.execPath, ['--test', 'test/*.spec.mjs'])
}

const results = []
for (const mutation of MUTATIONS) {
  if (filter !== undefined && !mutation.name.includes(filter)) continue
  // A malformed arm is worse than a missing one: `for (const [from, to] of
  // 'ab')` destructures a *string* into its characters, so the edit becomes a
  // search for two single characters and a rewrite that changes nothing — and
  // the arm then reports SILENT, blaming the suite for a harness bug. Measured
  // in this family: one flat `edits: ['…', '…']` reported "the suite stayed
  // green" while the real mutation was never applied.
  const malformed = mutation.edits.some(edit =>
    !Array.isArray(edit) || edit.length !== 2 || edit.some(part => typeof part !== 'string'))
  if (malformed) {
    results.push({ name: mutation.name, outcome: 'MALFORMED', detail: 'an edit is not a [from, to] pair of strings' })
    continue
  }
  const path = resolve(ROOT, mutation.file)
  const original = readFileSync(path, 'utf8')
  let mutated = original
  let applied = true
  for (const [from, to] of mutation.edits) {
    if (!mutated.includes(from)) {
      applied = false
      break
    }
    mutated = mutated.replace(from, to)
  }
  if (!applied) {
    results.push({ name: mutation.name, outcome: 'NO-OP', detail: 'the source no longer contains the text this arm mutates' })
    continue
  }
  try {
    writeFileSync(path, mutated)
    const built = build()
    if (!built.ok) {
      results.push({ name: mutation.name, outcome: 'TYPEFAIL', detail: 'the mutation does not compile, so the suite never ran' })
      continue
    }
    const tested = test()
    results.push(tested.ok
      ? { name: mutation.name, outcome: 'SILENT', detail: 'the suite stayed green — this arm proves nothing' }
      : { name: mutation.name, outcome: 'CAUGHT', detail: '' })
  } finally {
    writeFileSync(path, original)
  }
}

// Put `lib/` back. The last arm left its mutation COMPILED there — the source is
// restored in the `finally` above, but the build output is not, and a checkout
// that runs this script and then publishes would ship the last mutant. Rebuilt
// once here so the tree is consistent whether a human runs this or CI does.
const restored = build()
if (!restored.ok) {
  process.stdout.write('\nWARNING: the rebuild after restoring the sources failed — lib/ may hold a mutant\n')
}

const caught = results.filter(result => result.outcome === 'CAUGHT').length
const declared = new Set(MUTATIONS.filter(mutation => mutation.equivalent !== undefined).map(mutation => mutation.name))
const equivalents = results.filter(result => result.outcome === 'SILENT' && declared.has(result.name))
const silent = results.filter(result => result.outcome === 'SILENT' && !declared.has(result.name))
const other = results.filter(result => result.outcome !== 'CAUGHT' && result.outcome !== 'SILENT')

for (const result of results) {
  const label = result.outcome === 'SILENT' && declared.has(result.name) ? 'EQUIVALENT' : result.outcome
  process.stdout.write(`${label.padEnd(10)} ${result.name}${result.detail === '' ? '' : `\n           ${result.detail}`}\n`)
}
process.stdout.write(`\n${caught}/${results.length} caught`)
process.stdout.write(silent.length === 0
  ? ` — no arm is silent (${equivalents.length} declared equivalent — see the arms)\n`
  : `, ${silent.length} SILENT\n`)
if (other.length > 0) {
  process.stdout.write(`${other.length} arm(s) could not be evaluated: ${other.map(result => `${result.outcome} ${result.name}`).join(', ')}\n`)
}
process.exitCode = silent.length === 0 && other.length === 0 ? 0 : 1

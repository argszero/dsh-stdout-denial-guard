/**
 * A sandbox denial reported on stdout is never classified, so the model is never
 * told it was denied.
 *
 * ## The defect
 *
 * The harness classifies a denied file effect by matching the runner's dialect
 * against **stderr**, and only when the command exited non-zero:
 *
 * ```js
 * // packages/sandbox/sandbox/src/diagnostics.ts
 * function matchesSignature(exitCode: number | null, stderr: string, signatures: readonly string[]): boolean
 *
 * // packages/shell/bash-sandbox/src/helpers.ts
 * export function classifyDenial(result: ShellRunResult, signatures: readonly string[]): boolean {
 *   return matchesSignature(result.exitCode, result.stderr.text, signatures)
 * }
 * ```
 *
 * The verdict lands on the result as `sandbox.denied`, and everything the model
 * is told about a denial is gated on that one boolean — `packages/shell/tool-bash/
 * src/render.ts` prints `sandboxDenialMarker(mode)` when it is set, and the
 * same-turn escalation hint beside it:
 *
 * ```js
 * if (result.sandbox?.denied) {
 *   markers.push(sandboxDenialMarker(result.sandbox.mode))
 *   if (escalationModes.length > 0) markers.push(escalationHintMarker('command'))
 * }
 * ```
 *
 * So a program that reports the failing path on **stdout** — a Node tool printing
 * `EACCES: permission denied, mkdir '/data/config/astro'`, or any command that
 * merged the streams with `2>&1`, which agents do constantly — produces a
 * non-zero exit whose stderr carries nothing the matcher knows. The denial is
 * real, the field says `false`, and the result reads as an ordinary command
 * failure. The model, told nothing, works around the sandbox instead of asking
 * for the access it was refused.
 *
 * ## The seam
 *
 * `tools/post-execute` is a cordis waterfall whose `accept` decision may replace a
 * successful result's **value**, and `packages/core/tools/src/index.ts` re-runs the
 * tool's own output contract over the replacement:
 *
 * ```js
 * const replaced = this.createSuccessResult(exec, tool, decision.value)   // → tool.output.render(...)
 * ```
 *
 * That is the whole repair. This plugin does not print a marker; it sets the field
 * the renderer already reads and lets `tool-bash` print `[sandbox: file access
 * denied under <mode> mode]` in the canonical position, ahead of the exit marker
 * that `parseExitStatus` anchors on. What it *cannot* reach that way is the
 * escalation hint, which is gated on an `escalationModes` argument captured in the
 * tool's own closure — so that one line travels as `additionalContexts`, the
 * decision's public channel for context the renderer cannot produce.
 *
 * Whether escalation is advertised is not guessed: the tool's schema carries
 * `sandbox_permissions` **only** when the composition exposes escalation, so the
 * plugin reads that parameter off the registered definition and attaches the hint
 * exactly when the harness would have.
 *
 * ## What this plugin cannot do
 *
 * - It cannot fix the classifier. Reading stdout in `matchesSignature` is the
 *   upstream change, and it is the right one; this closes the model's side of the
 *   defect, for as long as it is mounted.
 * - It stands down whenever another `tools/post-execute` listener already replaced
 *   the result's `content` (a decision cannot carry both `value` and `content`),
 *   and whenever an inner listener blocked the call. A spilled or blocked result
 *   keeps the harness's own (unclassified) rendering.
 * - It classifies by dialect substring, as the harness does, so it inherits the
 *   same limit: a runner whose dialect is not in the table is not recognised.
 * - It requires a confining mode and a non-zero exit, so a command that swallowed
 *   its own failure and exited 0 stays unclassified.
 *
 * @module @argszero/dsh-stdout-denial-guard
 */

import type { Context } from '@deepseek-ai/cordis'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { PostToolDecision, ToolExecution, ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import { diagnose, markDenied } from './classify.ts'
import type { Reason, Verdict } from './classify.ts'
import { defaultConfig, normalizeConfig } from './config.ts'
import type { Config, Settings } from './config.ts'
import { createLedger } from './ledger.ts'
import type { Ledger, MarkEvent } from './ledger.ts'
import { noticeText, renderReport } from './advice.ts'

declare module '@deepseek-ai/dsh-llm' {
  interface MessageSourceMap {
    'stdout-denial-guard': { kind: 'stdout-denial-guard' }
  }
}

/** Cordis plugin name used by loader diagnostics. */
export const name = 'stdout-denial-guard'

/** The registry this plugin reads definitions from. */
export const inject = ['tools']

/** The tool name the report is read with. */
export const REPORT_TOOL = 'stdout_denial_report'

/** The parameter a tool carries only when the composition exposes escalation. */
export const ESCALATION_PARAMETER = 'sandbox_permissions'

export { DIALECTS, DIALECT_NAMES, defaultSignatures, isDialect, matchesSignature, signaturesFor } from './signatures.ts'
export type { Dialect } from './signatures.ts'
export { classify, diagnose, markDenied, readShellFacts } from './classify.ts'
export type { Diagnosis, Reason, ShellFacts, Verdict } from './classify.ts'
export { defaultConfig, normalizeConfig } from './config.ts'
export type { Config, GuardMode, Normalized, Settings } from './config.ts'
export { createLedger } from './ledger.ts'
export type { Ledger, LedgerSnapshot, MarkEvent } from './ledger.ts'
export { noticeText, renderReport } from './advice.ts'

/**
 * Whether the tool that ran advertises escalation.
 *
 * The schema is the contract, and the harness writes it from the same value it
 * gates the hint on: `tool-bash` spreads `sandbox_permissions` and `justification`
 * into its parameter spec only when its `escalationModes` is non-empty, so the
 * property's presence *is* "escalation is available in this composition".
 *
 * The property is read from `parameters.properties`, which is the normalized
 * shape `defineTool` stores — it runs the tool's parameter spec through
 * `parameterSchemaSpecToJsonSchema` before the definition is registered, so the
 * spec a tool author writes (inline `required: true` per property) is not the
 * object a reader gets back. Verified against the published 0.1.7 line, where the
 * registered value is `{ type, properties, required }`.
 *
 * A tool whose definition cannot be resolved answers `false`: the hint tells the
 * model to retry with a parameter, and a parameter that may not exist is worse
 * than no hint.
 * @param ctx - the plugin context.
 * @param toolName - the tool that produced the result.
 * @returns `true` when the escalation parameters are advertised.
 */
export function escalationAvailable(ctx: Context, toolName: string): boolean {
  try {
    const definition = ctx.tools.get(toolName)
    if (definition === undefined) return false
    const properties = (definition.parameters as Record<string, unknown> | undefined)?.['properties']
    return typeof properties === 'object' && properties !== null
      && (properties as Record<string, unknown>)[ESCALATION_PARAMETER] !== undefined
  } catch {
    return false
  }
}

/**
 * The read-only report tool.
 *
 * It is what makes the guard's posture checkable without reproducing an incident:
 * `inspected` against `classified` says the guard ran, the reason counters say how
 * much of what it saw it actually decided about, and the retained events name the
 * calls. Reads a counter and changes nothing.
 * @param ledger - the plugin's ledger.
 * @param settings - the resolved configuration.
 * @returns the tool definition.
 */
function reportTool(ledger: Ledger, settings: Settings) {
  return defineTool({
    name: REPORT_TOOL,
    description: 'Report how many sandbox denials @argszero/dsh-stdout-denial-guard found on stdout — the denials '
      + 'the harness\'s stderr-only classifier missed — together with how many tool results it inspected, why the '
      + 'other inspections ended, and which calls were affected. Reads a counter and changes nothing.',
    parameters: {
      clear: { type: 'boolean', description: 'Clear the counters and the retained events after reporting them.' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args) {
      const snapshot = ledger.snapshot()
      const clear = (args as { clear?: unknown }).clear === true
      const note = clear
        ? `Counters cleared at ${new Date().toISOString()}; the report below is the state before that.`
        : undefined
      const text = renderReport(snapshot, note)
      if (clear) ledger.clear()
      return `${settings.mode === 'off' ? 'The guard is not mounted (mode: off).\n\n' : ''}${text}`
    },
  })
}

/** What the listener decided about one settled result. */
interface Outcome {
  readonly decision: PostToolDecision
  /** What to log, or `undefined` when there is nothing to say. */
  readonly log?: string
}

/**
 * The `tools/post-execute` frame.
 *
 * The frame is the outermost one (`prepend`), so its `next()` settles only after
 * every inner listener has spoken and the decision it returns is the one the
 * registry applies. Two of those inner outcomes are honoured rather than
 * overridden:
 *
 * - a non-`accept` decision (a block) is passed through untouched, because
 *   un-blocking a call to add a marker would be a far worse bug than a missed
 *   marker;
 * - an `accept` that already carries `content` is passed through, because a
 *   decision cannot carry both `value` and `content`, and the listener that
 *   replaced the content — a spill, typically — did so to keep the model from
 *   reading this result verbatim.
 *
 * The inner decision's `additionalContexts` are always preserved; a replacement
 * decision the plugin returns has to carry them itself, since it is a new object.
 * @param ctx - the plugin context.
 * @param ledger - the plugin's ledger.
 * @param settings - the resolved configuration.
 * @param exec - the settled call.
 * @param result - the result the registry normalized.
 * @param inner - the decision the downstream listeners settled on.
 * @returns the decision this frame passes on.
 */
function respond(
  ctx: Context,
  ledger: Ledger,
  settings: Settings,
  exec: ToolExecution,
  result: ToolExecutionResult,
  inner: PostToolDecision,
): Outcome {
  const inspection = diagnose(result.isError ? undefined : result.value, settings.signatures)
  ledger.inspect(inspection.reason)

  const pass = (log?: string): Outcome => log === undefined ? { decision: inner } : { decision: inner, log }
  if (inspection.verdict === undefined) return pass()
  if (inner.kind !== 'accept') return pass()
  if (Object.hasOwn(inner, 'content') && inner.content !== undefined) {
    return pass(`stdout-denial-guard: noticed a denial on stdout in ${exec.name} (${exec.callId}) but another `
      + 'post-execute listener replaced this result\'s content; leaving that rendering alone')
  }

  const verdict: Verdict = inspection.verdict
  const hint = settings.hint && escalationAvailable(ctx, exec.name)
  const event: MarkEvent = {
    callId: String(exec.callId),
    tool: exec.name,
    mode: verdict.mode,
    signature: verdict.signature,
    response: settings.mode === 'mark' ? 'marked' : 'reported',
    hinted: hint,
    at: new Date().toISOString(),
  }
  ledger.record(event)

  if (settings.mode === 'report') {
    return pass(`stdout-denial-guard (report): ${exec.name} (${exec.callId}) was denied under ${verdict.mode} and the `
      + `harness did not classify it — stdout matched "${verdict.signature}" (change nothing; mode is "report")`)
  }

  const contexts = [...(inner.additionalContexts ?? [])]
  if (hint) {
    contexts.push(createUserMessage({
      content: [{ type: 'text', text: noticeText(settings.noticeMaxChars) }],
      source: { kind: 'stdout-denial-guard' },
    }))
  }
  return {
    decision: {
      kind: 'accept',
      value: markDenied(result.value, verdict.mode) as never,
      ...contexts.length > 0 ? { additionalContexts: contexts } : {},
    },
    log: `stdout-denial-guard: ${exec.name} (${exec.callId}) was denied under ${verdict.mode}; stdout matched `
      + `"${verdict.signature}" and the harness's stderr-only classifier missed it — `
      + `${hint ? 'marker + escalation hint' : 'marker only (no escalation in this composition)'}`,
  }
}

/**
 * Mount the guard.
 *
 * `config` is whatever a loader entry passed, or `undefined` when it passed
 * nothing, so the default lives here. It cannot live in an exported `Config`:
 * cordis reads `Config['~standard'].validate` off a plugin's `Config`, and a plain
 * defaults object has no such property, so naming one there makes the mount throw
 * before this function is called.
 * @param ctx - the plugin context.
 * @param config - the plugin configuration.
 */
export function apply(ctx: Context, config: Config = {}): void {
  const normalized = normalizeConfig(config)
  const settings = normalized.settings
  if (normalized.rejectedDialects.length > 0) {
    ctx.logger.warn(`stdout-denial-guard: ignoring unknown dialect name(s) `
      + `${normalized.rejectedDialects.join(', ')}; matching ${settings.dialects.join(', ') || 'nothing'}`)
  }
  if (normalized.emptySignatures.length > 0) {
    ctx.logger.warn(`stdout-denial-guard: ignoring empty signature entr${normalized.emptySignatures.length === 1 ? 'y' : 'ies'} `
      + `(${normalized.emptySignatures.length}); an empty substring is not a wildcard`)
  }
  if (normalized.emptyDialects) {
    ctx.logger.warn('stdout-denial-guard: the dialect list is empty — the guard is mounted but matches nothing')
  }
  if (settings.mode === 'off') {
    ctx.logger.warn('stdout-denial-guard: mode "off" — no listener is mounted; the report tool still answers, and says so')
  }

  const ledger = createLedger(settings.maxReported)
  const active = settings.mode !== 'off'

  ctx.effect(() => {
    const off = active
      ? ctx.on('tools/post-execute', async (exec, result, next): Promise<PostToolDecision> => {
        // `next()` is never wrapped: a downstream listener's throw is the
        // registry's to handle, and swallowing it would change what the model
        // sees. Only this plugin's own work is guarded, and it fails open — a
        // guard whose bug breaks working calls is worse than the failure it
        // prevents.
        const inner = await next()
        try {
          const outcome = respond(ctx, ledger, settings, exec, result, inner)
          if (outcome.log !== undefined) ctx.logger.warn(outcome.log)
          return outcome.decision
        } catch (error: unknown) {
          ctx.logger.warn(`stdout-denial-guard: failed while classifying a result, leaving it untouched: ${String(error)}`)
          return inner
        }
      }, { prepend: true })
      : () => {}

    const tool = settings.report ? ctx.tools.register(reportTool(ledger, settings)) : undefined
    return () => {
      off()
      tool?.()
    }
  }, `stdout-denial-guard: classify sandbox denials the stderr-only matcher misses (mode: ${settings.mode})`)
}

/**
 * The object a loader entry mounts: `vendor/loader` normalises a plugin module
 * with `exports.default ?? exports` and hands this to `ctx.plugin`, which reads
 * `Config['~standard'].validate` off it when it is present.
 *
 * No `Config` is exported on purpose. A plain defaults object in that position is
 * how a published plugin ends up mounting as `TypeError: Cannot read properties of
 * undefined (reading 'validate')`; the defaults reach a mount through
 * `apply(ctx, config = {})` instead.
 */
export default { name, inject, apply }

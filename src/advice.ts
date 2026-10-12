/**
 * The two texts the guard produces: what the model is told, and what the operator
 * can read back.
 *
 * The model-facing half is deliberately one line. The marker itself is **not**
 * reproduced here — the tool's own renderer prints it from the value this plugin
 * rewrote, in the canonical position, so the result the model reads is the one the
 * harness would have produced had its own classifier seen the denial. The only
 * thing left to supply is the escalation hint, which the renderer cannot produce
 * on its own because it depends on a render-time argument the plugin cannot reach.
 * Supplying exactly that — and nothing else — is what makes the claim in the
 * README checkable: mount this plugin and the outcome is the harness's own, not a
 * second dialect the model has to learn.
 *
 * @module @argszero/dsh-stdout-denial-guard/advice
 */

import { escalationHintMarker } from '@deepseek-ai/dsh-sandbox'
import type { LedgerSnapshot, MarkEvent } from './ledger.ts'
import type { Reason } from './classify.ts'

/** How one reason reads in the report. */
const REASON_LABELS: Readonly<Record<Reason, string>> = {
  'not-shell-shape': 'not a foreground shell result',
  'denied-not-false': 'the harness already recorded a denial, or the flag was not a boolean',
  'not-confined': 'ran under danger-full-access, or carried no usable mode',
  'zero-exit': 'exited 0, so the command did not report a failure',
  killed: 'timed out, was aborted, or was killed by a signal',
  'no-stdout-signature': 'no dialect signature on stdout',
  'stderr-signature': 'the harness\'s own stderr matcher matched it',
  classified: 'classified as a missed denial',
}

/** Bound one line of text. */
function clip(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, Math.max(0, max - 1))}…`
}

/**
 * The model-facing notice that accompanies a marked result.
 *
 * One sentence of referent plus the harness's own hint line, verbatim. The hint
 * is imported rather than typed out: it is the harness's vocabulary for a
 * sanctioned retry, and a plugin that paraphrases it is teaching the model a
 * second phrasing for one concept.
 * @param maxChars - cap on the notice's length.
 * @returns the notice text.
 */
export function noticeText(maxChars: number): string {
  return clip(`The sandbox denied the command above. ${escalationHintMarker('command')}`, maxChars)
}

/**
 * The read-only report.
 * @param snapshot - the ledger's state.
 * @param note - an optional sentence placed above the report.
 * @returns the report text.
 */
export function renderReport(snapshot: LedgerSnapshot, note?: string): string {
  const lines: string[] = []
  if (note !== undefined) lines.push(note, '')
  lines.push('# stdout-denial-guard report', '')
  lines.push(`tool results inspected: ${snapshot.inspected}`)
  lines.push(`denials the harness missed: ${snapshot.classified}`)
  lines.push(`  rewritten (posture "mark"): ${snapshot.marked}`)
  lines.push(`  counted only (posture "report"): ${snapshot.reported}`)
  lines.push(`  carrying the escalation hint: ${snapshot.hinted}`)
  lines.push('')
  lines.push('## why the other inspections ended')
  for (const [reason, count] of Object.entries(snapshot.reasons)) {
    lines.push(`${count}\t${REASON_LABELS[reason as Reason]}`)
  }
  lines.push('')
  lines.push(`## the ${snapshot.events.length} most recent classification${snapshot.events.length === 1 ? '' : 's'}`)
  if (snapshot.events.length === 0) {
    lines.push('(none — either nothing was missed, or this guard has not seen a shell result yet;')
    lines.push(' the counters above are what tells those apart)')
  } else {
    for (const event of snapshot.events) lines.push(eventLine(event))
    if (snapshot.truncated) lines.push('(older classifications were dropped from this list; the counters keep the total)')
  }
  return lines.join('\n')
}

/** One retained event as a line. */
function eventLine(event: MarkEvent): string {
  const hint = event.hinted ? ' +hint' : ''
  return `- ${event.at} ${event.callId} ${event.tool} [${event.response}${hint}] mode=${event.mode} matched "${event.signature}"`
}

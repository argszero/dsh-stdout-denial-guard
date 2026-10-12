/**
 * What the guard saw and what it did about it.
 *
 * A guard whose only output is a repaired result is a guard nobody can audit: the
 * repaired result looks like a result the harness produced correctly, so "the
 * deployment has nothing to fix" and "the guard never ran" are indistinguishable
 * from the model's side. The ledger keeps the counters that tell those apart —
 * including the denominators, and including the reasons results were left alone.
 *
 * @module @argszero/dsh-stdout-denial-guard/ledger
 */

import type { Reason } from './classify.ts'

/** One classified denial, as the report shows it. */
export interface MarkEvent {
  /** The tool call's id, so the event can be found in the session log. */
  readonly callId: string
  /** The tool that produced the value. */
  readonly tool: string
  /** The confining mode the call ran under. */
  readonly mode: string
  /** The dialect substring that matched. */
  readonly signature: string
  /** What the guard did: `marked` rewrote the value, `reported` changed nothing. */
  readonly response: 'marked' | 'reported'
  /** Whether the escalation hint accompanied it. */
  readonly hinted: boolean
  /** When it happened. */
  readonly at: string
}

/** The counters and the retained events. */
export interface LedgerSnapshot {
  /** How many tool results the guard looked at. */
  readonly inspected: number
  /** How many carried a denial the harness missed. */
  readonly classified: number
  /** How many it rewrote (posture `mark`). */
  readonly marked: number
  /** How many it only counted (posture `report`). */
  readonly reported: number
  /** How many carried the escalation hint. */
  readonly hinted: number
  /** How many inspections ended for each reason. */
  readonly reasons: Readonly<Record<Reason, number>>
  /** The retained events, most recent first. */
  readonly events: readonly MarkEvent[]
  /** Whether the retained list is dropping events. */
  readonly truncated: boolean
}

/** The ledger's write and read surface. */
export interface Ledger {
  /** Count one inspection that ended for `reason`. */
  inspect(reason: Reason): void
  /** Record one classification and its response. */
  record(event: MarkEvent): void
  /** Read the counters and the retained events. */
  snapshot(): LedgerSnapshot
  /** Reset the counters and drop the retained events. */
  clear(): void
}

/** Every reason, so the counters always have the same shape. */
const REASONS: readonly Reason[] = [
  'not-shell-shape',
  'denied-not-false',
  'not-confined',
  'zero-exit',
  'killed',
  'no-stdout-signature',
  'stderr-signature',
  'classified',
]

/** A fresh reason counter. */
function zeroReasons(): Record<Reason, number> {
  const counts = {} as Record<Reason, number>
  for (const reason of REASONS) counts[reason] = 0
  return counts
}

/**
 * Create the ledger.
 *
 * The retained list is bounded because a plugin's memory is not a log: the count
 * is the durable answer, and the events are there to name a caller's incident
 * while it is recent. The bound is reported (`truncated`) so a reader is never
 * told "these are all of them" when it is not.
 * @param maxReported - how many events to retain.
 * @returns the ledger.
 */
export function createLedger(maxReported: number): Ledger {
  let inspected = 0
  let classified = 0
  let marked = 0
  let reported = 0
  let hinted = 0
  let total = 0
  const reasons = zeroReasons()
  const events: MarkEvent[] = []

  return {
    inspect(reason) {
      inspected += 1
      reasons[reason] += 1
      if (reason === 'classified') classified += 1
    },
    record(event) {
      total += 1
      if (event.response === 'marked') marked += 1
      else reported += 1
      if (event.hinted) hinted += 1
      events.unshift(event)
      if (events.length > maxReported) events.length = maxReported
    },
    snapshot() {
      return {
        inspected,
        classified,
        marked,
        reported,
        hinted,
        reasons: { ...reasons },
        events: [...events],
        truncated: total > events.length,
      }
    },
    clear() {
      inspected = 0
      classified = 0
      marked = 0
      reported = 0
      hinted = 0
      total = 0
      for (const reason of REASONS) reasons[reason] = 0
      events.length = 0
    },
  }
}

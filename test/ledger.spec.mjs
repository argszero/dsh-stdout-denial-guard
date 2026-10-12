/**
 * The ledger: the counters that distinguish "nothing was missed" from "nothing ran".
 *
 * A guard whose only output is a repaired result is unauditable, so these arms are
 * about the properties that make the report readable rather than about rendering:
 * the denominator, the bounded window, and the honesty of `truncated`.
 *
 * @module test/ledger.spec
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createLedger } from '../lib/index.js'

/** One event, minimal but complete. */
function event(over = {}) {
  return {
    callId: 'call-1',
    tool: 'bash',
    mode: 'workspace-write',
    signature: 'permission denied',
    response: 'marked',
    hinted: true,
    at: '2026-10-12T00:00:00.000Z',
    ...over,
  }
}

test('a fresh ledger counts nothing, and every reason has a slot', () => {
  const snapshot = createLedger(50).snapshot()
  assert.equal(snapshot.inspected, 0)
  assert.equal(snapshot.classified, 0)
  assert.equal(snapshot.truncated, false)
  assert.deepEqual(snapshot.events, [])
  assert.deepEqual(Object.values(snapshot.reasons), [0, 0, 0, 0, 0, 0, 0, 0], 'one counter per reason, all present')
})

test('every inspection is counted, and under its own reason', () => {
  const ledger = createLedger(50)
  ledger.inspect('no-stdout-signature')
  ledger.inspect('zero-exit')
  ledger.inspect('classified')
  const snapshot = ledger.snapshot()
  assert.equal(snapshot.inspected, 3, 'the denominator')
  assert.equal(snapshot.classified, 1)
  assert.equal(snapshot.reasons['no-stdout-signature'], 1)
  assert.equal(snapshot.reasons['zero-exit'], 1)
  assert.equal(snapshot.reasons['killed'], 0)
})

test('the response posture is counted separately from the classification', () => {
  const ledger = createLedger(50)
  ledger.record(event({ response: 'marked', hinted: true }))
  ledger.record(event({ callId: 'call-2', response: 'reported', hinted: false }))
  const snapshot = ledger.snapshot()
  assert.equal(snapshot.marked, 1)
  assert.equal(snapshot.reported, 1)
  assert.equal(snapshot.hinted, 1)
})

test('the retained list is most recent first', () => {
  const ledger = createLedger(50)
  ledger.record(event({ callId: 'first' }))
  ledger.record(event({ callId: 'second' }))
  assert.deepEqual(ledger.snapshot().events.map(entry => entry.callId), ['second', 'first'])
})

test('the retained window is bounded, and says when it dropped something', () => {
  const ledger = createLedger(3)
  for (let index = 0; index < 10; index += 1) ledger.record(event({ callId: `call-${index}` }))
  const snapshot = ledger.snapshot()
  assert.equal(snapshot.events.length, 3, 'the bound holds: a plugin\'s memory is not a log')
  assert.deepEqual(snapshot.events.map(entry => entry.callId), ['call-9', 'call-8', 'call-7'], 'the newest survive')
  assert.equal(snapshot.truncated, true, 'and the reader is told the list is not all of them')
})

test('an exact fit is not reported as truncated', () => {
  const ledger = createLedger(2)
  ledger.record(event({ callId: 'a' }))
  ledger.record(event({ callId: 'b' }))
  assert.equal(ledger.snapshot().truncated, false)
  ledger.record(event({ callId: 'c' }))
  assert.equal(ledger.snapshot().truncated, true)
})

test('clearing resets the counters and drops the events, without touching the window', () => {
  const ledger = createLedger(2)
  ledger.inspect('classified')
  ledger.record(event())
  ledger.clear()
  const snapshot = ledger.snapshot()
  assert.equal(snapshot.inspected, 0)
  assert.equal(snapshot.classified, 0)
  assert.equal(snapshot.marked, 0)
  assert.deepEqual(snapshot.events, [])
  assert.equal(snapshot.truncated, false)
  assert.deepEqual(Object.values(snapshot.reasons), [0, 0, 0, 0, 0, 0, 0, 0])
})

test('a snapshot is a copy: a later write does not reach a reader holding one', () => {
  const ledger = createLedger(50)
  ledger.inspect('classified')
  const snapshot = ledger.snapshot()
  ledger.inspect('classified')
  ledger.record(event())
  assert.equal(snapshot.inspected, 1)
  assert.equal(snapshot.classified, 1)
  assert.deepEqual(snapshot.events, [])
  assert.equal(snapshot.reasons.classified, 1)
})

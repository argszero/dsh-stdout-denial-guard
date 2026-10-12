/**
 * The predicate, one arm per reason it declines.
 *
 * The arms that matter most are the refusals. A classifier that fires too rarely
 * is a missed repair; one that fires too often is a plugin telling the model it
 * was denied when it was not, which is worse than the bug it fixes — the model
 * would then retry with a wider sandbox mode it never needed, and ask the user to
 * approve it. So every boundary that keeps this plugin quiet gets its own arm.
 *
 * @module test/classify.spec
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { classify, diagnose, defaultSignatures, markDenied, normalizeConfig, readShellFacts } from '../lib/index.js'

const SIGNATURES = defaultSignatures()

/** A value in tool-bash's shape. */
function value(over = {}) {
  return {
    kind: 'foreground',
    exitCode: 1,
    signal: null,
    timedOut: false,
    aborted: false,
    timeoutMs: 120000,
    stdout: { text: "EACCES: permission denied, mkdir '/data/config/astro'", truncated: false },
    stderr: { text: 'landlock-run: partial enforcement (older Landlock ABI)', truncated: false },
    sandbox: { mode: 'workspace-write', denied: false },
    ...over,
  }
}

test('the Astro case classifies, with the evidence it classified on', () => {
  const verdict = classify(value(), SIGNATURES)
  assert.deepEqual(verdict, { mode: 'workspace-write', signature: 'permission denied' })
})

test('a merged stream classifies, which is the same defect by another route', () => {
  const merged = value({
    stdout: { text: 'mkdir: cannot create directory: Read-only file system', truncated: false },
    stderr: { text: '', truncated: false },
    sandbox: { mode: 'read-only', denied: false },
  })
  assert.deepEqual(classify(merged, SIGNATURES), { mode: 'read-only', signature: 'read-only file system' })
})

test('a denial the harness already recorded is not classified again', () => {
  assert.equal(classify(value({ sandbox: { mode: 'workspace-write', denied: true } }), SIGNATURES), undefined)
  assert.equal(diagnose(value({ sandbox: { mode: 'workspace-write', denied: true } }), SIGNATURES).reason, 'denied-not-false')
})

test('a denied flag that is not a boolean is not guessed at', () => {
  for (const denied of [undefined, null, 'false', 0]) {
    const result = diagnose(value({ sandbox: { mode: 'workspace-write', denied } }), SIGNATURES)
    assert.equal(result.reason, 'denied-not-false', `denied=${String(denied)}`)
  }
})

test('danger-full-access is not a confining mode, so nothing under it is a denial', () => {
  const result = diagnose(value({ sandbox: { mode: 'danger-full-access', denied: false } }), SIGNATURES)
  assert.equal(result.reason, 'not-confined')
  assert.equal(classify(value({ sandbox: { mode: 'danger-full-access', denied: false } }), SIGNATURES), undefined)
})

test('a mode added later is treated as confining rather than dropping out of coverage', () => {
  // The test is the negation of the one unconfined name, mirroring the harness's
  // own `ConfinedSandboxMode = Exclude<SandboxMode, 'danger-full-access'>`.
  const verdict = classify(value({ sandbox: { mode: 'some-future-mode', denied: false } }), SIGNATURES)
  assert.equal(verdict?.mode, 'some-future-mode')
})

test('a zero exit is not a denial, however the output is worded', () => {
  assert.equal(diagnose(value({ exitCode: 0 }), SIGNATURES).reason, 'zero-exit')
})

test('a killed call is not evidence of a denied file effect', () => {
  // In these states the exit status is ours, not the program's: text that happens
  // to contain a dialect substring was not produced by a refusal.
  assert.equal(diagnose(value({ timedOut: true }), SIGNATURES).reason, 'killed')
  assert.equal(diagnose(value({ aborted: true }), SIGNATURES).reason, 'killed')
  assert.equal(diagnose(value({ signal: 'SIGKILL' }), SIGNATURES).reason, 'killed')
})

test('a signature the harness already matches on stderr is left to the harness', () => {
  const both = value({ stderr: { text: 'cat: /etc/hosts: Permission denied', truncated: false } })
  assert.equal(diagnose(both, SIGNATURES).reason, 'stderr-signature')
})

test('no signature anywhere means no classification', () => {
  const plain = value({
    stdout: { text: 'some ordinary failure', truncated: false },
    stderr: { text: 'and an ordinary trace', truncated: false },
  })
  assert.equal(diagnose(plain, SIGNATURES).reason, 'no-stdout-signature')
})

test('a shape that is not a shell result is left alone', () => {
  for (const bad of [undefined, null, 'a string', 42, [], {}, { exitCode: 1 }, { exitCode: 1, sandbox: {} }]) {
    assert.equal(diagnose(bad, SIGNATURES).reason, 'not-shell-shape', JSON.stringify(bad))
  }
})

test('a stream without text is not proof of anything', () => {
  assert.equal(diagnose(value({ stdout: {} }), SIGNATURES).reason, 'not-shell-shape')
  assert.equal(diagnose(value({ stderr: { text: 5 } }), SIGNATURES).reason, 'not-shell-shape')
})

test('the facts read out are the facts reported', () => {
  const facts = readShellFacts(value())
  assert.equal(facts.exitCode, 1)
  assert.equal(facts.mode, 'workspace-write')
  assert.match(facts.stdout, /permission denied/)
})

test('recording the denial preserves every other field', () => {
  const source = value()
  const marked = markDenied(source, 'workspace-write')
  assert.equal(marked.sandbox.denied, true)
  assert.deepEqual(marked.stdout, source.stdout, 'the command output is untouched')
  assert.deepEqual(marked.stderr, source.stderr)
  assert.equal(marked.exitCode, source.exitCode)
  assert.equal(source.sandbox.denied, false, 'the input is not mutated in place')
})

test('a narrowed dialect set stops matching the dialects it dropped', () => {
  const settings = normalizeConfig({ dialects: ['bwrap'] }).settings
  assert.equal(classify(value(), settings.signatures), undefined, 'landlock is no longer matched')
  const readOnly = value({ stdout: { text: 'Read-only file system', truncated: false } })
  assert.equal(classify(readOnly, settings.signatures)?.signature, 'read-only file system')
})

test('a caller\'s extra signature is composed with the dialects, not instead of them', () => {
  const settings = normalizeConfig({ signatures: ['denied by the mount policy'] }).settings
  assert.ok(settings.signatures.includes('permission denied'), 'the dialects survive')
  const custom = value({ stdout: { text: 'EACCES: denied by the mount policy', truncated: false } })
  assert.equal(classify(custom, settings.signatures)?.signature, 'denied by the mount policy')
})

test('a text matching both an extra and a dialect reports the dialect entry', () => {
  // Dialects are composed first, so the reported evidence is the harness's own
  // vocabulary whenever the words overlap — an extra can add coverage, never
  // relabel a denial the harness would already have named.
  const settings = normalizeConfig({ signatures: ['operation not permitted on this mount'] }).settings
  const overlapping = value({ stdout: { text: 'operation not permitted on this mount', truncated: false } })
  assert.equal(classify(overlapping, settings.signatures)?.signature, 'operation not permitted')
})

test('an empty signature entry is dropped rather than becoming a wildcard', () => {
  const { settings, emptySignatures } = normalizeConfig({ signatures: ['', '   '] })
  assert.equal(emptySignatures.length, 2)
  assert.equal(settings.signatures.includes(''), false)
  // Nothing matches a bare empty signature, which is the point.
  const plain = value({ stdout: { text: 'an ordinary failure', truncated: false }, stderr: { text: '', truncated: false } })
  assert.equal(classify(plain, settings.signatures), undefined)
})

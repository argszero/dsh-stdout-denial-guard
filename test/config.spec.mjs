/**
 * Configuration resolution, where every mistake is invisible by construction.
 *
 * A matching set that is empty because of a typo looks exactly like an empty set
 * chosen on purpose; a posture that fell back to the default looks exactly like
 * the default. So the arms here are mostly about what a *broken* configuration is
 * allowed to become, and about the fact that it is said out loud.
 *
 * @module test/config.spec
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { defaultConfig, normalizeConfig } from '../lib/index.js'

test('an unconfigured mount is the documented default', () => {
  const { settings } = normalizeConfig()
  assert.equal(settings.mode, 'mark')
  assert.equal(settings.hint, true)
  assert.equal(settings.report, true)
  assert.equal(settings.maxReported, 50)
  assert.equal(settings.noticeMaxChars, 2000)
  assert.deepEqual([...settings.dialects], ['bwrap', 'landlock', 'seatbelt', 'windows-acl'])
  assert.equal(settings.signatures.length, 5, 'the default set is the dialect union')
})

test('a caller value reaches the settings, and undefined does not erase a default', () => {
  const { settings } = normalizeConfig({ mode: 'report', hint: false, report: false, maxReported: 7, noticeMaxChars: 80 })
  assert.equal(settings.mode, 'report')
  assert.equal(settings.hint, false)
  assert.equal(settings.report, false)
  assert.equal(settings.maxReported, 7)
  assert.equal(settings.noticeMaxChars, 80)
  assert.equal(normalizeConfig({ maxReported: undefined }).settings.maxReported, 50)
})

test('a mode this plugin does not implement falls back to the default, loudly', () => {
  // Taking `'Mark'` or `'silent'` as configured is how a deployment ends up with a
  // posture nobody chose and no error to explain it.
  const { settings } = normalizeConfig({ mode: 'silent' })
  assert.equal(settings.mode, defaultConfig.mode)
})

test('a dialect name this plugin does not know is rejected and reported, never honoured', () => {
  const { settings, rejectedDialects } = normalizeConfig({ dialects: ['landlock', 'landloc'] })
  assert.deepEqual([...settings.dialects], ['landlock'])
  assert.deepEqual([...rejectedDialects], ['landloc'])
})

test('a duplicate dialect is asked for once', () => {
  const { settings } = normalizeConfig({ dialects: ['bwrap', 'bwrap', 'landlock'] })
  assert.deepEqual([...settings.dialects], ['bwrap', 'landlock'])
})

test('narrowing the dialects to nothing is allowed, but a collapse to nothing is flagged', () => {
  // An explicit empty list is how a deployment turns matching off without
  // unmounting, and is taken as deliberate. A list of *typos* reaches the same
  // empty set by accident, looks identical from the outside, and is reported.
  const deliberate = normalizeConfig({ dialects: [] })
  assert.equal(deliberate.settings.signatures.length, 0)
  assert.equal(deliberate.emptyDialects, false, 'an explicit choice is not a mistake')

  const collapsed = normalizeConfig({ dialects: ['landloc'] })
  assert.equal(collapsed.settings.dialects.length, 0)
  assert.equal(collapsed.emptyDialects, true, 'every name was a typo, which is not the same request')
  assert.equal(normalizeConfig({ dialects: ['landlock'] }).emptyDialects, false)
})

test('a bound is honoured only when it is a positive integer', () => {
  for (const bad of [0, -5, 1.5, Number.NaN, Number.POSITIVE_INFINITY, undefined, null, '50']) {
    const { settings } = normalizeConfig({ maxReported: bad })
    assert.ok(Number.isInteger(settings.maxReported) && settings.maxReported > 0, `maxReported=${String(bad)}`)
  }
  assert.equal(normalizeConfig({ maxReported: 3.9 }).settings.maxReported, 3, 'a fraction floors rather than rounding up')
})

test('whitespace is not a signature, and an empty one is not a wildcard', () => {
  const { settings, emptySignatures } = normalizeConfig({ signatures: ['', '  ', 'denied by policy'] })
  assert.deepEqual([...emptySignatures], ['', '  '])
  assert.equal(settings.signatures.includes(''), false)
  assert.equal(settings.signatures.includes('denied by policy'), true)
})

test('a caller signature is composed with the dialects, and a duplicate is not counted twice', () => {
  const { settings } = normalizeConfig({ signatures: ['permission denied', 'mine'] })
  assert.equal(settings.signatures.filter(entry => entry === 'permission denied').length, 1)
  assert.equal(settings.signatures.filter(entry => entry === 'mine').length, 1)
})

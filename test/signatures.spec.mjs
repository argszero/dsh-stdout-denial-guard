/**
 * The mirrored dialect table, pinned.
 *
 * `@deepseek-ai/dsh-sandbox-local` keeps `DENIAL_SIGNATURES` module-private, so
 * this package carries a copy and the copy is the thing that can silently drift.
 * A table that drifts is not a harmless staleness: it is a plugin that recognises
 * a denial the harness does not, or misses one it does, in vocabulary the model
 * was taught to read. These arms exist so that a drift has to be *typed* here
 * before it can ship.
 *
 * @module test/signatures.spec
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { DIALECTS, DIALECT_NAMES, defaultSignatures, matchesSignature, signaturesFor } from '../lib/index.js'

/** The table as read from `packages/sandbox/sandbox-local/src/index.ts`. */
const UPSTREAM = {
  bwrap: ['read-only file system'],
  landlock: ['permission denied'],
  seatbelt: ['operation not permitted'],
  'windows-acl': ['access is denied', 'access to the path', 'permission denied', 'operation not permitted'],
}

test('every runner dialect matches the harness table, entry for entry', () => {
  assert.deepEqual(Object.keys(DIALECTS).sort(), Object.keys(UPSTREAM).sort())
  for (const [dialect, signatures] of Object.entries(UPSTREAM)) {
    assert.deepEqual([...DIALECTS[dialect]], signatures, `${dialect} drifted`)
  }
})

test('the launcher-failure entry is deliberately not a dialect', () => {
  // Upstream's `runnerCommand` is a launcher vocabulary, not a denial dialect: a
  // launcher failure means the command never ran, and the harness throws
  // SandboxUnavailableError for it. Treating its wording as a file-effect denial
  // would invent a denial the runner never reported.
  assert.equal(Object.hasOwn(DIALECTS, 'runnerCommand'), false)
  assert.equal(defaultSignatures().includes('read-only file system'), true, 'bwrap\'s copy still covers the overlap')
})

test('the default set is the union, with no duplicates', () => {
  const all = defaultSignatures()
  assert.deepEqual([...all].sort(), [...new Set(all)].sort(), 'no duplicate substrings')
  for (const dialect of DIALECT_NAMES) {
    for (const signature of DIALECTS[dialect]) {
      assert.ok(all.includes(signature), `${signature} missing from the default union`)
    }
  }
  // Four dialects, five distinct substrings: windows-acl repeats landlock's and
  // seatbelt's wording, and the union keeps one of each.
  assert.equal(all.length, 5, 'four dialects, five distinct substrings')
})

test('a narrowed dialect set carries only its own substrings', () => {
  assert.deepEqual([...signaturesFor(['bwrap'])], ['read-only file system'])
  assert.deepEqual([...signaturesFor(['seatbelt'])], ['operation not permitted'])
  assert.deepEqual([...signaturesFor(['landlock', 'bwrap'])], ['permission denied', 'read-only file system'])
})

test('dialects that share wording do not list the shared substring twice', () => {
  // windows-acl restates landlock's and seatbelt's words. A narrowed set that
  // asked for both would otherwise report its size as a count of dialect entries
  // rather than of distinct substrings.
  const overlapping = signaturesFor(['landlock', 'seatbelt', 'windows-acl'])
  assert.deepEqual([...overlapping], ['permission denied', 'operation not permitted', 'access is denied', 'access to the path'])
  assert.deepEqual([...overlapping].sort(), [...new Set(overlapping)].sort())
})

test('matching is case-insensitive, as the harness\'s own comparison is', () => {
  assert.equal(matchesSignature('Permission denied', ['permission denied']), true)
  assert.equal(matchesSignature('PERMISSION DENIED', ['permission denied']), true)
  assert.equal(matchesSignature('READ-ONLY FILE SYSTEM', ['read-only file system']), true)
})

test('an empty signature matches nothing, and empty text matches nothing', () => {
  // A config typo must not become a wildcard.
  assert.equal(matchesSignature('anything at all', ['']), false)
  assert.equal(matchesSignature('', ['permission denied']), false)
})

test('the real report text from #9497 is recognised', () => {
  const stdout = "EACCES: permission denied, mkdir '/data/config/astro'"
  assert.equal(matchesSignature(stdout, defaultSignatures()), true)
  // And the informational launcher line on stderr is not what proves it: the
  // correct classification comes from the stdout text, which is the whole point.
  const stderr = 'landlock-run: partial enforcement (older Landlock ABI)'
  assert.equal(matchesSignature(stderr, defaultSignatures()), false)
})

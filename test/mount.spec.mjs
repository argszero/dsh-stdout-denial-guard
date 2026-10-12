/**
 * The seam, against the real registry: a denial reported on stdout reaches the
 * model as a denial.
 *
 * The assertions are all about **what the renderer produced**, never about what
 * the plugin returned. The plugin's whole claim is that it repairs the *input* to
 * the harness's own rendering rather than printing a second dialect beside it, so
 * an arm that asserted the plugin's return value would test the wrong thing: the
 * marker in these results exists in exactly one place — the tool's `render` — and
 * the render call count says whether it ran again.
 *
 * @module test/mount.spec
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { escalationHintMarker, sandboxDenialMarker } from '@deepseek-ai/dsh-sandbox'
import { logText, resultText, run, shellValue, world } from './harness.mjs'

/** The report the Astro telemetry case actually produced, on the wrong stream. */
const ASTRO_STDOUT = "EACCES: permission denied, mkdir '/data/config/astro'\n"
const LANDLOCK_STDERR = 'landlock-run: partial enforcement (older Landlock ABI)\n'

test('a denial on stdout becomes a denial the model can read', async () => {
  const value = shellValue({
    stdout: { text: ASTRO_STDOUT, truncated: false },
    stderr: { text: LANDLOCK_STDERR, truncated: false },
  })
  const harness = await world({ value })
  const result = await run(harness)
  const text = resultText(result)

  assert.match(text, /file access denied under workspace-write mode/, 'the canonical marker is present')
  assert.ok(text.includes(sandboxDenialMarker('workspace-write')), 'and it is the harness\'s own string, not a copy')
  assert.match(text, /\[exit code: 1\]/, 'the exit marker is still there')
  assert.ok(text.indexOf(sandboxDenialMarker('workspace-write')) < text.indexOf('[exit code: 1]'),
    'the marker precedes the exit marker, which parseExitStatus anchors on')
})

test('the control arm: without the plugin the same result carries no marker', async () => {
  const value = shellValue({
    stdout: { text: ASTRO_STDOUT, truncated: false },
    stderr: { text: LANDLOCK_STDERR, truncated: false },
  })
  const harness = await world({ value, plugin: false })
  const text = resultText(await run(harness))

  assert.doesNotMatch(text, /file access denied/, 'the defect: the harness never classified it')
  assert.match(text, /permission denied/, 'and the raw text is still there — the model sees the failure, not the reason')
})

test('the marker comes from re-running the tool\'s own renderer', async () => {
  const harness = await world({ value: shellValue({ stdout: { text: ASTRO_STDOUT, truncated: false } }) })
  await run(harness)

  assert.equal(harness.renderCalls.length, 2, 'render ran twice: the original projection, then the replacement')
  assert.equal(harness.renderCalls[0]?.sandbox?.denied, false, 'the first call saw the harness\'s verdict')
  assert.equal(harness.renderCalls[1]?.sandbox?.denied, true, 'the second saw the plugin\'s')
  assert.equal(harness.renderCalls[1]?.stdout?.text, ASTRO_STDOUT, 'and the command output is untouched')
})

test('a denial the harness already classified is left exactly as it is', async () => {
  const value = shellValue({
    stdout: { text: '', truncated: false },
    stderr: { text: 'cat: /etc/hosts: Permission denied\n', truncated: false },
    sandbox: { mode: 'workspace-write', denied: true },
  })
  const harness = await world({ value })
  const text = resultText(await run(harness))

  assert.equal(harness.renderCalls.length, 1, 'no re-render: the plugin did not touch it')
  assert.ok(text.includes(sandboxDenialMarker('workspace-write')), 'the harness\'s own marker is the one shown')
})

test('a signature on stderr keeps the harness\'s answer, even with denied unset', async () => {
  // The harness would have set denied; a deployment where it did not is the one
  // case where this plugin could second-guess it. It must not.
  const value = shellValue({ stderr: { text: 'read-only file system\n', truncated: false } })
  const harness = await world({ value })
  await run(harness)

  assert.equal(harness.renderCalls.length, 1, 'left alone: the stderr matcher is the harness\'s own business')
})

test('no escalation in the composition means no escalation hint', async () => {
  const value = shellValue({ stdout: { text: ASTRO_STDOUT, truncated: false } })
  const harness = await world({ value, escalation: false })
  const result = await run(harness)

  assert.match(resultText(result), /file access denied under workspace-write mode/, 'the marker still appears')
  assert.equal(result.additionalContexts, undefined, 'but nothing tells the model to retry with a parameter the tool does not have')
})

test('when the tool advertises escalation, the hint rides additionalContexts', async () => {
  const value = shellValue({ stdout: { text: ASTRO_STDOUT, truncated: false } })
  const harness = await world({ value })
  const result = await run(harness)

  const injected = result.additionalContexts ?? []
  assert.equal(injected.length, 1, 'one injected message')
  const text = injected[0].content.map(block => block.type === 'text' ? block.text : '').join('\n')
  assert.ok(text.includes(escalationHintMarker('command')), 'carrying the harness\'s own hint line, verbatim')
  assert.equal(injected[0].source.kind, 'stdout-denial-guard', 'attributed to this producer')
})

test('a call another listener blocked is passed through untouched', async () => {
  const value = shellValue({ stdout: { text: ASTRO_STDOUT, truncated: false } })
  const harness = await world({ value, block: 'not allowed' })
  const result = await run(harness)

  assert.equal(result.isError, true, 'still blocked')
  assert.match(resultText(result), /not allowed/, 'with the blocker\'s own feedback')
})

test('a result another listener replaced the content of is left to that listener', async () => {
  const value = shellValue({ stdout: { text: ASTRO_STDOUT, truncated: false } })
  const harness = await world({ value, replaceContent: 'output spilled to /tmp/out.txt' })
  const text = resultText(await run(harness))

  assert.equal(text, 'output spilled to /tmp/out.txt', 'a spill keeps its rendering')
  assert.doesNotMatch(text, /file access denied/, 'and this plugin stood down rather than overwrite it')
})

test('mode "report" counts without changing anything', async () => {
  const value = shellValue({ stdout: { text: ASTRO_STDOUT, truncated: false } })
  const harness = await world({ value, config: { mode: 'report' } })
  const result = await run(harness)

  assert.doesNotMatch(resultText(result), /file access denied/, 'nothing is rewritten')
  assert.equal(result.additionalContexts, undefined, 'and nothing is injected')
})

test('mode "off" mounts no listener but still answers the report', async () => {
  const value = shellValue({ stdout: { text: ASTRO_STDOUT, truncated: false } })
  const harness = await world({ value, config: { mode: 'off' } })
  const result = await run(harness)

  assert.doesNotMatch(resultText(result), /file access denied/)
  const report = await harness.ctx.tools.execute({
    signal: new AbortController().signal,
    callId: 'call-report',
    name: 'stdout_denial_report',
    arguments: {},
  })
  assert.match(resultText(report), /not mounted \(mode: off\)/)
})

test('the report answers with the counters and the reason breakdown', async () => {
  const harness = await world({
    value: args => args.command === 'true'
      ? shellValue({ exitCode: 0, stdout: { text: '', truncated: false } })
      : shellValue({ stdout: { text: ASTRO_STDOUT, truncated: false } }),
  })
  await run(harness)
  await harness.ctx.tools.execute({
    signal: new AbortController().signal,
    callId: 'call-2',
    name: 'bash',
    arguments: { command: 'true' },
  })

  const report = await harness.ctx.tools.execute({
    signal: new AbortController().signal,
    callId: 'call-report',
    name: 'stdout_denial_report',
    arguments: {},
  })
  const text = resultText(report)
  assert.match(text, /tool results inspected: 2/, 'the denominator, so "nothing found" is distinguishable from "never ran"')
  assert.match(text, /denials the harness missed: 1/)
  assert.match(text, /rewritten \(posture "mark"\): 1/)
  assert.match(text, /no dialect signature on stdout/)
})

test('mounting the default export works, which is what a profile entry mounts', async () => {
  const harness = await world({ value: shellValue({ stdout: { text: ASTRO_STDOUT, truncated: false } }), plugin: 'default' })
  assert.match(resultText(await run(harness)), /file access denied under workspace-write mode/)
})

test('the report tool is registered by default and can be turned off', async () => {
  const on = await world({ value: shellValue() })
  assert.ok(on.ctx.tools.get('stdout_denial_report') !== undefined)
  const off = await world({ value: shellValue(), config: { report: false } })
  assert.equal(off.ctx.tools.get('stdout_denial_report'), undefined)
})

test('hint: false keeps the marker and drops the hint', async () => {
  const value = shellValue({ stdout: { text: ASTRO_STDOUT, truncated: false } })
  const harness = await world({ value, config: { hint: false } })
  const result = await run(harness)

  assert.match(resultText(result), /file access denied under workspace-write mode/, 'the marker is the repair of the field')
  assert.equal(result.additionalContexts, undefined, 'and the hint is off on its own')
})

test('an over-long notice is truncated and says so', async () => {
  const value = shellValue({ stdout: { text: ASTRO_STDOUT, truncated: false } })
  const harness = await world({ value, config: { noticeMaxChars: 30 } })
  const injected = (await run(harness)).additionalContexts ?? []
  const text = injected[0].content.map(block => block.type === 'text' ? block.text : '').join('\n')

  assert.ok(text.length <= 30, `the cap holds (${text.length})`)
  assert.match(text, /…$/, 'and a reader can tell it was cut rather than complete')
})

test('the report names every reason, with no undefined leaks', async () => {
  const harness = await world({ value: shellValue({ stdout: { text: ASTRO_STDOUT, truncated: false } }) })
  await run(harness)
  await harness.ctx.tools.execute({
    signal: new AbortController().signal,
    callId: 'call-report',
    name: 'stdout_denial_report',
    arguments: {},
  })
  const text = resultText(await harness.ctx.tools.execute({
    signal: new AbortController().signal,
    callId: 'call-report-2',
    name: 'stdout_denial_report',
    arguments: {},
  }))

  assert.doesNotMatch(text, /undefined/, 'a missing label reads as a bug in the report, not as a counter')
  for (const phrase of ['not a foreground shell result', 'the harness already recorded a denial', 'ran under danger-full-access',
    'exited 0, so the command did not report a failure', 'timed out, was aborted, or was killed by a signal',
    'no dialect signature on stdout', 'the harness\'s own stderr matcher matched it', 'classified as a missed denial']) {
    assert.ok(text.includes(phrase), `missing label: ${phrase}`)
  }
})

test('clearing reports the state before it clears it', async () => {
  const harness = await world({ value: shellValue({ stdout: { text: ASTRO_STDOUT, truncated: false } }) })
  await run(harness)
  const ask = args => harness.ctx.tools.execute({
    signal: new AbortController().signal,
    callId: `call-report-${args.clear === true ? 'clear' : 'read'}`,
    name: 'stdout_denial_report',
    arguments: args,
  })

  const cleared = resultText(await ask({ clear: true }))
  assert.match(cleared, /Counters cleared at/, 'the note says what just happened')
  assert.match(cleared, /denials the harness missed: 1/, 'and the report below is the state before it')
  assert.match(resultText(await ask({})), /denials the harness missed: 0/, 'the counters really were reset')
})

test('a failure in the guard\'s own work leaves the result exactly as it was', async () => {
  // Fail-open is a claim in the README, so it gets an arm rather than trust: the
  // guard's own logging interpolates the call id, and a value that cannot be
  // interpolated makes that interpolation throw. The call must survive it — a
  // guard whose bug breaks working tool calls is worse than the failure it
  // prevents — and the failure must still be reported, because a guard that
  // silently stops deciding is the other half of the same bug.
  const harness = await world({
    value: shellValue({ stdout: { text: ASTRO_STDOUT, truncated: false } }),
    replaceContent: 'output spilled to /tmp/out.txt',
  })
  const result = await harness.ctx.tools.execute({
    signal: new AbortController().signal,
    callId: Symbol('hostile'),
    name: 'bash',
    arguments: { command: 'npx astro dev --help' },
  })

  assert.equal(result.isError, false, 'the call still succeeds')
  assert.equal(resultText(result), 'output spilled to /tmp/out.txt', 'and the other listener\'s rendering is the one kept')
  assert.match(logText(harness.logged), /failed while classifying a result/, 'the failure is reported, not swallowed')
})

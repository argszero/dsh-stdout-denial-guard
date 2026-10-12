/**
 * The integration harness: a REAL cordis context, the REAL `ToolRuntime` from
 * `@deepseek-ai/dsh-tools`, and a tool whose output contract is tool-bash's.
 *
 * Nothing about the seam is simulated. The plugin listens on
 * `tools/post-execute`; this harness dispatches through `ctx.tools.execute()`,
 * the registry's own public entry point, so the pipeline under test — the
 * waterfall, its ordering, the `value` branch that re-runs the owning renderer,
 * the additionalContexts ferry — is the shipped one.
 *
 * The one fabricated piece is the point. The tool's `render` mirrors
 * `packages/shell/tool-bash/src/render.ts`: it prints
 * `sandboxDenialMarker(mode)` when `value.sandbox.denied` is set, and it is
 * **the only place in this harness that produces that string**. So an arm can
 * assert the marker appeared *because the plugin told the truth about one field*
 * rather than because the plugin printed anything — and `renderCalls` counts the
 * invocations, which is how the re-render itself becomes observable.
 *
 * Every arm runs twice — with the plugin and without it (`plugin: false`). The
 * control is what turns "the mutation had no effect" into "this plugin is why".
 *
 * @module test/harness
 */

import { Context } from '@deepseek-ai/cordis'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import { sandboxDenialMarker } from '@deepseek-ai/dsh-sandbox'
import { ToolCallId } from '@deepseek-ai/dsh-llm'
import ToolRuntime, { defineTool } from '@deepseek-ai/dsh-tools'
import * as plugin from '../lib/index.js'

/** The neutral signal every fabricated call carries. */
export const SIGNAL = new AbortController().signal

/** One agent stand-in; `ScopeKey` is any object. */
export const AGENT = { name: 'agent-a' }

/**
 * A shell result value in the shape `tool-bash`'s `canonicalBashResult` produces.
 * @param over - fields to override.
 * @returns the value.
 */
export function shellValue(over = {}) {
  return {
    kind: 'foreground',
    exitCode: 1,
    signal: null,
    timedOut: false,
    aborted: false,
    timeoutMs: 120000,
    stdout: { text: '', truncated: false },
    stderr: { text: '', truncated: false },
    sandbox: { mode: 'workspace-write', denied: false },
    ...over,
  }
}

/**
 * Mount a real context with a real tool registry, and by default this plugin.
 *
 * @param spec - `plugin: false` mounts everything except this plugin (the control
 *   arm); `config` is the plugin's configuration; `escalation: false` omits the
 *   escalation parameters from the tool schema, which is how tool-bash models a
 *   composition with no sandboxing executor to escalate; `value` is what the tool
 *   body returns, or a function of its arguments when two calls must differ; `replaceContent` registers a later `tools/post-execute`
 *   listener that replaces the result's content (the spill shape); `block`
 *   registers one that blocks the call.
 * @returns the context, what the renderer was called with, and the log.
 */
export async function world(spec = {}) {
  const ctx = new Context({})
  const logged = []
  const renderCalls = []
  ctx.logger.exporter({ levels: { default: 2 }, export: message => { logged.push(message) } })

  // ToolRuntime injects `systemPrompt`; without it the service never starts and
  // `ctx.tools` stays undefined.
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)

  ctx.tools.register(defineTool({
    name: 'bash',
    description: 'the bash tool',
    parameters: {
      command: { type: 'string', required: true, description: 'The bash command to execute.' },
      ...spec.escalation === false ? {} : {
        sandbox_permissions: {
          type: 'string',
          enum: ['workspace-write', 'danger-full-access'],
          description: 'The narrowest wider sandbox mode for a one-shot retry.',
        },
        justification: { type: 'string', description: 'Required with sandbox_permissions.' },
      },
    },
    output: {
      // The same shape tool-bash declares: a boolean, not a const, so recording
      // the truth about it is a value the contract already admits.
      schema: {
        type: 'object',
        additionalProperties: true,
        properties: {
          exitCode: { type: 'number', required: true },
          sandbox: {
            type: 'object',
            additionalProperties: false,
            properties: {
              mode: { type: 'string', required: true },
              denied: { type: 'boolean', required: true },
            },
          },
        },
      },
      render: (_args, value) => {
        renderCalls.push(value)
        const out = value.stdout?.text ?? ''
        const err = value.stderr?.text ?? ''
        let body = out
        if (err.length > 0) body += `[stderr]\n${err}`
        const markers = []
        if (value.sandbox?.denied) markers.push(sandboxDenialMarker(value.sandbox.mode))
        if (value.exitCode !== 0) markers.push(`[exit code: ${value.exitCode}]`)
        return [{ type: 'text', text: [body, ...markers].filter(part => part !== '').join('\n') }]
      },
    },
    async execute(args) {
      // `value` may be a function of the arguments, which is how one harness
      // serves two calls that must differ.
      if (typeof spec.value === 'function') return spec.value(args)
      return spec.value ?? shellValue()
    },
  }))

  if (spec.plugin !== false) {
    // `plugin` is this module's namespace; a loader entry mounts its **default**
    // export (`exports.default ?? exports`), and the two differ by the `Config` key.
    await ctx.plugin(spec.plugin === 'default' ? plugin.default : plugin, spec.config ?? {})
  }

  if (spec.replaceContent !== undefined) {
    ctx.on('tools/post-execute', async (_exec, _result, next) => {
      await next()
      return { kind: 'accept', content: [{ type: 'text', text: spec.replaceContent }] }
    })
  }

  if (spec.block !== undefined) {
    ctx.on('tools/post-execute', async (_exec, _result, next) => {
      await next()
      return { kind: 'block', feedback: [{ type: 'text', text: spec.block }] }
    })
  }

  return { ctx, logged, renderCalls }
}

/**
 * Run one call through the real registry.
 * @param harness - a harness from {@link world}.
 * @returns the normalized tool result.
 */
export function run(harness, agent = AGENT) {
  return harness.ctx.tools.execute({
    signal: SIGNAL,
    callId: ToolCallId(`call-${Math.random().toString(36).slice(2)}`),
    name: 'bash',
    arguments: { command: 'npx astro dev --help' },
    agent,
  })
}

/**
 * The final rendered text of a result's content blocks.
 * @param result - a normalized tool result.
 * @returns the concatenated text.
 */
export function resultText(result) {
  return (result.content ?? []).map(block => block.type === 'text' ? block.text : '').join('\n')
}

/** The captured log as one string. */
export function logText(logged) {
  return logged.map(message => message.args.map(argument => String(argument)).join(' ')).join('\n')
}

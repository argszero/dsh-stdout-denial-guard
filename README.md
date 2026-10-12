# @argszero/dsh-stdout-denial-guard

Classifies sandbox denials the harness reports on **stdout**.

The harness classifies a denied file effect by matching the runner's dialect
against **stderr**, and only when the command exited non-zero. A program that
reports the failing path on stdout — a Node tool printing
`EACCES: permission denied, mkdir '/data/config/astro'`, or any command that
merged the streams with `2>&1`, which agents do constantly — exits non-zero with
nothing on stderr the matcher knows. The denial is real, `sandbox.denied` stays
`false`, and the result reads as an ordinary command failure. The model, told
nothing, works around the sandbox instead of asking for the access it was
refused.

One report, one mechanism, one seam:
[#9497](https://github.com/deepseek-ai/deepseek-harness/discussions/9497).

## The problem

`packages/sandbox/sandbox/src/diagnostics.ts` matches one stream:

```ts
function matchesSignature(exitCode: number | null, stderr: string, signatures: readonly string[]): boolean
```

and `packages/shell/bash-sandbox/src/helpers.ts` passes it stderr:

```ts
export function classifyDenial(result: ShellRunResult, signatures: readonly string[]): boolean {
  return matchesSignature(result.exitCode, result.stderr.text, signatures)
}
```

The verdict lands on the result as `sandbox.denied`, and **everything** the model
is told about a denial is gated on that one boolean
(`packages/shell/tool-bash/src/render.ts`):

```ts
if (result.sandbox?.denied) {
  markers.push(sandboxDenialMarker(result.sandbox.mode))
  if (escalationModes.length > 0) markers.push(escalationHintMarker('command'))
}
```

So the failure is not that the model is told the wrong thing — it is that the
model is told nothing, in a case where the harness has a marker, a hint, and an
escalation path and uses none of them.

## The seam

The render layer is re-runnable. `tools/post-execute` is a cordis waterfall whose
`accept` decision may replace a successful result's **value**, and the registry
re-runs the tool's own output contract over the replacement
(`packages/core/tools/src/index.ts`):

```ts
const replaced = this.createSuccessResult(exec, tool, decision.value)   // → tool.output.render(...)
```

That is the whole repair. **This plugin prints nothing.** It sets the one field
the renderer already reads, and `tool-bash` prints its own marker in its own
position — ahead of the exit marker `parseExitStatus` anchors on:

```text
EACCES: permission denied, mkdir '/data/config/astro'[stderr]
landlock-run: partial enforcement (older Landlock ABI)
[sandbox: file access denied under workspace-write mode]
[exit code: 1]
```

(Verbatim output of the suite's own harness, which mirrors tool-bash's renderer
and is the only place in that harness that can produce that marker. The harness
counts renderer invocations, so the re-render is observed rather than assumed:
**2** for that call — the original and the replacement.)

What the plugin *cannot* reach that way is the escalation hint, which is gated on
an `escalationModes` argument captured in the tool's own closure. That one line
travels as `additionalContexts`, the decision's public channel for context a
renderer cannot produce — and it carries the harness's own
`escalationHintMarker`, imported rather than paraphrased, because a plugin that
rewrites the harness's retry vocabulary is teaching the model a second phrasing
for one concept.

Whether escalation is advertised is not guessed. `tool-bash` spreads
`sandbox_permissions` and `justification` into its parameter spec **only** when
its `escalationModes` is non-empty, so the parameter's presence in the registered
definition is "escalation is available in this composition". The plugin reads it
off `parameters.properties` — the normalized shape `defineTool` stores after
`parameterSchemaSpecToJsonSchema` — and attaches the hint exactly when the
harness would have.

### The dialect table is mirrored, deliberately

`DENIAL_SIGNATURES` is a module-private `const` in
`packages/sandbox/sandbox-local/src/index.ts`, and the package's `exports` map
publishes only `.`, so a consumer outside it has two options: mirror the table, or
invent a classification that disagrees with the harness. This mirrors it —
four runner dialects, five distinct substrings — in its own module with its own
test, because a table that drifts silently is a plugin that classifies denials
the harness does not, in vocabulary the model was taught to read.

The harness's `runnerCommand` entry is **not** mirrored: that is its
launcher-failure vocabulary, not a denial dialect. A launcher failure means the
command never ran, and the harness already ranks it above a denial and throws
`SandboxUnavailableError`; treating its wording as a file-effect denial would
invent a denial the runner never reported.

## Install

```sh
npm install @argszero/dsh-stdout-denial-guard
```

Mount it in a dsh profile like any other plugin, or apply the bundle patch this
package ships:

```yaml
- insert:
    - id: stdout-denial-guard
      name: '@argszero/dsh-stdout-denial-guard'
      config:
        mode: mark
```

The plugin declares `dsh.bundle.patch`, so `cordis.patch.yml` is what the harness
applies; the file carries the source anchors this README cites.

## Configuration

| option | default | meaning |
|---|---|---|
| `mode` | `'mark'` | `mark` re-classifies and restores the marker; `report` counts and logs the denial and changes nothing; `off` installs no listener |
| `dialects` | every dialect | which runner dialects to match, by name; unknown names are rejected and reported, never silently honoured |
| `signatures` | `[]` | extra substrings, **composed with** the dialects rather than replacing them |
| `hint` | `true` | attach the escalation hint when the tool advertises escalation |
| `report` | `true` | register the read-only `stdout_denial_report` tool |
| `maxReported` | `50` | how many classifications the in-memory report retains |
| `noticeMaxChars` | `2000` | cap on the length of the injected hint notice |

`dialects` exists because the harness picks the table by the runner it selected at
confine time, and the runner is **not** on the value this plugin sees — so the
default is the union, and a deployment that knows its own runner narrows it. A
typo there is the difference between recognising the runner and recognising
nothing, and the failure is invisible (a set that matches nothing also never
produces a false positive), so unknown names are logged rather than dropped in
silence. Narrowing to nothing is allowed — it is how a deployment turns matching
off without unmounting — and it is logged too.

`report` is how a deployment is measured before the guard is trusted: it decides
exactly as `mark` would and writes nothing.

## The report

```
# stdout-denial-guard report

tool results inspected: 3
denials the harness missed: 1
  rewritten (posture "mark"): 1
  counted only (posture "report"): 0
  carrying the escalation hint: 1

## why the other inspections ended
0	not a foreground shell result
0	the harness already recorded a denial, or the flag was not a boolean
0	ran under danger-full-access, or carried no usable mode
0	exited 0, so the command did not report a failure
0	timed out, was aborted, or was killed by a signal
2	no dialect signature on stdout
0	the harness's own stderr matcher matched it
1	classified as a missed denial

## the 1 most recent classification
- 2026-10-12T09:15:57.573Z call-1 bash [marked +hint] mode=workspace-write matched "permission denied"
```

(Verbatim: one denied call, two ordinary failures, then this report.)

The **denominator** is the part that makes it usable. `inspected` counts every
result this plugin's frame opened on, so `0` can be told apart from "the listener
never ran" — and the reason breakdown says how much of what it saw it actually
decided about, which is what a guard that is quiet because nothing happened looks
like next to one that is quiet because it is not running.

`clear: true` reports the current contents and then forgets them, which is how a
deployment is re-measured after a change.

## Honest boundaries

- **It cannot fix the classifier.** Reading stdout in `matchesSignature` is the
  upstream change, and it is the right one. This closes the model's side of the
  defect, for as long as it is mounted, and nothing else.
- **It stands down rather than overriding.** An inner listener that **blocked**
  the call is passed through untouched (un-blocking a call to add a marker is a
  far worse bug than a missed marker), and an inner `accept` that already carries
  `content` is left alone — a decision cannot carry both `value` and `content`,
  and a spill replaced the content so the model would not read the result
  verbatim. Both cases are logged.
- **It classifies by dialect substring, as the harness does**, so it inherits the
  same limit: a runner whose dialect is not in the table is not recognised.
- **It requires a confining mode and a non-zero exit.** A command that swallowed
  its own failure and exited 0 stays unclassified, and nothing under
  `danger-full-access` can be a policy denial.
- **A killed call is not evidence.** On a timeout, an abort, or a signal the exit
  status is ours, not the program's: text that happens to contain a dialect
  substring in that state was not produced by a refusal.
- **It fails open.** Every part of its own work is guarded; an error leaves the
  result exactly as the harness rendered it. A guard whose bug breaks working
  calls is worse than the failure it prevents.

## Tests

```sh
npm test          # build + the suite (39 arms)
npm run test:inject    # mutation harness: does the suite actually notice?
npm run test:probe-lines   # pin every line the peer range admits, per line
```

The integration arms run against a **real** cordis context and the **real**
`ToolRuntime` from `@deepseek-ai/dsh-tools`, dispatching through
`ctx.tools.execute()` — so the pipeline under test is the shipped one. Every arm
runs twice, with the plugin and without it, which is what turns "the mutation had
no effect" into "this plugin is why".

## Compatibility

`peerDependencies` admit `>=0.1.7-rc.1 <0.2.0 || >=0.2.0-rc.2 <0.3.0` for the
harness packages, and `npm run test:probe-lines` pins **the whole line** (not just
the packages this plugin imports), installs, builds and runs the suite per line.
A line that fails there is removed from the range, this section and the README
rather than left claimed.

`@deepseek-ai/cordis` is a peer as well but is not pinned per line: its version
numbering does not follow the harness's.

The two value imports — `createUserMessage` from `@deepseek-ai/dsh-llm` and
`defineTool` from `@deepseek-ai/dsh-tools` — are declared as peers rather than
dependencies on purpose: a `dependencies` entry is how a plugin ends up in a
`profile` deployment with its own copy of the registry's package, a second
evaluation whose symbols are equal to nothing the host holds.

## License

MIT.

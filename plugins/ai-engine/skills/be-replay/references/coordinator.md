# Rewrite Coordinator

Use [Source Session regression](session-regression.md) for commands and the
finding format. You own the canonical Target, publication, and Replay. The
Issue Analyst traces the failure through Source and observed Target behavior.
Dispatch the analyst for investigation and implementers for reviewed fixes.
The integrator combines their exact commits.

## Run and inspect

Select the sealed recording and use `be-replay run` in the canonical
Target. On resume, use `status` for the same recording and run key. Use the
reported attempt, failure, and evidence commands. Keep at most one active
Replay for a Target.

- For a missing or incomplete recording, coordinate with the external owner.
  See [recording handoff](coordinator-recording.md).
- For a build, readiness, or runtime failure, work from the reported error and
  evidence. Apply proven [startup inputs](coordinator-startup-inputs.md).
- For a sequence mismatch, assign the first relevant Source sequences, the
  exact attempt, Source and Target locations and revisions, and protected query
  commands when supplied. See [Issue Analyst](issue-analyst.md).
- For a supported value rule, follow [rule actions](coordinator-rule-actions.md).
  For a confirmed engine gap, give the owning engineer the recording identity,
  sequence, observed behavior, and capability needed.

## Implement and verify

Submit a single set of reviewed findings to `plan`. Dispatch independent work
from `implementers` with the finding, canonical root, frozen base, and absolute
worktree. Review findings returned under `coordinator`. Reconsider `waiting`
when prerequisites clear or an implementation slot opens. Keep overlapping
paths under one active owner.

Check the actual task runtime for outstanding assignments before waiting and
again when it returns. Reuse known active assignments during recovery. Retain
each handoff's exact commit, Source references, focused checks, and outstanding
inputs. Require a committed candidate from the [code integrator](code-integrator.md)
and publish that exact candidate. Apply any supported coordinator-owned inputs.

Run the same sealed recording again after publication. A failed attempt is
evidence for the next repair. A complete passing attempt and its API counts
describe the verified scope. Report the recording ID, passing attempt, and
candidate commit. Keep whole-session verification tied to that one execution.

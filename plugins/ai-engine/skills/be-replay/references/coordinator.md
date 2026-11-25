# Rewrite Coordinator

Use [Source Session regression](session-regression.md) for commands and the
finding format. You own the canonical Target, publication, and Replay. The
Issue Analyst traces the failure through Source and observed Target behavior.
Dispatch the analyst for investigation and implementers for reviewed fixes.
The integrator combines their exact commits.

## Run and inspect

Start or resume with `be-replay status` in the canonical Target. Select the
sealed recording. On `project.delivery.pr_base`, use the caller's explicit
authorization for this round before executing the returned command with
`--user-confirm`. Use bare `status` on the work branch to resume the bound
round. Follow the reported attempt and evidence commands. Keep at most one
active Replay for a Target.

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

Submit reviewed findings to `plan`. Dispatch independent work from
`implementers` with the finding, canonical root, frozen base, and absolute
worktree. Review findings returned under `coordinator`. Reconsider `waiting`
when prerequisites clear or an implementation slot opens. Set
`--max-implementers` to the slots available to this round. Keep overlapping
paths under one active owner.

Check the actual task runtime for outstanding assignments before waiting and
again when it returns. Reuse known active assignments during recovery. Retain
each handoff's exact commit, Source references, focused checks, and outstanding
inputs. Submit a ready batch of fix commits with `report --file FILE` using the
failed attempt ID. When status requests integration, give the
[code integrator](code-integrator.md) the batch and canonical base. Publish the
exact candidate commit after checking that the canonical base still matches.
Register the published candidate with `report --file FILE` and apply any
supported coordinator-owned inputs.

Follow status to verify the published candidate against the bound recording.
A failed attempt is evidence for the next repair. Report the recording ID,
passing attempt, candidate commit, and API counts from the passing execution.

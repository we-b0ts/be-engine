# Git And PR Delivery

Read this reference when choosing the migration branch and again when delivering
the verified change.

## Resolve The PR Base

Resolve the PR base in this order:

1. the user's explicit instruction;
2. the generated and validated `.traffic-e2e/e2e.yaml` `pr_base`;
3. target `AGENTS.md` or linked repository documentation;
4. the hosting repository's default branch when it is clearly the intended
   integration target.

If these sources disagree or no intended base can be established, stop and ask.
Never assume a universal PR base for a generic target.
`traffic-e2e init` must validate and persist the resolved branch before
prepare or replay; every later runner command revalidates it.

`pr_base` is only the pull-request target. Never commit, merge, rebase, or
cherry-pick migration work into it. Work on a focused feature branch.

## Protect Existing Work

Inspect `git status --short`, the current branch, its upstream, and the resolved
base before editing. Existing changes belong to the user unless proven
otherwise.

- Do not automatically stash, switch away from, rebase, pull over, or reapply a
  dirty worktree.
- Keep unrelated changes out of the migration commit. If they overlap the
  required scope and cannot be preserved safely, stop and report the conflict.
- Create a focused feature branch from the resolved base when repository state
  permits it. Follow the target naming convention; otherwise use a concise
  `codex/` scope name.
- Do not run migration write commands on `pr_base` or detached HEAD.
- Keep `.traffic-e2e/local/` ignored. Never stage, commit, or force-add its run
  state, reports, logs, sessions, PIDs, or temporary files.

## Deliver The Increment

Deliver useful focused changes after the applicable target quality checks and
evidence audit, even when recorded E2E leaves the migration `incomplete` or
`blocked`. A blocker prevents a completion claim, but does not prevent commit,
push, or PR creation.

1. inspect the final diff and `git diff --check`;
2. verify `git ls-files .traffic-e2e/local` and the staged diff contain no local
   migration artifact;
3. commit only intended migration, stable `.traffic-e2e/e2e.yaml` project
   metadata changes, applicable verified cross-scope lessons, and one concise
   changelog entry for this delivered increment;
4. require no uncommitted intended-scope change after the commit;
5. push the feature branch;
6. open a PR to `pr_base`;
7. independently verify the remote branch, commit SHA, PR URL, and PR base.

Delivery requires the focused commit on the remote feature branch and a
verified PR whose base equals `pr_base`. Missing credentials, remote access, or PR authority is
`blocked_delivery`; retain the useful local state and report the exact blocker.
An incremental PR does not make incomplete or blocked replay evidence complete;
report every unresolved blocker accurately.

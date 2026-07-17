# Git And PR Delivery

Read this reference when choosing the migration branch and again when delivering
the verified change.

## Resolve The Integration Branch

Resolve the PR base in this order:

1. the user's explicit instruction;
2. target `AGENTS.md` or linked repository documentation;
3. an existing repository migration configuration or documented integration
   branch;
4. the hosting repository's default branch when it is clearly the intended
   integration target.

If these sources disagree or no intended base can be established, stop and ask.
Never assume a universal integration branch name for a generic target.

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
- Do not commit a completed migration directly to the resolved base branch.
- Keep `.migration/local/` ignored. Never stage, commit, or force-add its run
  state, reports, logs, sessions, PIDs, or temporary files.

## Deliver The Increment

Deliver useful focused changes after the applicable target quality checks and
evidence audit, even when recorded E2E leaves the migration `incomplete` or
`blocked`. A blocker prevents a completion claim, but does not prevent commit,
push, or PR creation.

1. inspect the final diff and `git diff --check`;
2. verify `git ls-files .migration/local` and the staged diff contain no local
   migration artifact;
3. commit only intended migration, stable `.migration/e2e.yaml` project
   metadata changes, applicable verified cross-scope lessons, and one concise
   changelog entry for this delivered increment;
4. require no uncommitted intended-scope change after the commit;
5. push the feature branch;
6. open a PR to the resolved integration branch;
7. independently verify the remote branch, commit SHA, PR URL, and PR base.

A local branch, local commit, push without a PR, or prose saying a PR is planned
is not delivery. Missing credentials, remote access, or PR authority is
`blocked_delivery`; retain the useful local state and report the exact blocker.
An incremental PR does not make incomplete or blocked replay evidence complete;
report every unresolved blocker accurately.

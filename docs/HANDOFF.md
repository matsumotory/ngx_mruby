# Handoff: the state of the work

## How to use this file

This file records where the work on ngx_mruby stands, so that any session,
clone or contributor can continue it: the open pull requests, the decisions
that are not written down elsewhere yet, the work in progress and the queue.

- It records state, not rules. The rules are in [AGENTS.md](../AGENTS.md).
  The plan for v3 and the owner's decisions about it are in
  [docs/proposals/v3-plan.md](proposals/v3-plan.md). Where this file
  disagrees with them, they win, except for a dated row under "Decisions"
  that is newer than their text: it holds until it is written there.
- A decision of the owner that is not written there yet is recorded under
  "Decisions" below, in short, with the place where it will be written. Where
  the sessions apply a decision with a procedure of their own, the row names
  that procedure separately.
- This file is updated at every milestone: a merge or a decision that
  changes a list below, or a release. A pull request on `next` updates it
  in the same pull request. A pull request on `master` cannot, because the
  file is only on `next`: after the merge, the session that merged it
  updates the file in a small pull request on `next`, or in the merge of
  `master` into `next` if that comes first. Link pull requests and issues
  instead of copying their text.
- Remove an item when its pull request is merged or closed, when its issue is
  closed, or when it is written in the place that its row names. The pull
  requests and issues keep the history (see the `gh` commands below).
- The file lives on `next`. From a checkout of another branch, read it with
  `git fetch origin next` and `git show origin/next:docs/HANDOFF.md`.
- The statements about branches, pull requests and issues were checked with
  `gh` and `git` at the time in the next heading. Check them again before you
  act on them: other sessions merge pull requests all the time.

## State as of 2026-10-04 (16:17 JST)

Heads: `next` is `ec22740` (merge of #565), `master` is `2966465` (merge of
#564), and `v2.x` mirrors `master` (`2966465`).

Open pull requests, all drafts:

| PR | Base | Change | Stage |
|---|---|---|---|
| #561 | `next` | Bundle mruby 4.0.0 | Three review rounds, no "must fix" left. Before the merge: the performance follow-up and the move of the mruby-uname pin (both in the queue; the `perf` check fails on `82a1577`, see "Work in progress"), the note next to item 1 of section 7 of the plan (see "Decisions"; #561 does not change `docs/proposals/` yet), and the owner's approval of the expectation commit `df1d9b8bd` (question 2 at the top of the PR), which AGENTS.md "Writing tests" requires. That approval is not recorded yet: it still waits for the owner. The answer to question 1 is under "Decisions". |
| #563 | `master` | Stop the recursion between a content handler and a header filter in the same location (#206) | Three review rounds; the re-review of `67fbed1` leaves no "must fix". CI passed. Its author holds the merge and keeps it a draft, as [its comment of 16:08 JST](https://github.com/matsumotory/ngx_mruby/pull/563#issuecomment-5977578661) says. |
| #566 | `master` | Answer 500 instead of no response when a content handler writes nothing (#225, refs #200) | Narrowed to the fix of the hang and rebased onto `2966465` (head `71da105`). The author answered the review of `c51756f` at 16:03 JST; it waits for a review of `71da105`. CI passed. |
| #568 | `master` | The branch strategy in README.md, the 2.x support period in SECURITY.md, and how v3 is promoted to `master` in `docs/DEVELOPMENT.md` | Re-reviewed at `11864b4` with no "must fix". `1890306` applies the should-fix items; it waits for CI on that commit. |
| #569 | `next` | This file | Re-reviewed at `188d548`: two "must fix" (the state rows and the #321 row). The head applies them; it waits for the re-review of those rows. Merges before #570. |
| #570 | `master` | AGENTS.md sections on the design principles, on the owner's mrbgem repositories, and on the session handoff, which points to this file | Reviewed at `fe0c87c`: two "must fix" are open. CI passed. Merges after #569, so that AGENTS.md on `master` never names a file that is missing on `next`. |
| #571 | `next` | Proposal for the site at ngx.mruby.org and the documentation it is built from (`docs/proposals/site.md`) | Not reviewed yet. CI runs. |

Merged pull requests: `gh pr list --state merged --base master --search
'merged:>=2026-10-03' --limit 200`, and the same with `--base next`. Each
pull request says what it changed.

## Decisions

Decisions of the owner that are not yet written in the place their row names:

| Date | Decision | Where it is written |
|---|---|---|
| 2026-10-04 | The 2.x line puts compatibility first: stability and security fixes only, and observable behavior changes only as far as the fix of a defect requires, each with a release notes entry | AGENTS.md on `master` (#564); on `next` after the next merge of `master` into `next` |
| 2026-10-04 | Every observable behavior change gets a release notes entry: before, now, what is affected, what to do, and why the fix had to change the behavior, in English and Japanese | `docs/releases/README.md` on `master` (#564) has before, now, affected and what to do; the reason and the Japanese text are in the queue |
| 2026-10-04 | The branch names and structure stay as they are | AGENTS.md (unchanged); README.md, SECURITY.md and `docs/DEVELOPMENT.md` after #568 |
| 2026-10-04 | Design principles: one `mrb_state` per worker; no blocking; keep the existing performance; measure performance regularly. The sessions' procedure for the last two: a change on the request path is compared with the callgrind lane (`test/perf`) | AGENTS.md on `master` when #570 merges; this file until then. #561 is held by the third principle |
| 2026-10-04 | mruby on `next`: 4.0.0 first, then 4.1.0 when it is tagged, with Prism vendored as a subset, mruby-encoding out of the default build, and mruby-onig-regexp kept for v3.0 | This file; #561 adds a note to item 1 of section 7 of the plan before it merges |
| 2026-10-04 | Sessions may change the owner's mrbgem repositories, mruby-uname included. The sessions' procedure: a pull request in the gem's repository, reviewed by a separate agent and merged with a merge commit, as for matsumotory/mruby-uname#1 | AGENTS.md on `master` when #570 merges; this file until then |
| 2026-10-04 | The site at ngx.mruby.org (branch `gh-pages`, last changed 2020-09-22) is redesigned. The sessions' procedure: a design survey and a proposal before the implementation | The proposal of #571 (`docs/proposals/site.md` on `next`) when it merges; this file until then |

## Work in progress

### mruby update on `next`

- #561 bundles mruby 4.0.0. It pins matsumotory/mruby-uname to commit
  `c82f8a6` of the gem's branch `mruby-4`. That fix merged into the gem's
  `master` as `50031c8` (matsumotory/mruby-uname#1), and the pin moves there
  in a commit of #561 (queue). Until then, the branch `mruby-4` must not be
  deleted or rewritten.
- #561 is held for performance: the measurement, the cause and the plan are
  in [the comment that holds the merge](https://github.com/matsumotory/ngx_mruby/pull/561#issuecomment-5977240671).
  The follow-up that it waits for is in the queue; no pull request for it
  is open yet.
- 4.1.0 waits for its tag (the latest mruby tag on 2026-10-04 is
  `4.1.0-rc2`). Besides the three choices under "Decisions", #561 lists what
  that step has to do: the counted GC registrations (every register matched by
  one unregister; the stream path is not audited yet), the HAL gem names that
  4.1 drops, and the core gems of 4.1 that collide with third-party gems.

### Issue triage of 2026-10-04

The closed issues: `gh issue list --state closed --search
'closed:>=2026-10-04' --limit 200`. The reason is in the last comment of
each issue, or in the pull request that closed it.

Taken up:

| Issue | Disposition |
|---|---|
| #200, #225 | `master`: #566 answers 500 instead of no response (#225). `next`: the answer 200 with `Content-Length: 0` (#200), in a later pull request (the plan accepts "empty 200 allowed" for v3, section 7, item 8). |
| #206 | #563 (`master`) |
| #321 | Needs a design decision of the owner. Not scheduled. |
| #502 | Pillar B (core design) of the v3 plan, not recorded there yet. Reproduced on `master`; the result and the two options for the owner are in [the triage comment](https://github.com/matsumotory/ngx_mruby/issues/502#issuecomment-5977615799). The measurement that the sessions propose before the decision is in the queue. |

### The next 2.x release

The next 2.x release (2.7.1) is being prepared through the security process
of [SECURITY.md](../SECURITY.md).

## Queue

| Follow-up | Target branch | Waits for |
|---|---|---|
| Merge `master` into `next`, after merges into `master`. Model: #553 (branch `merge/master-into-next-20261004b`). The rows here that say "reaches `next` by the next merge", the #200 row and the decision on the 2.x line wait for it. | `next` | Ready to start: `master` is ahead of `next` by #562 and #564 |
| A pointer to this file in AGENTS.md (`git show origin/next:docs/HANDOFF.md`), so that a session on the default branch finds it | `master` (reaches `next` by the next merge) | In #570, which merges after this pull request (#569) |
| AGENTS.md section on the design principles and on changing the owner's mrbgem repositories | `master` (reaches `next` by the next merge) | In #570 |
| Release notes: the reason each behavior change was needed, and a Japanese text next to the English one (`docs/releases/README.md`) | `master` | Ready to start |
| Restore `mruby-redis` in the default build with `hiredis` pinned to a release tag (plan section 5 and section 7, item 5; no later decision changes it). `master` commits no gem lock, and the gem's [`mrbgem.rake`](https://github.com/matsumotory/mruby-redis/blob/5895adbaa9fcc6e9f76b1aa1f967dbae5ff52c02/mrbgem.rake#L24-L26) clones `hiredis` unpinned (it checks out `v0.13.3` only on Darwin). First step: a pull request in matsumotory/mruby-redis that pins the clone, under the decision on the owner's mrbgem repositories; the other way is a pinned clone of `hiredis` in the build of ngx_mruby. Then a pull request to `master` enables the gem in `build_config.rb`. | `master` | Ready to start |
| Port the perf lane (`test/perf`, `test/build_release.sh`, the `perf` CI job) to `master`, so that 2.x fixes are measured. It needs `test/soak/http_client.rb`, `test/soak/scenarios.rb` and the configuration `test/soak/nginx.conf`, which exist only on `next`. That configuration calls `Nginx::Debug`, which the perf build leaves out (it is built only with `NGX_MRUBY_DEBUG_STATS`) and which 2.x must not add (the 2.x policy), so the port must work without it. | `master` | The owner: no decision puts the port in the scope of 2.x yet. The sessions recommend it: it changes only tests and CI, as #530 did. |
| The answer 200 with an empty body (#200) | `next` | #566 merged, then merged into `next` |
| A row of the v3 plan for #502, then close #502 | `next` | Ready to start |
| For the owner's decision on #502: measure what running handler code in a method or lambda frame changes (`self`, local variables, constant lookup) and what it costs in the perf lane | `next` | Ready to start |
| Site: a proposal from a design survey, then the implementation | Proposal: `next` (`docs/proposals/`). Implementation: `gh-pages`, which the branch table of AGENTS.md does not cover yet | The proposal is #571. The implementation waits for its review and for the owner's answers to the open questions in its section 7. |
| Intern the fixed names once at initialization instead of on every request (`mrb_intern_cstr` in `ngx_mrb_get_class_obj`, `ngx_mrb_get_request_var` and the `Nginx::Var` path), measured against `next` on mruby 3.3 | `next` | Ready to start; #561 waits for it |
| Move the mruby-uname pin of #561 to `50031c8` on the gem's `master` | `next` (#561) | Ready to start |
| mruby 4.1.0 | `next` | The 4.1.0 tag and #561 |

## How a session continues

1. Fetch first (`git fetch origin`) and work from `origin/<base>`: local
   checkouts fall behind as other sessions merge.
2. One `git worktree` per task, on a branch `claude/<topic>` made from
   `origin/<base>` (see [CLAUDE.md](../CLAUDE.md)).
3. Follow [AGENTS.md](../AGENTS.md): the branch table, the two commits of a
   bug fix, the review checklist and the merge conditions.
4. Builds and tests are run on Linux. On macOS, build a Linux container that
   matches CI: [.github/workflows/test.yml](../.github/workflows/test.yml)
   runs on `ubuntu-22.04` and installs its packages in the `apt-get install`
   lines (valgrind among them: the `build` job runs nginx under valgrind,
   and the `perf` job uses it for callgrind). The root `Dockerfile` is a
   runtime image, not this environment. Run one `test.sh` per machine at a
   time.
5. Before you act on a pull request, read its newest comments: reviews and the
   author's answers are posted there.
6. To take over an open pull request from another session (one that stopped,
   or one on another machine), post a comment on it that takes it over from
   its head commit, then push.
7. When you start a row of the queue, first push a `claude/<topic>` branch
   or open a draft pull request, so that a session on another machine sees
   the work and does not start it again. Name it in the row: in your own
   pull request when its base is `next`, otherwise in the next update of
   this file.
8. Possible vulnerabilities go to the security process of
   [SECURITY.md](../SECURITY.md), never into issues, pull requests, commit
   messages or this file.
9. When your work changes a list in this file, update it as "How to use
   this file" says (for a pull request on `master`, after the merge).

## Private material

Vulnerability reports and their fixes are handled privately as
[SECURITY.md](../SECURITY.md) describes; this file does not record them.

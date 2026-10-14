# Handoff: the state of the work

## How to use this file

This file records where the work on ngx_mruby stands, so that any session,
clone or contributor can continue it: the open pull requests, the decisions
that are not written down elsewhere yet, the work in progress and the queue.

- It records state, not rules. The rules are in [AGENTS.md](../AGENTS.md).
  The plan for v3 and the owner's decisions about it are in
  [docs/proposals/v3-plan.md](proposals/v3-plan.md). Where this file
  disagrees with them, they win, with the one exception that AGENTS.md
  "Session handoff" sets: a dated row under "Decisions" holds over their
  older text until a pull request writes it there, but only when the row
  links the owner's comment or quotes the owner's words. A row with neither
  is a proposal of the sessions and changes no rule.
- A decision of the owner that is not written there yet is recorded under
  "Decisions", in short, with its date, the link or the quotation, and the
  place where it will be written. Where the sessions apply a decision with
  a procedure of their own, the row names that procedure separately.
- A pull request on `next` updates this file in the same pull request when
  it changes what the file records, its own row and the queue item that it
  finishes included. A pull request on `master` cannot, because the file is
  only on `next`: the session that merged it into `master` opens a small
  pull request on `next` that updates the file, or updates the file in the
  merge of `master` into `next` if that comes first. A release is recorded
  in the same way by the first session that finds its tag missing here.
  Link pull requests and issues instead of copying their text.
- Remove an item when its pull request is merged or closed, when its issue
  is closed, or when it is written in the place that its row names. The
  pull requests and issues keep the history (see the `gh` commands below).
- The file lives on `next`. From a checkout of another branch, read it with
  `git fetch origin next` and `git show origin/next:docs/HANDOFF.md`.
- The statements about branches, pull requests and issues were checked with
  `gh` and `git` at the time in the next heading. Check them again before
  you act on them: other sessions merge pull requests all the time.

## State as of 2026-10-14 (17:36 JST)

Heads: `next` is `570cdab` (merge of #571), `master` is `b3df70f` (merge of
#570, unchanged since 2026-10-04), and `v2.x` mirrors `master` (`b3df70f`).
`next` contains `master`: #573 merged `master` at `b3df70f` into `next`.

Merged on 2026-10-14, into `next`: #572 (the fixed symbol names interned
once, `bc2488a`) and #571 (the site proposal `docs/proposals/site.md`,
`570cdab`). Merged on 2026-10-04: into `next` #560, #565 and #573 (`master`
into `next`); into `master` #562, #564, #566, #568 and #570. The full
lists: `gh pr list --state merged --base next --search
'merged:>=2026-10-03' --limit 200`, and the same with `--base master`. Each
pull request says what it changed.

Open pull requests, all drafts:

| PR | Base | Change | Stage |
|---|---|---|---|
| #561 | `next` | Bundle mruby 4.0.0 | Held for performance by [its hold comment](https://github.com/matsumotory/ngx_mruby/pull/561#issuecomment-5977240671). [The record of the owner's answers](https://github.com/matsumotory/ngx_mruby/pull/561#issuecomment-5977746245) to its two questions: mruby 4.0.0 first (see "Decisions"), and the expectation commit approved with the migration note. Being rebased onto `next` after #572, with the mruby-uname pin on the gem's `master`, and measured again (queue); not on origin yet. Before the merge it adds the note next to item 1 of section 7 of the plan. CI on `82a1577` fails only `perf`. |
| #563 | `master` | Stop the recursion between a content handler and a header filter in the same location (#206) | Three review rounds; the re-review of `67fbed1` leaves no "must fix". It conflicts with `master` at `b3df70f` (AGENTS.md and `docs/releases/v2.7.1.md`). CI passed. Its author holds the merge. |
| #569 | `next` | This file | Re-reviewed at `d1cc25f`: two "must fix" (the #563 row and the state rows) and five "should fix", which a state-only commit applies; it waits for the re-review of the changed rows and for CI. #570 merged first, so AGENTS.md "Session handoff" on both branches names this file, which reaches `next` with this pull request. |
| #574 | `next` | 200 with `Content-Length: 0` for a content handler that ends without output (#200), and an output body filter that ends with an empty body sends the response; creates `docs/releases/v3.0.0.md` | Opened on 2026-10-14. CI passed at `d2c9836`. Waits for the review with the checklist of AGENTS.md and for the owner's answer to the questions in its description, among them the changed expectation of `test/t/cases/filter_connection.rb` ("an empty String closes the connection without a response"). |

## Decisions

Decisions of the owner that are not yet written in the place their row names:

| Date | Decision | Where it is written |
|---|---|---|
| 2026-10-04 | mruby on `next`: 4.0.0 first, then 4.1.0 when it is tagged, with Prism vendored as a subset, mruby-encoding out of the default build, and mruby-onig-regexp kept for v3.0. Linked: [the record on #561](https://github.com/matsumotory/ngx_mruby/pull/561#issuecomment-5977746245). | Item 1 of section 7 of the plan on `next`: #561 adds the note before it merges; this file until then |
| 2026-10-04 | Recorded by the session from the owner's instruction in chat: every behavior change entry also states why the fix had to change the behavior, and the release notes are written in English and Japanese. | Not yet in `docs/releases/README.md`; until that pull request (queue) merges, this row is the only record. |

## Work in progress

### mruby update on `next`

- #561 bundles mruby 4.0.0 and pins matsumotory/mruby-uname to commit
  `c82f8a6` of the gem's branch `mruby-4`. The fix merged into the gem's
  `master` as `50031c8` (matsumotory/mruby-uname#1). Until #561 moves the
  pin there, the branch `mruby-4` must not be deleted or rewritten.
- #572 (merged) is the follow-up that #561's hold comment asked for: the
  fixed names are interned once. On mruby 4.0.0, the scenarios that do not
  reach those calls still grow against mruby 3.3 (the tables of #572).
- 4.1.0 waits for its tag: the newest mruby tag on 2026-10-14 is
  `4.1.0-rc2` (`gh api repos/mruby/mruby/tags`). Besides the choices under
  "Decisions", #561 lists what that step has to do: the counted GC
  registrations (every register matched by one unregister; the stream path
  is not audited yet), the HAL gem names that 4.1 drops, and the core gems
  of 4.1 that collide with third-party gems.

### Issue triage of 2026-10-04

The closed issues (16, among them #225 closed by #566, #320 by #565 and
#519 by #562): `gh issue list --state closed --search
'closed:>=2026-10-04' --limit 200`. The reason is in the last comment of
each issue, or in the pull request that closed it.

Taken up and still open:

| Issue | Disposition |
|---|---|
| #200 | `master` answers 500 since #566. `next`: 200 with `Content-Length: 0` for an empty body in #574 (the plan accepts "empty 200 allowed" for v3, section 7, item 8). GitHub closes the issue only when the fix reaches `master`, so the session that merges #574 closes it by hand. See [the status comment](https://github.com/matsumotory/ngx_mruby/issues/200#issuecomment-5977863245). |
| #206 | #563 (`master`) |
| #321 | Needs a design decision of the owner. Not scheduled. |
| #502 | Pillar B (core design) of the v3 plan, not recorded there yet. Reproduced on `master`; the result and the two options for the owner are in [the triage comment](https://github.com/matsumotory/ngx_mruby/issues/502#issuecomment-5977615799). The measurement that the sessions propose before the decision is in the queue. |

### The next 2.x release

The next 2.x release is being prepared. When it is tagged, its release
notes in [docs/releases/](releases/) list what it contains.

## Queue

| Follow-up | Target branch | Waits for |
|---|---|---|
| Merge `master` into `next` after each merge into `master`. Model: #573. | `next` | The next merge into `master`: `next` contains `master` (`b3df70f`) now |
| `docs/releases/README.md`: add the 'why it changed' part of each entry and the Japanese version of the notes (see "Decisions") | `master`, a small docs pull request (reaches `next` by the merge of `master` into `next`) | #575 (draft). When it merges, `docs/releases/v3.0.0.md` (#574) needs its Japanese version too |
| The check of `docs/releases/README.md` "Before the tag" for the next 2.x release: `docs/releases/v2.7.1.md` against every pull request merged into `master` since v2.7.0, adding the missing entries (#562 has none yet), with the perf comparison against the tag that AGENTS.md "Design principles" asks for | `master` | Before the owner tags; pull requests merged after it are checked again |
| Add to `docs/releases/v3.0.0.md` the entries of the pull requests merged into `next` before #574 (the merges of `master` excepted), as `docs/releases/README.md` "File names" says. #574 creates the file with its own two entries only. | `next` | #574 |
| The case that #566 leaves without a response: output, then a status below 300 other than 200, 201 and 204 ([the re-review of #566](https://github.com/matsumotory/ngx_mruby/pull/566#issuecomment-5977670159), should fix 5) | `master` | Ready to start: a test commit, then a fix commit |
| Restore `mruby-redis` in the default build with `hiredis` pinned to a release tag (plan section 5 and section 7, item 5): first a pin in matsumotory/mruby-redis or in ngx_mruby's build ([the re-review of #569](https://github.com/matsumotory/ngx_mruby/pull/569#issuecomment-5977574834), should fix 6), then a pull request to `master` that enables the gem in `build_config.rb` | `master` | Ready to start |
| Port the perf lane (`test/perf`, `test/build_release.sh`, the `perf` job) to `master`, without `Nginx::Debug` (what it needs: [the review of #569](https://github.com/matsumotory/ngx_mruby/pull/569#issuecomment-5977395918), should fix 5). Until then AGENTS.md "Design principles" measures `master` changes with the lane of `next`. | `master` | The owner: no decision puts it in the scope of 2.x yet. The sessions recommend it: tests and CI only, as #530 was. |
| `test.sh` waits a fixed `NGINX_HEATTIME` for nginx; wait until it listens on the test ports, as `wait_for_listen` in `test/t/cases/_second_instance.rb` does (a valgrind cell failed with `Errno::ECONNREFUSED` before nginx listened, [#564](https://github.com/matsumotory/ngx_mruby/pull/564#issuecomment-5977252444)), and update `docs/test/README.md` | `master` (reaches `next` by the merge) | Ready to start |
| CI: also grep the `stderr.log` files for sanitizer reports. The `Check for sanitizer reports` step of `.github/workflows/test.yml` reads only `build/nginx/logs/error.log`; `stderr.log` there holds the test client's stderr, and under `build/nginx/second_instance/` the second nginx's. | `master` (reaches `next` by the merge) | Ready to start |
| 200 with `Content-Length: 0` for an empty body (#200), as nginx's own `return 200;` does | `next` | #574 (draft) |
| The output body filter that ends with an empty body sends a zero size buffer marked as memory, and the client gets no byte (`Nginx::Filter#output ""`, pinned by `test/t/cases/filter_connection.rb` on `master`): the same change to `ngx_mrb_finalize_body_filter` as in #574, as a 2.x stability fix | `master` (reaches `next` by the merge) | The owner's answer to the question on #574 |
| `Nginx::Async.sleep` in a content handler ends the request without any response, with or without output after the sleep (found while testing #574). The docs list sleep for the set, rewrite and access handlers only: raise there as the output filters do, or let nginx wait for the timer. Checked on `next` only | `master` if it has the same defect (it reaches `next` by the merge), otherwise `next` | Ready to start: a test commit, then a fix commit |
| Subrequests: the content handler of a subrequest that returns `Nginx::HTTP_OK` without output still sets status 500, where nginx's `return 200;` gives 200. Answering 200 there would make `auth_request` allow such a request (#574 keeps the 500) | `next` | The owner's decision (the question on #574) |
| A row of the v3 plan for #502, then close #502 | `next` | Ready to start |
| For the owner's decision on #502: measure what running handler code in a method or lambda frame changes (`self`, local variables, constant lookup) and what it costs in the perf lane | `next` | Ready to start |
| An end-to-end benchmark scenario: throughput and p50 and p99 latency with `oha` or `h2load`, planned in AGENTS.md "Design principles" and in section 8 of the plan, which also records the reference proxy end to end | `next` | Ready to start; where the results are recorded is decided when it is added (AGENTS.md) |
| Site: the implementation, in the steps of [section 6 of the proposal](proposals/site.md#6-implementation-plan) | `next` (`site/`, as Q1 proposes); steps 6 and 7 also change `master` | The owner's answers to [the open questions](proposals/site.md#7-open-questions); each step names the ones it needs |
| Before the switch of ngx.mruby.org (step 7 of the site proposal), the owner has an item to do in the Pages settings for the custom domain | Repository settings | The owner |
| Move the mruby-uname pin of #561 to `50031c8` on the gem's `master` | `next` (#561) | #561's next revision (being rebased; not on origin yet) |
| #561's remaining performance difference after #572: measure the rebased branch against `next` and quote the table; it merges by the rule of its hold comment | `next` (#561) | The same revision |
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
5. Before you act on a pull request, read its newest comments: reviews and
   the author's answers are posted there.
6. To take over an open pull request from another session (one that
   stopped, or one on another machine), post a comment on it that takes it
   over from its head commit, then push.
7. Before you start a row of the queue, look for it with
   `gh pr list --state open` and `git ls-remote origin 'refs/heads/claude/*'`:
   another session may have started it. Then push a `claude/<topic>` branch
   or open a draft pull request, so that a session on another machine sees
   the work, and name it in the row: in your own pull request when its base
   is `next`, otherwise in the next update of this file.
8. Possible vulnerabilities go to the security process of
   [SECURITY.md](../SECURITY.md), never into issues, pull requests, commit
   messages or this file.
9. When your work changes a list in this file, update it as "How to use
   this file" says. For a pull request on `master`, the session that merged
   it opens the update on `next`.

## Private material

Vulnerability reports and their fixes are handled privately as
[SECURITY.md](../SECURITY.md) describes; this file does not record them.

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

## State as of 2026-10-15 (14:05 JST)

Heads: `next` is the merge of #584, whose first parent is `982a20e`
(merge of #583, whose first parent is `acdc82f`, the merge of #582),
`master` is `0a1e8ac` (merge of #578), and `v2.x` mirrors `master`
(`0a1e8ac`). `next` contains `master`.

Merged on 2026-10-15, into `next`: #584 (the regression test of #502,
`test/t/cases/return_in_block.rb` on 18117, its entry in the 3.0.0 release
notes and the migration guide, and the owner's decision on the frame of
handler code as item 14 of section 7 of the plan), #583 (the proposal
`docs/proposals/handler-code-frame.md` for #502, and one sentence in the
`private` entry of the 3.0.0 release notes and in the migration guide: a
top-level `def` in handler code stays public, `982a20e`) and #582 (the
release notes for 3.0.0 of the pull requests merged before
`docs/releases/v3.0.0.md` existed, `Set#flatten_merge`, the migration guide
and `docs/releases/v3.0.0.ja.md`, `acdc82f`).
Merged on 2026-10-14, into `next`: #572 (the fixed symbol names interned
once, `bc2488a`), #571 (the site proposal `docs/proposals/site.md`,
`570cdab`), #569 (this file, `e0dfdc6`), #561 (mruby 4.0.0, `0b76bfa`),
#577 (the proposal `docs/proposals/nginx-var-method-lookup.md`, `53e8d39`),
#579 (`master` at `b017496` into `next`, `7696e1c`) and #580 (`master` at
`0a1e8ac` into `next`, `dcd3103`); into `master`:
#576 (`.gitignore` and `CLAUDE.md`, `9be7f02`), #575 (the "Why it changed"
lines and the Japanese file of the release notes, `b017496`) and #578 (the
`files` job of CI, `test/check_added_files.sh`, `0a1e8ac`). Merged on
2026-10-04: into `next` #560, #565 and #573 (`master` into `next`); into
`master` #562, #564, #566, #568 and #570. The full lists: `gh pr list
--state merged --base next --search 'merged:>=2026-10-03' --limit 200`, and
the same with `--base master`. Each pull request says what it changed.

Open pull requests, all drafts:

| PR | Base | Change | Stage |
|---|---|---|---|
| [#563](https://github.com/matsumotory/ngx_mruby/pull/563) | `master` | Stop the recursion between a content handler and a header filter in the same location (#206) | Three review rounds; the re-review of `67fbed1` leaves no "must fix". It conflicts with `master` at `0a1e8ac` (AGENTS.md and `docs/releases/v2.7.1.md`). CI passed. Its author holds the merge. Since #575, adding its entry to `docs/releases/v2.7.1.md` also means creating `docs/releases/v2.7.1.ja.md`, unless another pull request has created it first ("Who writes the entries, and when" in `docs/releases/README.md`). |
| [#574](https://github.com/matsumotory/ngx_mruby/pull/574) | `next` | Answer 200 with `Content-Length: 0` when a content handler sends no body (#200) | A draft that waits for the next merge of `master` into `next` after the next 2.x release, then a full review round. It conflicts with `next` (it also creates `docs/releases/v3.0.0.md`, which #561 created); its entries go into that file and, since #582, into `docs/releases/v3.0.0.ja.md` too. |
| [#581](https://github.com/matsumotory/ngx_mruby/pull/581) | `master` | Run the `nginx -s quit` of `test/t/ngx_mruby.rb` with `detect_leaks=0`, as `nginx_t` runs `nginx -t` | One review round; the author's changes are at `eef5fd9`, where CI passed. Its author holds the merge. It comes before the queue row that greps the `stderr.log` files for sanitizer reports. |

## Decisions

Decisions of the owner that are not yet written in the place their row
names: none. The two decisions of 2026-10-04 that were recorded here are
written where their rows said: the mruby steps in item 1 of section 7 of
[the plan](proposals/v3-plan.md) (#561), and the "Why it changed" lines and
the Japanese release notes in [docs/releases/README.md](releases/README.md)
(#575).

## Work in progress

### mruby update on `next`

- #561 (merged, `0b76bfa`) bundles mruby 4.0.0. Its lock pins
  matsumotory/mruby-uname to `50031c8` on the gem's `master` (the merge of
  matsumotory/mruby-uname#1), so no build depends on the gem's branch
  `mruby-4`. The owner accepted the `perf` FAIL rows that remained after
  #572:
  [the record on #561](https://github.com/matsumotory/ngx_mruby/pull/561#issuecomment-6165028832).
  #577 (merged) is the proposal for the `var` and `auth` rows; its
  implementation is in the queue.
- 4.1.0 waits for its tag: the newest mruby tag on 2026-10-14 is
  `4.1.0-rc2` (`gh api repos/mruby/mruby/tags`). The choices for that step
  are in item 1 of section 7 of the plan. #561 lists what the step has to
  do: the counted GC registrations (every register matched by one
  unregister; the stream path is not audited yet), the HAL gem names that
  4.1 drops, and the core gems of 4.1 that collide with third-party gems.

### Issue triage of 2026-10-04

The closed issues (16, among them #225 closed by #566, #320 by #565 and
#519 by #562): `gh issue list --state closed --search
'closed:>=2026-10-04' --limit 200`. The reason is in the last comment of
each issue, or in the pull request that closed it.

Taken up and still open:

| Issue | Disposition |
|---|---|
| #200 | `master` answers 500 since #566. `next`: 200 with `Content-Length: 0` for an empty body, in [#574](https://github.com/matsumotory/ngx_mruby/pull/574) (see "Open pull requests"; the plan accepts "empty 200 allowed" for v3, section 7, item 8). See [the status comment](https://github.com/matsumotory/ngx_mruby/issues/200#issuecomment-5977863245). |
| #206 | #563 (`master`) |
| #321 | Needs a design decision of the owner. Not scheduled. |
| #502 | Reproduced on `master` (mruby 3.3.0, [the triage comment](https://github.com/matsumotory/ngx_mruby/issues/502#issuecomment-5977615799)). On `next` the two locations answer 302 since mruby 4.0.0 (#561); #584 pins it with a test and records it in the 3.0.0 release notes. The owner decided on 2026-10-15 to keep the top-level frame (section 7, item 14, of the plan, after [the proposal for the frame of handler code](proposals/handler-code-frame.md)). What remains is the note in the docs of `master` (the queue); #502 is closed when it is merged. |

### The next 2.x release

The next 2.x release is being prepared. When it is tagged, its release
notes in [docs/releases/](releases/) list what it contains.

## Queue

| Follow-up | Target branch | Waits for |
|---|---|---|
| Merge `master` into `next` after each merge into `master`. Model: #573. | `next` | The next merge into `master` after #580, which merged `master` at `0a1e8ac` into `next` |
| The check of `docs/releases/README.md` "Before the tag" for the next 2.x release: `docs/releases/v2.7.1.md` against every pull request merged into `master` since v2.7.0, adding the missing entries (#544, #562 and #578 have none yet; #578's entry under "Build and test changes" is added in this check, as #578 says; #544 brought the fragment and case harness and the 18xxx test ports to `master`, which #534 and #545 brought to `next`, and #582 leaves their entry to this file), with the perf comparison against the tag that AGENTS.md "Design principles" asks for | `master` | Before the owner tags; pull requests merged after it are checked again |
| The case that #566 leaves without a response: output, then a status below 300 other than 200, 201 and 204 ([the re-review of #566](https://github.com/matsumotory/ngx_mruby/pull/566#issuecomment-5977670159), should fix 5) | `master` | Ready to start: a test commit, then a fix commit |
| Restore `mruby-redis` in the default build with `hiredis` pinned to a release tag (plan section 5 and section 7, item 5): first a pin in matsumotory/mruby-redis or in ngx_mruby's build ([the re-review of #569](https://github.com/matsumotory/ngx_mruby/pull/569#issuecomment-5977574834), should fix 6), then a pull request to `master` that enables the gem in `build_config.rb` | `master` | Ready to start |
| Port the perf lane (`test/perf`, `test/build_release.sh`, the `perf` job) to `master`, without `Nginx::Debug` (what it needs: [the review of #569](https://github.com/matsumotory/ngx_mruby/pull/569#issuecomment-5977395918), should fix 5). Until then AGENTS.md "Design principles" measures `master` changes with the lane of `next`. | `master` | The owner: no decision puts it in the scope of 2.x yet. The sessions recommend it: tests and CI only, as #530 was. |
| `test.sh` waits a fixed `NGINX_HEATTIME` for nginx; wait until it listens on the test ports, as `wait_for_listen` in `test/t/cases/_second_instance.rb` does (a valgrind cell failed with `Errno::ECONNREFUSED` before nginx listened, [#564](https://github.com/matsumotory/ngx_mruby/pull/564#issuecomment-5977252444)), and update `docs/test/README.md` | `master` (reaches `next` by the merge) | Ready to start |
| CI: also grep the `stderr.log` files for sanitizer reports. The `Check for sanitizer reports` step of `.github/workflows/test.yml` reads only `build/nginx/logs/error.log`; `stderr.log` there holds the test client's stderr, and under `build/nginx/second_instance/` the second nginx's. | `master` (reaches `next` by the merge) | Ready to start |
| 200 with `Content-Length: 0` for an empty body (#200), as nginx's own `return 200;` does: [#574](https://github.com/matsumotory/ngx_mruby/pull/574) | `next` | #574 is a draft that waits for the next merge of `master` into `next` after the next 2.x release, then a full review round |
| #502: a note in the docs of `master` on a `return` inside a block or a `for` body of handler code: in 2.x it raises `LocalJumpError`, which `error.log` records, and the handler answers 500, or 200 with the output that a content handler wrote before it; the two ways around it are a `return` at the top level of the code and the code in a method or a lambda; 3.0.0 accepts the `return` in a block ([the entry of 3.0.0](releases/v3.0.0.md#a-return-inside-a-block-or-a-for-body-of-handler-code-ends-the-code-561), section 7, item 14, of the plan). Then close #502, whose test and 3.0.0 entry came with #584 | `master` | The next 2.x release: `master` is held for it |
| `README.md` (line 153) and `docs/README.md` (line 76), the abstract of the paper, say that the server process frees the global variables table between scripts. On `next` and `master`, globals, constants, instance variables of `main`, methods and classes persist in a worker from one request to the next, since `ngx_mrb_state_clean` clears only `mrb->exc` (section 1.4 of [the proposal for the frame of handler code](proposals/handler-code-frame.md), measured on both branches in the review of #583). To do: a docs pull request that keeps the abstract and says beside it what persists in a worker today | `master` (reaches `next` by the merge) | Ready to start |
| A rewrite handler that ends without `Nginx.return` (for example `mruby_rewrite_handler_code 'x = 1'` before a content handler, or before nginx's `return 200`) sends no response, and `error.log` has no line at the `error` level: with keep-alive the connection stays open until `keepalive_timeout`, with `Connection: close` it is closed with nothing sent. `ngx_mrb_finalize_rputs` (`src/http/ngx_http_mruby_core.c:179`) returns `NGX_OK` when nothing was sent and no status was set, and the rewrite phase of nginx 1.31.6 finalizes the request on `NGX_OK` (`ngx_http_core_rewrite_phase`), where the access phase goes on to the next handler. Found and measured on `next` and `master` while #583 was written and reviewed; no issue tracks it. To do: for v3, a test commit and a fix under the Pillar B row "Redesign response finalization per phase" of the plan; for 2.x, the owner decides between documenting it and a fix | `next`; `master` after the owner's decision | v3: ready to start; 2.x: the owner |
| An end-to-end benchmark scenario: throughput and p50 and p99 latency with `oha` or `h2load`, planned in AGENTS.md "Design principles" and in section 8 of the plan, which also records the reference proxy end to end | `next` | Ready to start; where the results are recorded is decided when it is added (AGENTS.md) |
| Site: the implementation, in the steps of [section 6 of the proposal](proposals/site.md#6-implementation-plan) | `next` (`site/`, as Q1 proposes); steps 6 and 7 also change `master` | The owner's answers to [the open questions](proposals/site.md#7-open-questions); each step names the ones it needs |
| Before the switch of ngx.mruby.org (step 7 of the site proposal), the owner has an item to do in the Pages settings for the custom domain | Repository settings | The owner |
| The implementation of [the proposal for the method lookup of `Nginx::Var` accessors](proposals/nginx-var-method-lookup.md) (#577): candidates (a) and (d), accessors defined on `Nginx::Var` at the first miss with the rule (a2), and ngx_mruby's own methods that read variables in C, with the tests, docs, release notes entries and the three comparisons of its section 3 | `next` | The owner's answer to the question of section 4 of the proposal (#561 merged as `0b76bfa6d`) |
| mruby 4.1.0 | `next` | The 4.1.0 tag |

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

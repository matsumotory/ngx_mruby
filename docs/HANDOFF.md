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

## State as of 2026-10-19 (19:30 JST)

Heads: `next` is the merge of #595, whose first parent is `a466688`
(merge of #591), whose first parent is `3566595` (merge of #590). #590
merges `master` at `03aad70` into `next`, and #595 merges `master` at
`36f4c82`, so `next` contains every change of `master` except #593 and
#592, which the next merge of `master` into `next` brings (see "Queue").
`master` is `a6c32a4` (merge of #592); `v2.x` mirrors `master`
(`a6c32a4`).

2.7.1 was released on 2026-10-19: the tag `v2.7.1` is on `ce5eb11`, the
merge of the 2.7.1 changes into `master`. Its release notes are
`docs/releases/v2.7.1.md` and `docs/releases/v2.7.1.ja.md`. The next 2.x
release is 2.7.2; its release notes `docs/releases/v2.7.2.md` and
`docs/releases/v2.7.2.ja.md` are on `master` since #589, and on `next`
since #595.

Merged on 2026-10-19, into `next`: #595 (`master` at `36f4c82` into `next`,
with #589; its description lists the conflicts in
`src/http/ngx_http_mruby_var.c` and `AGENTS.md` and how they were
resolved), #591 (site step 1: `site/` with Starlight, the generator of
`docs/`, the checks and `.github/workflows/site.yml`, `a466688`), #590
(`master` into `next` in two merge
commits: `master` at `4091cbd`, with the 2.7.1 changes, #581, #586 and
#587, and then `master` at `03aad70`, with #588; its description lists the
conflicts and how they were resolved, and it makes the texts of #584 and
#586 on a `return` inside a block one text for 3.0.0 and 2.x) and #585 (the
owner's decisions of 2026-10-15 on the site proposal: section 7 of
`docs/proposals/site.md` records them, section 4 derives the design from
the source of three of the owner's sites, 3.5 plans the diagrams and
samples, section 6 says what each step produces and what the owner reviews,
and `contrast.py` checks a second palette, `75bfa6f`). Into `master`: the
2.7.1 changes (`ce5eb11`), #581 (the test harness runs `nginx -s quit` with
`detect_leaks=0`, `edc85f0`), #586 (the note on a `return` inside a block
of handler code in 2.x, `5e7d57e`), #587 (a change of the 2.7.1 release
notes, `4091cbd`), #588 (tests: the request body that a log handler or a
filter sees after nginx ended a body read, and the status 500 after an
exception in an output header filter; and two sentences of
`docs/directives/README.md` on such a handler, `03aad70`), #589
(`Nginx::Var` rejects names and setter calls that name no variable, and
leaves the name passed to `set` unchanged; it creates
`docs/releases/v2.7.2.md` and `docs/releases/v2.7.2.ja.md` and the test
fragment `test/conf/conf.d/67-var-input.conf`; merged at 16:35 JST,
`36f4c82`), #593 (`test.sh` waits until the test nginx listens instead
of sleeping `NGINX_HEATTIME`, with `test/t/cases/_wait_for_listen.rb` and
an entry in `docs/releases/v2.7.2.md`; merged at 17:16 JST, `188d324`)
and #592 (`README.md` and `docs/README.md` say next to the abstract of the
paper what a worker keeps between requests; merged at 19:10 JST,
`a6c32a4`).
#563 was closed
on 2026-10-19: its change is part of 2.7.1 (its last comment). #502 was
closed on 2026-10-19 after #586; its test and its entry in the 3.0.0
release notes came with #584. Merged on
2026-10-15, into `next`: #584
(the regression test of #502,
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
| [#574](https://github.com/matsumotory/ngx_mruby/pull/574) | `next` | Answer 200 with `Content-Length: 0` when a content handler sends no body (#200) | A draft. It merged `next` at `a466688` (#591, after #590, which brought 2.7.1 into `next`). The two reviews of `37accc7` ([tests, release notes, docs](https://github.com/matsumotory/ngx_mruby/pull/574#issuecomment-6264724199); [C change, merges and runs](https://github.com/matsumotory/ngx_mruby/pull/574#issuecomment-6264801287)) have no "must fix"; the head `82c1fdf` applies their other items. The merge waits for the owner's approval of expectation 4 and for the `perf` table on the head (the first review). |
| [#594](https://github.com/matsumotory/ngx_mruby/pull/594) | `master` | Send the output with the status set after it when nginx would not answer it (the case that #566 leaves without a response) | A draft (head `2e3e838`); no review yet. |
| [#596](https://github.com/matsumotory/ngx_mruby/pull/596) | `master` | Release notes: builds that enable mruby-redis get hiredis v1.5.0 ([matsumotory/mruby-redis#108](https://github.com/matsumotory/mruby-redis/pull/108)) | A draft. [The re-review of `6bc2d91`](https://github.com/matsumotory/ngx_mruby/pull/596#issuecomment-6264762363) finds the three "must fix" of the first review fixed; its should fix 1 is applied in `69593a5`, and the head `26eae96` merges `master` at `a6c32a4`. matsumotory/mruby-redis#108 is open. |
| [#597](https://github.com/matsumotory/ngx_mruby/pull/597) | `next` | Update the bundled ngx_devel_kit (`dependence/ngx_devel_kit/`) from v0.3.1 to v0.3.4 with `./update-devkit-subtree v0.3.4` (Pillar A of the plan) | A draft whose description says that the test runs, the release notes and the `perf` comparison are added as they finish; no review yet. |
| [#598](https://github.com/matsumotory/ngx_mruby/pull/598) | `master` | Docs: state the trust boundary (trusted configuration code, untrusted client input) in `docs/README.md`, linked from `README.md`, `docs/README.md` and `SECURITY.md` (Pillar G of the plan) | A draft; no review yet. |

## Decisions

Decisions of the owner that are not yet written in the place their row
names:

| Date | Decision | Where it is written |
|---|---|---|
| 2026-10-19 | The perf lane on `master`: asked in a session which form to port, the owner chose the option "テストと CI だけ移植する" (port the tests and the CI only): `test/perf`, `test/build_release.sh` and the `perf` job, without `Nginx::Debug`. | The pull request that ports the lane to `master` (its description, and `docs/test/README.md` on `master`); see "Queue". |

The two decisions of 2026-10-04 that were recorded here before are written
where their rows said: the mruby steps in item 1 of section 7 of
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
- 4.1.0 waits for its tag: the newest mruby tag on 2026-10-19 is
  `4.1.0-rc2` (`gh api repos/mruby/mruby/tags`). The choices for that step
  are in item 1 of section 7 of the plan. #561 lists what the step has to
  do: the counted GC registrations (every register matched by one
  unregister; the stream path is not audited yet), the HAL gem names that
  4.1 drops, and the core gems of 4.1 that collide with third-party gems.

### Issue triage of 2026-10-04

The closed issues (20 on 2026-10-19, among them #225 closed by #566, #320
by #565 and #519 by #562, and #206, #321 and #502, closed on 2026-10-19):
`gh issue list --state closed --search
'closed:>=2026-10-04' --limit 200`. The reason is in the last comment of
each issue, or in the pull request that closed it.

Taken up and still open:

| Issue | Disposition |
|---|---|
| #200 | `master` answers 500 since #566. `next`: 200 with `Content-Length: 0` for an empty body, in [#574](https://github.com/matsumotory/ngx_mruby/pull/574) (see "Open pull requests"; the plan accepts "empty 200 allowed" for v3, section 7, item 8). See [the status comment](https://github.com/matsumotory/ngx_mruby/issues/200#issuecomment-5977863245). |

## Queue

| Follow-up | Target branch | Waits for |
|---|---|---|
| Merge `master` into `next` after each merge into `master`. Model: #573. | `next` | Ready to start once #595 (`master` at `36f4c82` into `next`) is merged: the next merge brings #593 and #592 (`master` at `a6c32a4`), and whatever is merged into `master` before it |
| The case that #566 leaves without a response: output, then a status below 300 other than 200, 201 and 204 ([the re-review of #566](https://github.com/matsumotory/ngx_mruby/pull/566#issuecomment-5977670159), should fix 5) | `master` | [#594](https://github.com/matsumotory/ngx_mruby/pull/594) (see "Open pull requests") |
| Restore `mruby-redis` in the default build with `hiredis` pinned to a release tag (plan section 5 and section 7, item 5; [the re-review of #569](https://github.com/matsumotory/ngx_mruby/pull/569#issuecomment-5977574834), should fix 6). The pin is [matsumotory/mruby-redis#108](https://github.com/matsumotory/mruby-redis/pull/108) (hiredis v1.5.0), a draft under review. After its merge: a pull request to `master` that enables the gem in `build_config.rb` for 2.7.2, and a pull request to `next` that pins the gem in `build_config.rb.lock` to the merge commit on the gem's `master` (AGENTS.md "Other repositories"; the line in `build_config.rb` reaches `next` with the merge of `master`, and the lock has no entry for the gem today) | `master`, then `next` | The merge of matsumotory/mruby-redis#108 |
| Port the perf lane (`test/perf`, `test/build_release.sh`, the `perf` job) to `master`, without `Nginx::Debug` (what it needs: [the review of #569](https://github.com/matsumotory/ngx_mruby/pull/569#issuecomment-5977395918), should fix 5). Until then AGENTS.md "Design principles" measures `master` changes with the lane of `next`. | `master` | Ready to start: tests and CI only (`test/perf`, `test/build_release.sh`, the `perf` job), without `Nginx::Debug`, as the owner decided on 2026-10-19 (see "Decisions") |
| CI: also grep the `stderr.log` files for sanitizer reports. The `Check for sanitizer reports` step of `.github/workflows/test.yml` reads only `build/nginx/logs/error.log`; `stderr.log` there holds the test client's stderr, and under `build/nginx/second_instance/` the second nginx's. | `master` (reaches `next` by the merge) | Ready to start |
| 200 with `Content-Length: 0` for an empty body (#200), as nginx's own `return 200;` does: [#574](https://github.com/matsumotory/ngx_mruby/pull/574) | `next` | #574: the owner's approval of expectation 4 and the `perf` table on the head (see "Open pull requests") |
| A rewrite handler that ends without `Nginx.return` (for example `mruby_rewrite_handler_code 'x = 1'` before a content handler, or before nginx's `return 200`) sends no response, and `error.log` has no line at the `error` level: with keep-alive the connection stays open until `keepalive_timeout`, with `Connection: close` it is closed with nothing sent. `ngx_mrb_finalize_rputs` (`src/http/ngx_http_mruby_core.c:179`) returns `NGX_OK` when nothing was sent and no status was set, and the rewrite phase of nginx 1.31.6 finalizes the request on `NGX_OK` (`ngx_http_core_rewrite_phase`), where the access phase goes on to the next handler. Found and measured on `next` and `master` while #583 was written and reviewed; no issue tracks it. To do: for v3, a test commit and a fix under the Pillar B row "Redesign response finalization per phase" of the plan; for 2.x, the owner decides between documenting it and a fix | `next`; `master` after the owner's decision | v3: ready to start; 2.x: the owner |
| An end-to-end benchmark scenario: throughput and p50 and p99 latency with `oha` or `h2load`, planned in AGENTS.md "Design principles" and in section 8 of the plan, which also records the reference proxy end to end | `next` | Ready to start; where the results are recorded is decided when it is added (AGENTS.md) |
| Site: the implementation, in the steps of [section 6 of the proposal](proposals/site.md#6-implementation-plan). Step 1 is merged: [#591](https://github.com/matsumotory/ngx_mruby/pull/591) (`a466688`), `site/` with Starlight 0.42.6 and Astro 7.3.8 pinned and Node.js 22.23.3, the generator `site/scripts/sync-docs.mjs` that renders `docs/` without design, its test and the checks of step 1 under `site/scripts/` (AGENTS.md, "The site"), and `.github/workflows/site.yml`, which builds the site, runs the checks and uploads the built site as a workflow artifact, without deploying. Next: step 2, the tokens of section 4 and the specimens of 4.12, which the owner reviews. In step 1 the generated pages fill all of `site/src/content/docs/` (gitignored), with `docs/README.md` as the page `/`; 5.2 puts the committed home pages `index.mdx` and `ja/index.mdx` in that folder and the generated pages in a gitignored folder under it, so step 3 moves the generated pages into such a folder (they already carry `slug`) before it adds the home pages | `next` (`site/`, as decided with Q1); steps 6 and 7 also change `master` | Step 2 (the tokens of section 4 and the specimens of 4.12, which the owner reviews): ready to start. The owner decided the questions on 2026-10-15 ([section 7 of the proposal](proposals/site.md#7-decisions-2026-10-15)); the last column of section 6 lists what the owner reviews in each step |
| Before the switch of ngx.mruby.org (step 7 of the site proposal), the owner has an item to do in the Pages settings for the custom domain | Repository settings | The owner |
| The implementation of [the proposal for the method lookup of `Nginx::Var` accessors](proposals/nginx-var-method-lookup.md) (#577): candidates (a) and (d), accessors defined on `Nginx::Var` at the first miss with the rule (a2), and ngx_mruby's own methods that read variables in C, with the tests, docs, release notes entries and the three comparisons of its section 3 | `next` | Ready to start once #595 merges (it brings #589 to `next`); the owner's answer of 2026-10-15 to section 4 is to be written into the Status line of `docs/proposals/nginx-var-method-lookup.md` by the implementation pull request |
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

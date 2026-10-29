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

## State as of 2026-10-29 (21:45 JST)

Heads: `next` is the merge of the pull request "Merge `master` (c6d3b3b9b)
into `next`" (`master` at `c6d3b3b9b` into `next`, with #636, #639, #638
and #645) once it is merged; before it, on its first parent, `67ad9b919`
(#640, `auto-ssl` removed from `next`) and `be559a017`, the merge of #641
(`TEST_SH_PORT_OFFSET`); before that, on its first parent, `c0df45534` (#637, the v3 plan, the archive
of two proposals and this file), `5e9d50663` (#632), `a3b1c9276` (#631), `66ab330a9` (#630), `12202b8c4` (#629),
`a9792b82f` (#626), `8bff5fbd7` (#634), `c4e6ac6cc` (#635), `2c96302b7`
(#633, this file and the 3.0.0 release notes) and `c9c49023e`, the merge of #628 (`master` at `93432cf69`
into `next`, with #616, #624 and #627); before that, on its first parent,
`2969426f6` (#625, this file and the state of site step 4 in
`docs/proposals/site.md`), `69b245bdb` (#623), `807865280` (#622), `ca7b473b0` (#621),
`28faff6c2` (#620), `ac7d569c3` (#619), `d5548db41` (#618), `dbe4acf5b`
(#617), `0d1b3d756` (#600), `571212d58` (#614), `5ca7c955b` (#606) and
`216df0ceb` (#615, `master` at `6b27f08da` into `next`). `master` is
`c6d3b3b9b`, the merge of #645; before it, `9acb75949` (#638),
`eb9055584` (#639), `22f13686f` (#636) and `93432cf69` (#627). With that
merge, `next` has the commits of `master` up to `c6d3b3b9b`; its description
lists the conflicts and how they were resolved (the auto-ssl tests and the
gem fix of #636 are left out, as `next` removed the gem with #640). `v2.x` is
`c6d3b3b9b` (`git ls-remote origin refs/heads/v2.x`), so it mirrors
`master`.

2.7.2 was released on 2026-10-29: the tag `v2.7.2` is on `d5ae75547`, the
merge of #624 into `master`, and the release was published at 13:26 JST.
Its release notes are `docs/releases/v2.7.2.md` and
`docs/releases/v2.7.2.ja.md`, on `next` with the same content since #628. 2.7.1 was released on 2026-10-19: the tag `v2.7.1` is on
`ce5eb11`, the merge of the 2.7.1 changes into `master`. Its release notes
are `docs/releases/v2.7.1.md` and `docs/releases/v2.7.1.ja.md`. The release
notes of the next 2.x release are `docs/releases/v2.7.3.md` and
`docs/releases/v2.7.3.ja.md`, created on `master` by #636 and on `next`
with the same content by the merge of `master` at `c6d3b3b9b`.

Merged on 2026-10-29 (JST) after 14:40, into `next`: #633 (this file and
the comparison of the 3.0.0 release notes with 2.7.2; merged at 14:51,
`2c96302b7`), #635 (`test.sh` stops
only the nginx that it started, by its pid; merged at 16:09, `c4e6ac6cc`),
#634 (valgrind fails the cell; one cell runs under valgrind on pull
requests and every cell except the sanitizer cell nightly; 16:51, `8bff5fbd7`), #626 (the agent
proxy endpoints diagram without a line in its narrow arrangement; 18:11,
`a9792b82f`), site step 5, #629 to #632 (18:39 to 19:31, `12202b8c4` to
`5e9d50663`; the site row of "Queue" lists them) and #637 (the v3 plan,
the archive of two proposals and this file; 19:50, `c0df45534`) and #641
(`TEST_SH_PORT_OFFSET`; 20:31, `be559a017`) and #640 (the auto-ssl mrbgem
and `NGX_MRUBY_AUTO_SSL` removed from `next`; 21:33, `67ad9b919`). Into `master`: #636
(the auto-ssl gem tested with Redis, Pebble and dehydrated; 16:40,
`22f13686f`), #639 (`CONTRIBUTING.md` and other documentation fixes;
17:59, `eb9055584`), #638 (nginx 1.31.8 and 1.30.6; 18:31,
`9acb75949`) and #645 (the stream `Async.sleep` timer cancelled when the
session's pool is freed, and the fiber registered with the GC once per
fiber; 20:06, `c6d3b3b9b`).

Merged on 2026-10-29 (JST) after 13:20, into `master`: #624 (the 2.7.2
release: #594 and the other changes of the release; merged at 13:25,
`d5ae75547`; GitHub marks #594 merged with it) and #627 (the two sentences
of `README.md` "Branch strategy" in the present; 13:52, `93432cf69`). Into
`next`: #625 (this file; 13:40, `2969426f6`) and #628 (`master` at
`93432cf69` into `next`; 14:26, `c9c49023e`; its description lists the
conflicts, how they were resolved, and the test ports of `master` that it
moved on `next`).

Merged on 2026-10-29 (JST) after 01:20, into `next`: #615 (`master` at
`6b27f08da` into `next`; merged at 01:46, `216df0ceb`), #606 (mruby-redis in the default build of `next` again,
pinned in `build_config.rb.lock` at `8d9391049`; 02:11, `5ca7c955b`), #614
(the Pagefind result titles at a size of the scale, and the search check
with the results loading and loaded; 03:38, `571212d58`), #600
(the OpenAI Responses API in the mock LLM upstream; 05:30, `0d1b3d756`),
#617 (site step 3; 05:58, `dbe4acf5b`) and the six parts of site step 4,
#618 to #623 (12:02 to 13:13, `d5548db41` to `69b245bdb`; the site row of
"Queue" lists them). Into `master`: #616 (the check of the 2.7.2 release
notes against every pull request since 2.7.1, and the performance
comparison with 2.7.1; 02:35, `f70b24031`).

Merged on 2026-10-29 (JST), into `next`: #607 (site step 2: the design
tokens, the checks of step 2 and the specimens of 4.12; merged at 00:12,
`0e7fba441`) and #605 (`Nginx::Debug.stats` and `Nginx::Debug.gc` tested in
the soak; merged at 00:46, `5999a0cc7`). Into `master`: #612 (the entry of
the 2.7.2 release notes for `Redis.connect_set_udptr` and `Redis.new`
without arguments, matsumotory/mruby-redis#109; merged at 00:10,
`cfe77a506`), #603 (tests of the directives and Ruby methods that had none;
merged at 00:46, `baea78cd7`) and #613 (actions/upload-artifact 7.0.2;
merged at 01:08, `6b27f08da`). In matsumotory/mruby-redis: #109 (the
connection of `Redis.connect_set_udptr` kept in the `mrb_state`, not in
`mrb->ud`; merged at 00:12, `8d9391049` on the gem's `master`). Merged on
2026-10-28, into `next`: #610 (`Nginx::Var` accessors defined at their
first use, and the variables of `Connection`, `Server` and `Request` read
in C; merged at 06:02, `a0f4b97a2`). Merged on 2026-10-20, into `next`:
#608 (this file, the state as of 00:10; merged at 00:16, `39e870c9f`); into
`master`: #604 (mruby-redis in the default build again for 2.7.2; merged
at 00:29, `e77f9a705`).

Merged on 2026-10-19, into `next`: #602 (the `nginx-tests` workflow: nginx's own test suite on nginx with and without ngx_mruby; merged at 23:03 JST, `620e65718`), #597 (the bundled ngx_devel_kit v0.3.4 with `./update-devkit-subtree v0.3.4`; merged at 22:08 JST, `2de1626`), #595 (`master` at `36f4c82` into `next`,
with #589; its description lists the conflicts in
`src/http/ngx_http_mruby_var.c` and `AGENTS.md` and how they were
resolved), #574 (200 with `Content-Length: 0` when a content handler
sends no body, #200, and an output body filter that ends with an empty
body sends the response; its entries are in `docs/releases/v3.0.0.md` and
`.ja.md` and the migration guide, `7b5a0c4`), #591 (site step 1:
`site/` with Starlight, the generator of `docs/`, the checks and
`.github/workflows/site.yml`, `a466688`), #590 (`master` into `next` in
two merge
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
an entry in `docs/releases/v2.7.2.md`; merged at 17:16 JST, `188d324`),
#592 (`README.md` and `docs/README.md` say next to the abstract of the
paper what a worker keeps between requests; merged at 19:10 JST,
`a6c32a4`), #596 (the entry of `docs/releases/v2.7.2.md` and `.ja.md`
for the builds that enable mruby-redis, which get hiredis v1.5.0 since
matsumotory/mruby-redis#108; `a500846`), #599 (the supply chain checks
in CI: zizmor, OpenSSF Scorecard and the heads of the GitHub gems; merged
at 20:43 JST, `ee0a57f`), #598 (the trust boundary of the docs: trusted configuration code, untrusted client input; merged at 21:35 JST, `5eec909`), #601 (the callgrind performance lane and wider sanitizer log checks on `master`; merged at 22:33 JST, `68032bb6a`), #609 (the `Nginx::SSL` examples of the docs look the SNI name up in a table; merged at 23:20 JST, `2135d68a4`) and #611 (no checkout token kept in the `test.yml` jobs, and zizmor audits `test.yml` again; merged at 23:58 JST, `0d09b5054`). Issue #200 was closed at 19:42 JST, after #574.
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

Open pull requests (`gh pr list --state open` at 21:42 JST; the table leaves out the merge of `master` into `next` that writes it):

| Pull request | Base | Stage |
|---|---|---|
| [#646](https://github.com/matsumotory/ngx_mruby/pull/646): a content handler answers after `Nginx::Async.sleep`, and an exception of the location that `Nginx.redirect` runs stops at that location's handler (branch `claude/async-content-sleep-nested-raise`) | `master` | Draft |
| [#642](https://github.com/matsumotory/ngx_mruby/pull/642): Dependabot, github/codeql-action/upload-sarif 4.39.1 | `master` | Open |
| [#643](https://github.com/matsumotory/ngx_mruby/pull/643): Dependabot, github/codeql-action/upload-sarif 4.39.1 | `next` | Open |
| [#644](https://github.com/matsumotory/ngx_mruby/pull/644): Dependabot, actions/upload-artifact 7.0.2 | `next` | Open |


## Decisions

Decisions of the owner that are not yet written in the place their row
names: (a) and (b) of 2026-10-04 in the next paragraph. The owner's choice of 2026-10-29 at 05:34 JST, in a session's
question on who merges the pull request of the 2.7.2 release, tags
`v2.7.2` and publishes the release ("セッションが進める (推奨)", "the session
goes ahead"), covered 2.7.2 only, and it is carried out: the session that
prepared the release merged #624 at 13:25 JST, tagged `v2.7.2` on
`d5ae75547` and published the release at 13:26 JST. AGENTS.md keeps the
rule that agents never create tags and never publish releases; nothing is
written there unless the owner keeps the choice for later releases. The choices among the options of 4.12 of the site proposal
are written in `docs/proposals/site.md` (#607). The decision of 2026-10-19
on the perf lane of `master` (port the tests and the CI only, without
`Nginx::Debug`) is written in #601 (its description and
`docs/test/README.md`, which `next` has since the merge of `master` at
`6b27f08da`). The decision on the method lookup of `Nginx::Var` accessors
(the owner's answer of 2026-10-15 to the question of section 4 of
[the proposal](proposals/archive/nginx-var-method-lookup.md), in a session's
question: the change to introspection is accepted as a behavior change of
3.0.0; and the confirmation of 2026-10-19, in a session's question, with
the option "その内容で合っている (推奨)" ("that content is right"): (a) with the
rule (a2), (d), and accessors in introspection) is written in the Status
line of the proposal and in the entries of `docs/releases/v3.0.0.md` and
`.ja.md` (#610).

On 2026-10-04 the owner answered the recommendations of the analysis of the
control flow of `Nginx::Async` with 「全部推奨通りでいこう、安全網から始めて」
("go with all the recommendations, starting from the safety net"). Two of
its decisions, (a) and (b), are not written in the plan or in the release notes yet,
and a third, (c), is amended below:
(a) `Nginx::Async.sleep` in a content handler is supported, so it does not
raise and nginx waits for the timer; (b) a rewrite handler that ends with no
output and no `Nginx.return` keeps the 2.x behavior on `master`, and on
`next` the request goes on to the next phase as with `NGX_DECLINED`; (c)
the rewrite of how resumed handlers end goes into `master` after 2.7.1. On
2026-10-29 the owner amended (c), in a session's question, with the option
"master は最小の直し、書き直しは next (推奨)": the rewrite lands on `next`,
in the core stabilization of 3.0.0, and `master` gets only the minimal fix
for the content handler sleep. The amendment of (c) is written in item 15 of
section 7 and in the Pillar B row "One fiber lifecycle for HTTP and
stream"; (a) and (b) are written in the plan when their work lands, under
that row and under the row "Redesign response finalization per phase".

The other owner decisions of 2026-10-29, all in session's questions, are
written in the plan: items 1 and 6 and 15 of section 7 (mruby 4.1.0-rc2 now,
`auto-ssl` out of `next`, the agent proxy rows in `v3.0.0-alpha.1`, the
parallel start of parts (a) and (c) of step 7, the subrequest 500, the fix of
the empty output body filter in 2.7.3). Two are not written in the plan: the
rule on the gems that the owner maintains is in AGENTS.md, "Other
repositories", with the owner's words (#637 on `next`, #639 on `master`);
and the body of the GitHub release v2.7.2 gets the section "Behavior
changes: read before upgrading" in English and then in Japanese, option
"足す (推奨)" (the session that prepared the release edits it with `gh release edit`).

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
  #577 (merged) is the proposal for the `var` and `auth` rows; #610
  (merged) implements it.
- `next` bundles mruby 4.0.0 and moves to `4.1.0-rc2` (the newest mruby tag
  on 2026-10-29, `gh api repos/mruby/mruby/tags`), then to 4.1.0 when it is
  tagged (the owner's decision of 2026-10-29). The choices for that step
  are in item 1 of section 7 of the plan, and the row "mruby 4.1.0" of
  "Queue" lists what the step changes.

### Issue triage of 2026-10-04

The closed issues (21 on 2026-10-29, among them #225 closed by #566, #320
by #565 and #519 by #562, and #206, #321, #502 and #200, closed on
2026-10-19; #200 after #574):
`gh issue list --state closed --search
'closed:>=2026-10-04' --limit 200`. The reason is in the last comment of
each issue, or in the pull request that closed it.

Taken up and still open: none.

## Queue

| Follow-up | Target branch | Waits for |
|---|---|---|
| Merge `master` into `next` after each merge into `master`. Model: #573. | `next` | The next merge into `master`: the merge of `master` at `c6d3b3b9b` (#636, #639, #638 and #645) is done by the pull request that writes this state |
| The output body filter that ends with an empty body sends a zero size buffer marked as memory, and the client gets no byte (`Nginx::Filter#output ""`, pinned by `test/t/cases/filter_connection.rb` on `master`). Decided on 2026-10-29 (option "入れる (推奨)"): 2.7.3 gets the same change to `ngx_mrb_finalize_body_filter` as #574 on `next`, so that the response is sent with its status and `Content-Length: 0`, and the owner approved changing the expectation "an empty String closes the connection without a response" of that file. To do: a pull request to `master` with the test commit, then the fix commit, and the entry in `docs/releases/v2.7.3.md` and `.ja.md` | `master` (reaches `next` by the merge) | Ready to start |
| `Nginx::Async.sleep` in a content handler ends the request without any response, with or without output after the sleep (found while testing #574). 2.7.1 documents it under "Known limitations" of `docs/releases/v2.7.1.md`, which plans a later release that lets a content handler wait. To do: let nginx wait for the timer (decision of 2026-10-04), as the minimal fix on `master` (decision of 2026-10-29); the larger rewrite of how resumed handlers end is the row "The async resume rewrite" | `master`, which has it too (it reaches `next` by the merge) | [#646](https://github.com/matsumotory/ngx_mruby/pull/646) (draft), with the redirect exception fix |
| Subrequests: the content handler of a subrequest that returns `Nginx::HTTP_OK` without output sets status 500, where nginx's `return 200;` gives 200. Decided on 2026-10-29 (option "500 のまま (推奨)"): 3.0.0 keeps the 500, so that `auth_request` fails closed (#574 keeps it). To do: the entry of #574 in `docs/releases/v3.0.0.md` and `.ja.md` already says that the status stays 500; add that nginx's own `return 200;` gives 200 and that the 500 keeps `auth_request` from allowing the request | `next` | Ready to start |
| After a HEAD request to a location with an mruby output body filter, nginx sends the header and closes the keep-alive connection: the mruby body filter returns `NGX_ERROR` after it passed on the header of a header-only response (`ngx_mrb_finalize_body_filter`), and `ngx_http_output_filter` then sets `c->error`. The same with output, on 2.7.1, and on the merge of 2.7.2 into `next` (#628, which ran HEAD and then GET on one connection to such a location); `docs/releases/v3.0.0.md` (#574) names it as an exception ([the review of #574](https://github.com/matsumotory/ngx_mruby/pull/574#issuecomment-6166201549), should fix 1). To do: a test commit (HEAD, then GET on one connection), then a fix commit | `master` (reaches `next` by the merge) | Ready to start |
| A rewrite handler that ends without `Nginx.return` (for example `mruby_rewrite_handler_code 'x = 1'` before a content handler, or before nginx's `return 200`) sends no response, and `error.log` has no line at the `error` level: with keep-alive the connection stays open until `keepalive_timeout`, with `Connection: close` it is closed with nothing sent. `ngx_mrb_finalize_rputs` (`src/http/ngx_http_mruby_core.c`; the `rc = NGX_OK` after the log line "rputs_chain is null and return NGX_OK") returns `NGX_OK` when nothing was sent and no status was set, and the rewrite phase of nginx 1.31.6 finalizes the request on `NGX_OK` (`ngx_http_core_rewrite_phase`), where the access phase goes on to the next handler. Found and measured on `next` and `master` while #583 was written and reviewed; no issue tracks it. To do: for v3, a test commit and a fix under the Pillar B row "Redesign response finalization per phase" of the plan, so that the request goes on to the next phase as with `NGX_DECLINED`; for 2.x, the behavior stays (both are the decisions of 2026-10-04), and a line under "Known limitations" in the release notes of the next 2.x release can document it | `next` | v3: waits for the row on step 4 below (the fix belongs to the Pillar B work that step 4 holds until the safety net is done); 2.x: nothing |
| An end-to-end benchmark scenario: throughput and p50 and p99 latency with `oha` or `h2load`, planned in AGENTS.md "Design principles" and in section 8 of the plan, which also records the reference proxy end to end | `next` | Ready to start; where the results are recorded is decided when it is added (AGENTS.md) |
| Site: the implementation, in the steps of [section 6 of the proposal](proposals/site.md#6-implementation-plan). Step 1 is merged: [#591](https://github.com/matsumotory/ngx_mruby/pull/591) (`a466688`), `site/` with Starlight 0.42.6 and Astro 7.3.8 pinned and Node.js 22.23.3, the generator `site/scripts/sync-docs.mjs`, its test and the checks of step 1 under `site/scripts/` (AGENTS.md, "The site"), and `.github/workflows/site.yml`, without deploying. Step 2 is merged: [#607](https://github.com/matsumotory/ngx_mruby/pull/607) (`0e7fba441`), `site/src/styles/tokens.css` with the owner's four choices of 4.12 of 2026-10-19 (palette A, Geist Mono, code blocks at 12 px, the means of 4.3) and the checks of step 2; [#614](https://github.com/matsumotory/ngx_mruby/pull/614) fixes its search check. Step 3 is merged: [#617](https://github.com/matsumotory/ngx_mruby/pull/617) (`dbe4acf5b`), approved by the owner on 2026-10-29 with two small fixes (section 7 of the proposal): the home pages `site/src/content/docs/index.mdx` and `ja/index.mdx` with the example of `test/t/cases/home_example.rb`, the header, menu and footer of 4.10, the sample and diagram mechanisms of 3.5, the request phases diagram in `docs/concepts/request-phases.md` and its translation, the checks of step 3, and the screenshots as the workflow artifact `screenshots`; the specimen pages of step 2 are gone. Step 4 also took what step 3 left for it: the sidebar of the four kinds of page and the routes of 3.2 (#618), the class `num` of numeric table cells and the line breaks of long names (#620), and the last lines of one or two characters on `/guides/install/` and `/ja/docs/` (#623), which `check-styles.mjs` now fails on every page it checks; the fourth-level headings left in `docs/install/` and `docs/class_and_method/` are subsection headings, not code-block labels. Left from step 4: the guides of observability with `ngx_otel_module` and of certificate lookup of 3.2, which need a test build with `ngx_otel_module` and a TLS client in the sample's case (item 1 of the description of #619); and the narrow drawing of the agent proxy endpoints diagram, which still joins the kinds of request with a line ([the review of #622](https://github.com/matsumotory/ngx_mruby/pull/622#issuecomment-6485583255), should fix 1) (#626 removed it). Left for step 6: the version link of the header goes to the 2.x documentation on GitHub until `/v2/` exists | `next` (`site/`, as decided with Q1); steps 6 and 7 also change `master` | Steps 3 and 4 are merged: #617 (`dbe4acf5b`), and #618 (routes, sidebar, start page; `d5548db41`), #619 (guides and use cases with samples; `ac7d569c3`), #620 (Reference with the build diagram; `28faff6c2`), #621 (Concepts with its diagrams; `ca7b473b0`), #622 (the agent proxy page; `807865280`) and #623 (Releases, Security, Contributing, README and the fixes of 2.2; `69b245bdb`). Step 5, the Japanese pages, is merged: #629 (the checks of row 5 and the notice of the generated reference; `12202b8c4`), #630 (Concepts and the start page; `66ab330a9`), #631 (the guides; `a3b1c9276`) and #632 (install, migration, use cases and the build reference; `5e9d50663`). #626 (`a9792b82f`) removed the line of the narrow endpoints drawing. Next: step 6. The owner decided the questions on 2026-10-15 and the choices of 4.12 on 2026-10-19 ([section 7 of the proposal](proposals/site.md#7-decisions-2026-10-15)); the last column of section 6 lists what the owner reviews in each step |
| Before the switch of ngx.mruby.org (step 7 of the site proposal), the owner has an item to do in the Pages settings for the custom domain | Repository settings | The owner |
| nginx-tests with the modules that its skipped files need: a build with the options of `test.sh` and `--with-http_v2_module`, `--with-http_v3_module`, `--with-stream_ssl_module`, `--with-mail` and the other modules that "Results of nginx-tests" in `docs/test/README.md` lists (in the CI run of #602, 189 of the 209 skipped files need a module that `test.sh` does not build), with and without ngx_mruby, in the `nginx-tests` workflow | `next` | Ready to start: #602 is merged |
| nginx-tests with ngx_mruby code configured: runs that add handlers or filters with code for every request through `TEST_NGINX_GLOBALS_HTTP` (the Pillar E row of the plan), compared with the run without code. The pull request decides which code: a rewrite handler that ends without `Nginx.return` sends no response (the row on it above), so that handler would fail most files for a known reason | `next` | Ready to start: #602 is merged |
| Test harness rewrite (step 2 of section 6 of the plan; Pillar E): [#635](https://github.com/matsumotory/ngx_mruby/pull/635) (merged, `c4e6ac6cc`) made `test.sh` stop only the nginx that it started, by its pid, with no `killall` or `pkill`, and send SIGTERM again while the single nginx process still runs, because that process can miss a SIGTERM that arrives right before it waits for events (the run at `7926f72`, where nginx stayed in `epoll_wait()` for 20 minutes after it logged the SIGTERM: "Stopping nginx" in `docs/test/README.md` has the cause and the measurements). [#641](https://github.com/matsumotory/ngx_mruby/pull/641) (merged, `be559a017`) added `TEST_SH_PORT_OFFSET`, which moves every port of the suite, so that two checkouts can run `test.sh` at the same time ("Ports" in `docs/test/README.md`). Still to do, in pull requests of their own: `master_process on` with several workers and reload cases, requests from CRuby instead of the client built into the test mruby, and HTTP/2 and HTTP/3 clients. A should fix of the review of #635 waits for the pull request that next changes `test/build_release.sh`, an input of the `perf` job: its comment still says that `test.sh` kills every running nginx. The readiness wait of #593 is the first part, on `next` since the merge of `master` at `6b27f08da` | `next` | Ready to start: `master_process on` with several workers, on top of #641; no pull request yet |
| valgrind in CI: done on `next` by [#634](https://github.com/matsumotory/ngx_mruby/pull/634) (`8bff5fbd7`): valgrind errors fail the cell, one cell runs under valgrind on pull requests and pushes, and `.github/workflows/valgrind-nightly.yml` runs every cell except the sanitizer cell under valgrind nightly. GitHub runs a schedule only from the workflow file on the default branch, so the nightly run starts once a copy of the file is on `master` ("valgrind in CI" in `docs/test/README.md`). To do: a follow-up PR to `master` that adds `valgrind-nightly.yml` as it is on `next`; to run the cells of `master` under valgrind as well, the same PR gives the `test.yml` of `master` the input `valgrind`, the valgrind options, `test/valgrind.supp` and the step "Check the valgrind reports" of #634, and adds `master` to the matrix of the file | `master` | A decision that `master`, the 2.x line, takes this change of CI |
| nginx floor for v3 (item 2 of section 7 of the plan): drop the cells for nginx 1.26.3 and 1.28.3 from the `build` matrix of `.github/workflows/test.yml` and document the floor of 1.30 stable and 1.31 mainline | `next` | Ready to start: #601's change to `.github/workflows/test.yml` is on `next` since the merge of `master` at `6b27f08da` |
| OpenSSL 3.5 and 4.0 (item 3 of section 7 of the plan): cells for OpenSSL 3.5 as the baseline and 4.0 in `.github/workflows/test.yml`, which builds `1.1.1w` today; drop 1.1.1 and 3.0, and check ENGINE and the removed APIs in ngx_mruby and the gems | `next` | Ready to start: #601's change to `.github/workflows/test.yml` is on `next` since the merge of `master` at `6b27f08da` |
| `build_config.rb` rewrite with explicit gems (step 3 of section 6; Pillar A): `iij/mruby-env` and `iij/mruby-process` replaced by core gems, the choice between core `mruby-regexp` and `mruby-onig-regexp` (item 1 of section 7 keeps onig-regexp for 3.0), `monochromegane/mruby-secure-random` and `iij/mruby-digest` replaced, and `mruby-vedis` and `mruby-localmemcache` out of the default build | `next` | Ready to start: #606, which edits the same file, is merged. The part that replaces `env` and `process` with the core gems needs the subtree at 4.1.0-rc2 (the row "mruby 4.1.0"); the other parts do not |
| mruby 4.1.0 (step 3 of section 6; item 1 of section 7). The step changes: the mruby subtree updated to the tag with Prism vendored (the tag's tarball has an empty `mrbgems/mruby-compiler/lib/prism`, a submodule upstream), the three HAL gem names (`hal-posix-dir`, `hal-posix-io`, `hal-posix-socket`) removed from `NGX_MRUBY_CORE_GEMS` and its comment, the core `env`, `process` and `regexp` gems of 4.1 decided on (see the row above), `build_config.rb.lock` regenerated, the build with `NGX_MRUBY_DEBUG_STATS` run with its tests (4.1 keeps the roots in `mrb->gc.root`), the stream path of the counted GC registrations audited, a release notes entry, and the callgrind comparison against `next`, which includes the measurement of `var` and `auth` on mruby 4.1 (step 4 of the archived proposal for the method lookup of `Nginx::Var`). The owner decided on 2026-10-29 that `next` bundles `4.1.0-rc2` now and moves to 4.1.0 in a small subtree pull request when it is tagged | `next` | Nothing: the pull request for 4.1.0-rc2 is not opened yet |
| Build each bundled gem on mruby 4 (step 3 of section 6): #561 builds the default gem set on mruby 4.0.0; the rest is the build of all of them on 4.1.0-rc2 (the row "mruby 4.1.0"). `auto-ssl` is not built: the owner decided on 2026-10-29 to remove it from `next` | `next` | The pull request of the row "mruby 4.1.0" (not opened yet) |
| OpenSSF Best Practices badge (Pillar G of the plan) | `master` (README) | The owner registers the project on bestpractices.dev and gives the project id; then a session adds the badge |
| Step 4 of section 6 of the plan, the core stability work of Pillar B (execution context, response finalization, fiber lifecycle, common layer, headers and variables, and the two agent proxy rows), then `v3.0.0-alpha.1` | `next` | Held until the safety net of step 2 is done; what is left of it is the row above for the test harness rewrite (#641 is merged; `master_process on` with several workers comes next): valgrind in CI (#634) and the auto-ssl tests (#636 on `master`) are done. #600, #603 and #605 are merged (#603 on `next` since the merge of `master` at `6b27f08da`, with the sanitizer log check of #601). The plan: nothing in the core is refactored before it exists |
| nginx-tests required: the `nginx-tests` workflow records its results and fails only when a build, the fetch of the suite or `prove` fails. In the runs of 2026-10-28 and 2026-10-29 the build with ngx_mruby and the build without it have the same counts (511 files, 302 passed, 0 failed, 209 skipped). To do: the job fails when the build with ngx_mruby fails a file that the build without it passes, and the job joins the `needs` of `ci-ok` | `next` | Ready to start: the counts are the same in every run since #602 |
| The `perf` job in the `needs` of `ci-ok`, and the "In CI" text of `docs/test/README.md` (the sentences that call the job advisory and say that a `FAIL` does not block a merge, under "Performance comparison with callgrind") aligned with the rule of AGENTS.md "Design principles", under which a session does not merge while the job reports `FAIL` or `ERROR` | `next`, then `master` | Ready to start |
| Soak: record `Pss` and `Private_Dirty` from `/proc/<pid>/smaps_rollup` beside `VmRSS`, then bound their slope over more windows, set after measuring (the Pillar E row on memory accounting). Today `test/soak/soak.rb` bounds `VmRSS` by a step and a total and checks the counters of `Nginx::Debug.stats` | `next` | Ready to start |
| The ASan cell with `-DNGX_DEBUG_PALLOC -DNGX_DEBUG_MALLOC` (3.7 of the plan; the cell of `test.yml` sets only `-fsanitize` and `-fno-omit-frame-pointer`), so that ASan sees an access that runs from one pool allocation into the next. To do: a run of the suite with these flags, whose findings follow [SECURITY.md](../SECURITY.md), then the cell | `next`, `master` | Ready to start |
| A test build with `ngx_otel_module` (nginx/nginx-otel, built with CMake against the nginx source of `test.sh`) and an OTLP receiver for the case of the observability sample of 3.2 of the site proposal | `next` | The harness rewrite (the row above) |
| Step 7 of section 6 of the plan, the agent proxy, parts (a) to (e); none exists on `next` | `next` | Parts (a) and (c) wait, as step 4 does, for what is left of the safety net of step 2: the row above for the test harness rewrite ([#641](https://github.com/matsumotory/ngx_mruby/pull/641) is merged; valgrind in CI, #634, and the auto-ssl tests, #636 on `master`, are done); then they start beside step 4 (decision of 2026-10-29). (b) and (d) also wait for step 4. The order inside the step is a proposal of the 2026-10-04 amendment until the owner decides it |
| Remove `example/` (`README.md`, `nginx.conf`, `proxy.rb`, `set.rb`, `set2.rb`, `unified_hello.rb`): no CI job starts it, no page links it, and its `/proxy` location picks among `test1.example.com` to `test3.example.com`, which are unreachable; `examples/start/` is checked by `examples.yml` | `next` | Ready to start |
| A stream handler that raises after `Nginx::Stream::Async.sleep` leaves its exception in the worker's `mrb_state`, and the next session of that worker is aborted by it. Reproduced on `master`. Decided on 2026-10-29 at 21:00 JST (option "2.7.3の通常の修正 (推奨)"): an ordinary 2.x fix in 2.7.3, a test commit and then a fix commit, with an entry under "Fixes" of `docs/releases/v2.7.3.md` and `.ja.md` | `master` (reaches `next` by the merge) | The pull request comes after #646 |
| After that exception, or after `stream_status` is set to ABORT, the stream session is not closed. Reproduced on `master`. Decided on 2026-10-29 at 21:00 JST with the row above (option "2.7.3の通常の修正 (推奨)"): an ordinary 2.x fix in 2.7.3, in the same way | `master` (reaches `next` by the merge) | The pull request comes after #646 |
| When the handler of the location that `Nginx.redirect` runs sleeps and the handler that called `Nginx.redirect` then raises, the 500 page is followed by the output of the sleeping handler when its timer fires. The request ends and the connection is closed, and nothing leaks. Not a 2.x fix: it needs the rewrite of the row "The async resume rewrite" (#646 leaves it out) | `next`, in the core stabilization of 3.0.0 | The row "The async resume rewrite" |
| The async resume rewrite (decision (c) of 2026-10-04, amended on 2026-10-29: the rewrite of how resumed handlers end in `src/http/ngx_http_mruby_async.c`, which includes the resume of a handler after `Nginx::Async::HTTP.sub_request` from its own request). No pull request exists | `next`, in the core stabilization of 3.0.0 | Step 4, held as in the row on step 4 above |
| The generated reference of the site (Pillar F of the plan): the directives from the `ngx_command_t` tables, the Ruby API with YARD and yard-mruby, the C API with Doxygen. `site/scripts/check-reference.mjs` checks, among other things, that each directive name has a heading in `docs/directives/README.md`; the pages are written by hand | `next` | Ready to start; no step of section 6 of the site proposal produces it yet |

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

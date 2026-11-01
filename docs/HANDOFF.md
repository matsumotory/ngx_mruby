# Handoff: the state of the work

## State as of 2026-11-02 (02:45 JST)

- Heads: `next` is `0f7ad0b96`, the merge of
  [#728](https://github.com/matsumotory/ngx_mruby/pull/728) (step 7 of the
  core stabilization, 02:33 JST), after `7a0076e58`, the merge of
  [#733](https://github.com/matsumotory/ngx_mruby/pull/733) (the
  should-fix items of the review of #729), and `d70481db6`, the merge of
  [#732](https://github.com/matsumotory/ngx_mruby/pull/732) (the advisory
  id of 2.7.4 and the release rule of 2026-11-02 on `next`); `master` is
  `0f865ed4a`, the merge of
  [#731](https://github.com/matsumotory/ngx_mruby/pull/731) (the same on
  `master`), after `e2aeb5ddd`, the merge of the 2.x form of the fix of
  GHSA-xjh6-6vgm-56wj, where the tag `v2.7.4` is; `v2.x` mirrors `master`.
  `next` contains `master` as of `0f865ed4a`, with the merge
  [#734](https://github.com/matsumotory/ngx_mruby/pull/734) (before it, as of
  [#701](https://github.com/matsumotory/ngx_mruby/pull/701)).
- The release 2.7.3: the tag `v2.7.3` is on `591147b01` (2026-11-01 00:08
  JST), and [the release](https://github.com/matsumotory/ngx_mruby/releases/tag/v2.7.3)
  is published. Two advisories were published with it:
  [GHSA-86wx-fcwx-m3vh](https://github.com/matsumotory/ngx_mruby/security/advisories/GHSA-86wx-fcwx-m3vh)
  (High; the stream `Nginx::Stream::Async.sleep` use-after-free, fixed by [#645](https://github.com/matsumotory/ngx_mruby/pull/645)) and
  [GHSA-8r78-rxqq-5gp5](https://github.com/matsumotory/ngx_mruby/security/advisories/GHSA-8r78-rxqq-5gp5)
  (Low; a string with a NUL byte in `Nginx::Upstream#server=` and
  `Nginx::Stream::Connection#upstream_server=`, fixed by `591147b01`,
  entry 9 of [the 2.7.3 release notes](releases/v2.7.3.md)).
  #699 added the two advisory ids to the 2.7.3 release notes.
- The release 2.7.4: the tag `v2.7.4` is on `e2aeb5ddd` (2026-11-02 01:04
  JST), and [the release](https://github.com/matsumotory/ngx_mruby/releases/tag/v2.7.4)
  is published. One advisory was published with it:
  [GHSA-xjh6-6vgm-56wj](https://github.com/matsumotory/ngx_mruby/security/advisories/GHSA-xjh6-6vgm-56wj)
  (Moderate; the stream module: the reads of a session whose code waits in
  `Nginx::Stream::Async.sleep` on a `listen ... proxy_protocol`, and
  `proxy_protocol_addr` for a connection without a PROXY source address).
  `master` has it as entries 1 and 2 of
  [the 2.7.4 release notes](https://github.com/matsumotory/ngx_mruby/blob/master/docs/releases/v2.7.4.md)
  ([Japanese](https://github.com/matsumotory/ngx_mruby/blob/master/docs/releases/v2.7.4.ja.md)),
  which reach `next` with the merge of `master` at `0f865ed4a`; `next` got the same
  fix in its own form, with the two entries in
  [the 3.0.0 release notes](releases/v3.0.0.md). The check before the tag:
  the pull requests merged into `master` from `v2.7.3` to the fix are
  [#699](https://github.com/matsumotory/ngx_mruby/pull/699) (the advisory
  ids of 2.7.3, docs only), [#704](https://github.com/matsumotory/ngx_mruby/pull/704)
  (CI, its entry under "Build and test changes"),
  [#703](https://github.com/matsumotory/ngx_mruby/pull/703) and
  [#716](https://github.com/matsumotory/ngx_mruby/pull/716) (docs only);
  none changes an input of the measured binary, and the fix changes
  `src/stream/` only, which the callgrind lane does not build
  (`--with-stream` is not given), so 2.7.4 and 2.7.3 measure as the same
  binary. "Security fixes" in `docs/releases/README.md` asks for a public
  check pull request before the fix; none was opened, although
  `v2.7.4.md` had existed since #704 and the check could have been made
  before the fix. The check was made with the private pull request of
  the fix instead, and is recorded in
  [#731](https://github.com/matsumotory/ngx_mruby/pull/731), which adds the
  advisory id to `master`.
- [#729](https://github.com/matsumotory/ngx_mruby/pull/729) (the terms of
  the AI gateway on the site) was merged at 01:33 JST, and
  [#733](https://github.com/matsumotory/ngx_mruby/pull/733), the
  should-fix items of its review, at 02:14 JST.
- [#731](https://github.com/matsumotory/ngx_mruby/pull/731) (base
  `master`, 01:51 JST) and [#732](https://github.com/matsumotory/ngx_mruby/pull/732)
  (base `next`, 01:56 JST) are merged: the advisory id of 2.7.4, and the
  owner's decision of 2026-11-02 that a session publishes the release
  after the owner's go-ahead, written into AGENTS.md, CLAUDE.md,
  `docs/releases/README.md` and `docs/DEVELOPMENT.md`.
- Open: [#734](https://github.com/matsumotory/ngx_mruby/pull/734), the merge
  of `master` at `0f865ed4a` into `next` (base `next`).

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

## Decisions

Decisions of the owner that are not yet written in the place their row
names: (a) and (b) of 2026-10-04, and (1) of 2026-11-01. The owner's choice of 2026-10-29 at 05:34 JST, in a session's
question on who merges the pull request of the 2.7.2 release, tags
`v2.7.2` and publishes the release ("セッションが進める (推奨)", "the session
goes ahead"), covered 2.7.2 only, and it is carried out: the session that
prepared the release merged #624 at 13:25 JST, tagged `v2.7.2` on
`d5ae75547` and published the release at 13:26 JST. On 2026-11-02 the owner kept
the choice for later releases ("release と tag はセッション、advisory の公開は
本人": the session publishes the release and its tag, the owner publishes
the advisory); #731 and #732 write it into AGENTS.md, CLAUDE.md,
`docs/releases/README.md` and `docs/DEVELOPMENT.md`. The choices among the
options of 4.12 of the site proposal are written in `docs/proposals/site.md` (#607). The decision of 2026-10-19
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

On 2026-11-01 the owner decided Q1 to Q6 of section 9 of
[docs/proposals/core-stabilization.md](proposals/core-stabilization.md), in a
session's question, each as recommended, with the options 「動くようにする (推奨)」
(Q1), 「handler の終わりで効く (推奨)」 (Q2), 「いまの動きを保つ (推奨)」 (Q3),
「1回にする (推奨)」 (Q4), 「RuntimeError にする (推奨)」 (Q5) and
「handler ごとにする (推奨)」 (Q6). They are recorded in section 9 of the
proposal ([#710](https://github.com/matsumotory/ngx_mruby/pull/710)).

On 2026-11-01 the owner decided to build the site with Astro and the
repository's own components instead of Starlight:
「サイトのドキュメントに既存のドキュメントライブラリ使うの微妙じゃない？あれは人が作る場合の便利ツールであっていまはcodexとかがデザインにあったドキュメントを自前で書いたほうが良さそう」
(a documentation library is a tool for people who write a site by hand;
now Codex and the like can write documentation that fits the design
themselves). The plan is section 5.4 of
[docs/proposals/site.md](proposals/site.md)
([#700](https://github.com/matsumotory/ngx_mruby/pull/700)). Its first
layer, the site's own shell beside Starlight, is merged in
[#708](https://github.com/matsumotory/ngx_mruby/pull/708). Later the same
day the owner decided that work that can be done without splitting is not
split into stages and is asked of Codex in one request:
「今後も分けなくてもできるなら無駄に分けず依頼は一回で終わるようにせよ」.
So Codex does the rest of the replacement in one pull request,
[#713](https://github.com/matsumotory/ngx_mruby/pull/713), and that
pull request changes the iPhone width of the layout checks to 402px
(「じゃあ402にしよう」). Claude Code took #713 over from Codex for the
browser acceptance; at 402px the root font size grows with the screen
(4.4 of the site proposal), so that the lines set at 390px keep their
breaks.

On 2026-11-01 the owner decided four things in a session's questions.
(1) On the CI of a pull request that changes code, the owner asked
「ciでバージョンとstatic dynamlc link全部網羅すべきなんかな？定期アクションとかリリース前チェックではいいけど、日々のciでそこまでやるべき？」
(should CI cover every version and both static and dynamic links? for the
nightly runs or the check before a release yes, but in the daily CI?) and
chose the option 「4 cell に減らす (推奨)」: such a pull request runs four
cells of the `build` matrix (nginx 1.31.8 static, nginx 1.30.6 dynamic, the
ASan and UBSan cell and the valgrind cell) instead of the whole matrix, and
the whole matrix runs nightly, before a tag (the label `full-matrix` on the
check pull request of "Before the tag") and on the push of a tag. A pull
request on `next`, then one on `master`, implements it and writes it in
AGENTS.md and `docs/test/README.md`; until then this row holds it.
(2) Discussions are on and the wiki is off (Q9 of the site proposal); this
was done on 2026-11-01 (`has_discussions: true`, `has_wiki: false`).
(3) The next v3 work is the extension of the test harness (`master_process
on`, several workers, reload), after the change of the CI cells (the
queue row "Test harness rewrite"). (4) The seven Japanese pages of the site
that are left go to Codex, which the owner asks (the subsection "Japanese
pages of the site" of "Work in progress").

On 2026-10-31 the owner decided, in the sessions' questions on the
release of 2.7.3, that the finding on the stream `Nginx::Stream::Async.sleep`
of a UDP session is published as an advisory of its own, from a new
draft ([GHSA-86wx-fcwx-m3vh](https://github.com/matsumotory/ngx_mruby/security/advisories/GHSA-86wx-fcwx-m3vh)), and that the regression of #645, a second fiber of a UDP
session that was not kept from the GC, is fixed before the tag
([#698](https://github.com/matsumotory/ngx_mruby/pull/698)). Both are
carried out: 2.7.3 has #698, and the advisory is published. Nothing is
written elsewhere for them.

On 2026-10-31 the owner set a rule for CI:
「ciはあくまで綺麗な環境での最終チェックであってテストはローカルできっちりやること、ciに過剰なテストを詰め込み過ぎて何十分もかかるようにしないこと」
(CI is only the final check in a clean environment, and the tests are done
thoroughly locally; CI is not packed with so many tests that it takes tens
of minutes). It is written in AGENTS.md, "Branches and pull requests", with
how the sessions apply it, by
[#692](https://github.com/matsumotory/ngx_mruby/pull/692) on `next` and by
[#693](https://github.com/matsumotory/ngx_mruby/pull/693) on `master`.
On the same day the owner decided, in a session's question, with the option
「vendor を対象から外して却下 (推奨)」, that CodeQL leaves out the vendored
trees `mruby/` and `dependence/`, that the alerts of code scanning on them
are dismissed as vendored upstream code, and that nothing is reported
upstream for them; it is written in "CodeQL" in `docs/test/README.md` by
the same pull requests.

On 2026-10-31 the owner decided on the differences of mruby 4.1.0-rc2 in
the `perf` comparison of #678, in two session's questions: first the option
"GC の設定を先に試す (推奨)" (GC の増分が消えれば、残る auth の VM の分を受け入れてマージ),
and after the measurements
「一旦はmruby側の仕様という程度にしか言えないならそれをテストに反映しつつ注意点として記録しておくのが良さそうかな。使いやすさの時点でそういう実装になってるかもしれないし」.
No GC setting removed the larger GC share without raising the work without
the GC, so ngx_mruby keeps mruby's defaults; the accepted differences
(`auth` +7.10% without GC, the GC share of the scenarios with Ruby) are
written under "Known differences" in `docs/test/README.md` and in the entry
of the bundled mruby in `docs/releases/v3.0.0.md` and `.ja.md` (#678), and
the acceptance is recorded on #678. The owner then asked, on the same
day: 「callgrindのテストはエラーにならんように調整しとかなね」 (adjust the
callgrind comparison so that it does not report an error for this). A
pull request to `next` compares against `next`, which has mruby 4.1; a
comparison with a commit of `next` from before #678 still has mruby 4.0.0
in its base. [#696](https://github.com/matsumotory/ngx_mruby/pull/696)
adds `test/perf/accepted.txt`, which
`test/perf/perf.rb` reads: `mruby-version 4.0 4.1 auth 8` shows `auth`
within +8% without GC as `ok (accepted: ...)` when the base bundles mruby
4.0.x and the head 4.1.x ("Known differences" in `docs/test/README.md`,
and "Before a tag" in AGENTS.md). The comparison before the first
pre-release of v3 has `v2.7.2`, with mruby 3.3.0, as its base; the file has
no line for mruby 3.3 against 4.1, so its `WARN` and `FAIL` rows go to the
owner.

On 2026-10-31 the owner set a rule for reports to mruby, in a session's
question: 「mruby側への報告は確定と明らかにどの観点でも修正すべきと判断でき、パッチをかけるものだけにしたい。ngx_mrubyの都合だけでの報告はしたくない」
(report to mruby only a defect that is confirmed and that should clearly be
fixed from every viewpoint, with a patch; nothing only for ngx_mruby's
convenience). It is written in AGENTS.md, "Other repositories", on `next`
and on `master` with the same text, by the next pull request that changes
that section. Until then this row holds it.

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
(b) is in effect on `next` since
[#720](https://github.com/matsumotory/ngx_mruby/pull/720), which writes it
in that row.

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

The owner's choice of 2026-11-02 on the terms for models, agents, their
traffic and the AI gateway is written in section 7 of
[the site proposal](proposals/site.md#7-decisions-2026-10-15) and in
[the glossary](glossary.md). Its second choice of the same day, on how
the Japanese pages write these terms (katakana, with identifiers in
English) and on the home page heading, is written there too.

## Work in progress

### Japanese pages of the site

- [#705](https://github.com/matsumotory/ngx_mruby/pull/705) (base `next`,
  merged as `fe9a3f2bf`) translated six of the seven pages of
  `NOT_TRANSLATED_YET` in `site/scripts/lib/site.mjs`: the contributing
  page, development, the test guide, the releases page, security and the
  trust boundary. The handoff page stays in English with a Japanese
  notice: on 2026-10-29 the owner chose 「英語のまま注記つき (推奨)」 in a
  session's question (Q2 in section 7 of `docs/proposals/site.md`), so
  `NOT_TRANSLATED_YET` keeps only `contributing/handoff`.
  [#703](https://github.com/matsumotory/ngx_mruby/pull/703) (base
  `master`, merged as `6eae5a2df`) rewrote the Japanese 2.x release notes.
  What is left: after `master` is merged into `next`, a pull request to
  `next` empties `NOTES_ONLY` in `site/scripts/check-japanese-lines.mjs`
  if the four release-note pages pass. The branch `claude/site-step5-last`
  holds an earlier translation that #705 and #703 drew on.

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
| Merge `master` into `next` after each merge into `master`. Model: #573. | `next` | The merge of `master` at `0f865ed4a` (#704, #703, #716, the 2.x form of the fix of GHSA-xjh6-6vgm-56wj, #731) is [#734](https://github.com/matsumotory/ngx_mruby/pull/734); the next merge brings what `master` gains after it |
| Subrequests: the content handler of a subrequest that returns `Nginx::HTTP_OK` without output sets status 500, where nginx's `return 200;` gives 200. Decided on 2026-10-29 (option "500 のまま (推奨)"): 3.0.0 keeps the 500, so that `auth_request` fails closed (#574 keeps it). To do: the entry of #574 in `docs/releases/v3.0.0.md` and `.ja.md` already says that the status stays 500; add that nginx's own `return 200;` gives 200 and that the 500 keeps `auth_request` from allowing the request | `next` | Ready to start |
| After a HEAD request to a location with an mruby output body filter, nginx sends the header and closes the keep-alive connection: the mruby body filter returns `NGX_ERROR` after it passed on the header of a header-only response (`ngx_mrb_finalize_body_filter`), and `ngx_http_output_filter` then sets `c->error`. The same with output, on 2.7.1, and on the merge of 2.7.2 into `next` (#628, which ran HEAD and then GET on one connection to such a location); `docs/releases/v3.0.0.md` (#574) names it as an exception ([the review of #574](https://github.com/matsumotory/ngx_mruby/pull/574#issuecomment-6166201549), should fix 1). To do: a test commit (HEAD, then GET on one connection), then a fix commit | `master` (reaches `next` by the merge) | Ready to start |
| A rewrite handler that ends without `Nginx.return` (for example `mruby_rewrite_handler_code 'x = 1'` before a content handler, or before nginx's `return 200`) sends no response, and `error.log` has no line at the `error` level: with keep-alive the connection stays open until `keepalive_timeout`, with `Connection: close` it is closed with nothing sent. `ngx_mrb_finalize_rputs` (`src/http/ngx_http_mruby_core.c`; the `rc = NGX_OK` after the log line "rputs_chain is null and return NGX_OK") returns `NGX_OK` when nothing was sent and no status was set, and the rewrite phase of nginx 1.31.6 finalizes the request on `NGX_OK` (`ngx_http_core_rewrite_phase`), where the access phase goes on to the next handler. Found and measured on `next` and `master` while #583 was written and reviewed; no issue tracks it. To do: for v3, a test commit and a fix under the Pillar B row "Redesign response finalization per phase" of the plan, so that the request goes on to the next phase as with `NGX_DECLINED`; for 2.x, the behavior stays (both are the decisions of 2026-10-04), and a line under "Known limitations" in the release notes of the next 2.x release can document it | `next` | v3: done in [#720](https://github.com/matsumotory/ngx_mruby/pull/720) (decision (b), step 4 of section 8 of the core stabilization proposal); 2.x: nothing |
| An end-to-end benchmark scenario: throughput and p50 and p99 latency with `oha` or `h2load`, planned in AGENTS.md "Design principles" and in section 8 of the plan, which also records the reference proxy end to end | `next` | Ready to start; where the results are recorded is decided when it is added (AGENTS.md) |
| Site: steps 1 to 4, 6 and 7 are merged (#591, #607, #614, #617–#623, #626, #629–#632, #653–#657), and the site is deployed from `next`. Step 5, the Japanese pages, is merged (#705 for six pages, #703 for the 2.x release notes on `master`); the handoff page stays English with a notice, and `NOTES_ONLY` of `check-japanese-lines.mjs` still lists four release notes (the subsection "Japanese pages of the site" of "Work in progress") | `next` for `site/`; `master` for 2.x sources | Still open: the emptying of `NOTES_ONLY` once `master` is merged into `next`; the site on Astro without Starlight (5.4 of the site proposal, #700, the owner's decision of 2026-11-01), whose first layer, the own shell beside Starlight behind `NGX_MRUBY_SITE_SHELL=own`, is merged in #708, and whose rest is #713 (from a Codex session, taken over by Claude Code for the browser acceptance), which also changes the iPhone width to 402px with the root size of 4.4; the 3.x development banner of 3.4; and the observability and certificate-lookup sample prerequisites of #619. Q9 is done (Discussions on, wiki off, 2026-11-01) |
| nginx-tests with the modules that its skipped files need: a build with the options of `test.sh` and `--with-http_v2_module`, `--with-http_v3_module`, `--with-stream_ssl_module`, `--with-mail` and the other modules that "Results of nginx-tests" in `docs/test/README.md` lists (in the CI run of #602, 189 of the 209 skipped files need a module that `test.sh` does not build), with and without ngx_mruby, in the `nginx-tests` workflow | `next` | Ready to start: #602 is merged |
| nginx-tests with ngx_mruby code configured: runs that add handlers or filters with code for every request through `TEST_NGINX_GLOBALS_HTTP` (the Pillar E row of the plan), compared with the run without code. The pull request decides which code: a rewrite handler that ends without `Nginx.return` sends no response (the row on it above), so that handler would fail most files for a known reason | `next` | Ready to start: #602 is merged |
| Test harness rewrite (step 2 of section 6 of the plan; Pillar E): [#635](https://github.com/matsumotory/ngx_mruby/pull/635) (merged, `c4e6ac6cc`) made `test.sh` stop only the nginx that it started, by its pid, with no `killall` or `pkill`, and send SIGTERM again while the single nginx process still runs, because that process can miss a SIGTERM that arrives right before it waits for events (the run at `7926f72`, where nginx stayed in `epoll_wait()` for 20 minutes after it logged the SIGTERM: "Stopping nginx" in `docs/test/README.md` has the cause and the measurements). [#641](https://github.com/matsumotory/ngx_mruby/pull/641) (merged, `be559a017`) added `TEST_SH_PORT_OFFSET`, which moves every port of the suite, so that two checkouts can run `test.sh` at the same time ("Ports" in `docs/test/README.md`). [#706](https://github.com/matsumotory/ngx_mruby/pull/706) added nginx with `master_process on` and several workers, and a reload in the middle of a case: `test/t/cases/_workers.rb` starts such an nginx from `test/conf/workers/`, and `test/t/cases/workers.rb` checks that each of four workers answers from an mrb_state of its own, and that across a SIGHUP the old workers finish an `Nginx::Async.sleep` and an `Nginx::Stream::Async.sleep` in flight while the new configuration answers ("Several workers and reloads" in `docs/test/README.md`). Still to do, in pull requests of their own: requests from CRuby instead of the client built into the test mruby for the other cases, and HTTP/2 and HTTP/3 clients. A should fix of the review of #635 waits for the pull request that next changes `test/build_release.sh`, an input of the `perf` job: its comment still says that `test.sh` kills every running nginx. The readiness wait of #593 is the first part, on `next` since the merge of `master` at `6b27f08da` | `next` | Several workers and reloads: done by [#706](https://github.com/matsumotory/ngx_mruby/pull/706) (decision (3) of 2026-11-01). Requests from CRuby and the HTTP/2 and HTTP/3 clients: ready to start |
| CI runs only the jobs that a change needs: done on both branches by [#676](https://github.com/matsumotory/ngx_mruby/pull/676), [#685](https://github.com/matsumotory/ngx_mruby/pull/685), [#686](https://github.com/matsumotory/ngx_mruby/pull/686) and [#692](https://github.com/matsumotory/ngx_mruby/pull/692) on `next`, and [#679](https://github.com/matsumotory/ngx_mruby/pull/679), [#690](https://github.com/matsumotory/ngx_mruby/pull/690) and [#693](https://github.com/matsumotory/ngx_mruby/pull/693) on `master`; the owner's decisions and rules are in AGENTS.md and `docs/test/README.md`. Left: a pull request to `master` that gives it the lines of `test/ci/changes.sh` and `test/ci/changes_test.sh` that `next` has (on `master`, a change of `test/soak/mock_llm_test.rb` alone runs that check only with the label `perf`); the first run of the whole build matrix through `fromJSON` (should fix 4 of [the review of #686](https://github.com/matsumotory/ngx_mruby/pull/686#issuecomment-6541409852)), which the nightly run under valgrind makes; and from [the review of #693](https://github.com/matsumotory/ngx_mruby/pull/693#issuecomment-6542620420): local commands for the build of the 2.x pages in "The 2.x pages of the site" of `docs/test/README.md` on `master` (should fix 1 and 2), and on both branches, a sentence in "Required status check" that a draft run queued after the ready run cancels it in `site-v2`, `codeql` and `zizmor`, or a concurrency group that includes the draft state (should fix 4). Four cells: the owner's decision of 2026-11-01 under "Decisions", in a session's question, with the option 「4 cell に減らす (推奨)」, that a pull request that changes the code runs four cells of the build matrix: done on both branches by [#702](https://github.com/matsumotory/ngx_mruby/pull/702) on `next` (`bf1b742b7`) and [#704](https://github.com/matsumotory/ngx_mruby/pull/704) on `master` (`166341b93`), with `build` `standard` of `test/ci/changes.sh`; every cell runs only nightly, on a tag, in the check pull request before a tag (the label `full-matrix`, which exists in the repository) and on "Run workflow" without `base` | `master`, `next` | Ready to start |
| nginx floor for v3 (item 2 of section 7 of the plan): drop the cells for nginx 1.26.3 and 1.28.3 from the `build` matrix of `.github/workflows/test.yml` and document the floor of 1.30 stable and 1.31 mainline | `next` | Ready to start: #601's change to `.github/workflows/test.yml` is on `next` since the merge of `master` at `6b27f08da` |
| OpenSSL 3.5 and 4.0 (item 3 of section 7 of the plan): cells for OpenSSL 3.5 as the baseline and 4.0 in `.github/workflows/test.yml`, which builds `1.1.1w` today; drop 1.1.1 and 3.0, and check ENGINE and the removed APIs in ngx_mruby and the gems | `next` | Ready to start: #601's change to `.github/workflows/test.yml` is on `next` since the merge of `master` at `6b27f08da` |
| `build_config.rb` rewrite with explicit gems (step 3 of section 6; Pillar A): `iij/mruby-env` and `iij/mruby-process` replaced by core gems, the choice between core `mruby-regexp` and `mruby-onig-regexp` (item 1 of section 7 keeps onig-regexp for 3.0), `monochromegane/mruby-secure-random` and `iij/mruby-digest` replaced, and `mruby-vedis` and `mruby-localmemcache` out of the default build | `next` | Ready to start: #606, which edits the same file, and #678 (mruby 4.1.0-rc2, whose core gems replace `env` and `process`) are merged |
| mruby 4.1.0 (step 3 of section 6; item 1 of section 7). The owner decided on 2026-10-29 that `next` bundles `4.1.0-rc2` now and moves to 4.1.0 in a small subtree pull request when it is tagged. `next` bundles `4.1.0-rc2` since [#678](https://github.com/matsumotory/ngx_mruby/pull/678). The step to 4.1.0: `./update-mruby-subtree 4.1.0`, `vendor-mruby-prism` if the gitlink of Prism moves, the lock, and the release notes | `next` | The tag `4.1.0` of mruby |
| Step 4 of section 6 of the plan, the core stability work of Pillar B (execution context, response finalization, fiber lifecycle, common layer, headers and variables, and the two agent proxy rows), then `v3.0.0-alpha.1` | `next` | Design accepted. Step 1 of section 8 of the proposal (tests only) merged in [#712](https://github.com/matsumotory/ngx_mruby/pull/712), 2026-11-01; step 2 (the common layer) in [#714](https://github.com/matsumotory/ngx_mruby/pull/714); step 3 (the wake and the second call of an HTTP handler after its sleep, and the result of a handler kept for that handler) in [#715](https://github.com/matsumotory/ngx_mruby/pull/715). step 4 (decision (b): a rewrite or server rewrite handler without a result goes on) in [#720](https://github.com/matsumotory/ngx_mruby/pull/720). step 5 (subrequests through the wake, `sub_request` returns the response, a content handler waits for a subrequest) in [#722](https://github.com/matsumotory/ngx_mruby/pull/722). step 6 (the stream wake, a UDP session runs its code once, and the end of a waiting session on `worker_shutdown_timeout`) in [#727](https://github.com/matsumotory/ngx_mruby/pull/727). step 7 (`Nginx.redirect` takes effect when the handler ends) in [#728](https://github.com/matsumotory/ngx_mruby/pull/728). Step 8 follows. [#709](https://github.com/matsumotory/ngx_mruby/pull/709) merged 2026-11-01, `next` 2ba80f4e9: [docs/proposals/core-stabilization.md](proposals/core-stabilization.md), whose six questions the owner decided in section 9; the security session reviews it before the first implementation pull request. Started by: 本人の選択 2026-11-01、問い「v3 の次の作業を何から始めますか」に対して「ハーネスの試験の拡張 (推奨)」、その選択肢の文「master_process on、複数の worker、reload を test.sh で試験できるようにする。その後にコアの安定化 (fiber の寿命と応答の終了の作り直し) へ」 (the owner chose to extend the harness so that `test.sh` tests `master_process on`, several workers and reloads, and then to go on to the core stabilization, the rework of the fiber lifetime and of the end of the response). [#706](https://github.com/matsumotory/ngx_mruby/pull/706) adds that extension. The requests from CRuby and the HTTP/2 and HTTP/3 clients of the row above for the test harness rewrite stay there. valgrind in CI (#634) and the auto-ssl tests (#636 on `master`) were done before. #600, #603 and #605 are merged (#603 on `next` since the merge of `master` at `6b27f08da`, with the sanitizer log check of #601). The plan: nothing in the core is refactored before it exists |
| nginx-tests required: the `nginx-tests` workflow records its results and fails only when a build, the fetch of the suite or `prove` fails. In the runs of 2026-10-28 and 2026-10-29 the build with ngx_mruby and the build without it have the same counts (511 files, 302 passed, 0 failed, 209 skipped). To do: the job fails when the build with ngx_mruby fails a file that the build without it passes, and the job joins the `needs` of `ci-ok` | `next` | Ready to start: the counts are the same in every run since #602 |
| The `perf` job in the `needs` of `ci-ok`, and the "In CI" text of `docs/test/README.md` (the sentences that call the job advisory and say that a `FAIL` does not block a merge, under "Performance comparison with callgrind") aligned with the rule of AGENTS.md "Design principles", under which a session does not merge while the job reports `FAIL` or `ERROR` | `next`, then `master` | Ready to start |
| Soak: record `Pss` and `Private_Dirty` from `/proc/<pid>/smaps_rollup` beside `VmRSS`, then bound their slope over more windows, set after measuring (the Pillar E row on memory accounting). Today `test/soak/soak.rb` bounds `VmRSS` by a step and a total and checks the counters of `Nginx::Debug.stats` | `next` | Ready to start |
| The ASan cell with `-DNGX_DEBUG_PALLOC -DNGX_DEBUG_MALLOC` (3.7 of the plan; the cell of `test.yml` sets only `-fsanitize` and `-fno-omit-frame-pointer`), so that ASan sees an access that runs from one pool allocation into the next. To do: a run of the suite with these flags, whose findings follow [SECURITY.md](../SECURITY.md), then the cell | `next`, `master` | Ready to start |
| A test build with `ngx_otel_module` (nginx/nginx-otel, built with CMake against the nginx source of `test.sh`) and an OTLP receiver for the case of the observability sample of 3.2 of the site proposal | `next` | The harness rewrite (the row above), of which this waits for what is left: the requests from CRuby instead of the client built into the test mruby, and the HTTP/2 and HTTP/3 clients. [#706](https://github.com/matsumotory/ngx_mruby/pull/706) added `master_process on`, several workers and reloads |
| Step 7 of section 6 of the plan, the agent proxy, parts (a) to (e); none exists on `next` | `next` | Parts (a) and (c) start "after the safety net of step 2, beside step 4" (step 7 of section 6 of the plan, decided on 2026-10-29 in item 15 of section 7), so they wait for what is left of that safety net: in the row above for the test harness rewrite, the requests from CRuby instead of the client built into the test mruby, and the HTTP/2 and HTTP/3 clients. [#706](https://github.com/matsumotory/ngx_mruby/pull/706) added `master_process on`, several workers and reloads, and its `test/t/cases/_workers.rb` runs the several workers that the test of N concurrent `incr` calls of the shared dictionary needs (section 8 of the plan). (b) and (d) also wait for step 4. The order inside the step is a proposal of the 2026-10-04 amendment until the owner decides it. The `serves:` notes on the rows of the plan name the uses of [the ledger](proposals/edge-control.md#use-cases-and-the-features-they-need) that each part serves |
| The AI uses of v3 beyond the agent proxy: the next work comes from [the ledger of the uses](proposals/edge-control.md#use-cases-and-the-features-they-need), first its rows at `designing` ([MCP tool authorization](proposals/edge-control.md#mcp-tool-authorization), whose first recipe uses two tenants and read and write mock tools, [MCP tool profiles](proposals/edge-control.md#mcp-tool-profiles), [MCP progressive retrieval](proposals/edge-control.md#mcp-progressive-retrieval), and [LLM API fallback](proposals/edge-control.md#llm-api-fallback), whose test is in section 8 of the plan), then its rows at `direction`. This row copies the ledger; when they disagree, the ledger holds | `next` | The core stabilization (the row of step 4 above); the fallback also waits for step 7 of the plan (the row above). No API for these uses is designed yet |
| Remove `example/` (`README.md`, `nginx.conf`, `proxy.rb`, `set.rb`, `set2.rb`, `unified_hello.rb`): no CI job starts it, no page links it, and its `/proxy` location picks among `test1.example.com` to `test3.example.com`, which are unreachable; `examples/start/` is checked by `examples.yml` | `next` | Ready to start |
| When a rewrite handler of the location that `Nginx.redirect` runs sleeps and the handler that called `Nginx.redirect` then answers the request, with a status or an exception, the response is followed by the output of the sleeping handler when its timer fires. The request ends and nothing leaks. After an exception nginx closes the connection; for a status, see [the review of #646](https://github.com/matsumotory/ngx_mruby/pull/646#issuecomment-6497236767), item 1. Not a 2.x fix: it needs the rewrite of the row "The async resume rewrite" (#646 leaves it out) | `next`, in the core stabilization of 3.0.0 | Done in [#728](https://github.com/matsumotory/ngx_mruby/pull/728): `Nginx.redirect` takes effect when the handler ends (Q2 of the core stabilization proposal, decided on 2026-11-01) |
| A content handler of the location that `Nginx.redirect` runs from Ruby code ends the request at `Nginx::Async.sleep`, without its output ("Not changed by this release" in entry 2 of [the 2.7.3 release notes](releases/v2.7.3.md)). Not a 2.x fix: the handler that called `Nginx.redirect` goes on after the call and may answer the request itself | `next`, in the core stabilization of 3.0.0 | Done in [#728](https://github.com/matsumotory/ngx_mruby/pull/728): `Nginx.redirect` takes effect when the handler ends (Q2 of the core stabilization proposal, decided on 2026-11-01) |
| A content handler that sleeps in `Nginx::Async.sleep` and then calls `Nginx.redirect` with a local URI: the client gets 200 and the body of the target, and the access log has 500. Run on 2026-10-31 on `next` with [#680](https://github.com/matsumotory/ngx_mruby/pull/680), nginx 1.31.8 with ASan and UBSan: `"GET /sleep_redirect HTTP/1.0" 500 6`. The same with a URL that nginx answers with 302 logs 302. A rewrite handler goes through the same code in `ngx_mrb_post_fiber` (read from the source, not run here), and `master` has the same code; [#646](https://github.com/matsumotory/ngx_mruby/pull/646) records this in its body. No test holds this yet. Not a 2.x fix: it is neither a stability nor a security fix, and `master` gets only the minimal fix of the amended decision (c) | `next`, in the core stabilization of 3.0.0 | Done in [#728](https://github.com/matsumotory/ngx_mruby/pull/728): `Nginx.redirect` takes effect when the handler ends (Q2 of the core stabilization proposal, decided on 2026-11-01) |
| A proposal of the sessions for the rewrite, not a decision: let `Nginx::Async::HTTP.sub_request` work in a content handler after `Nginx::Async.sleep`, where it raises `RuntimeError` since 2.7.3 because nginx would not finish the request after the subrequest | `next`, in the core stabilization of 3.0.0 | Done in [#722](https://github.com/matsumotory/ngx_mruby/pull/722): the owner decided Q1 of the core stabilization proposal on 2026-11-01 |
| The async resume rewrite (decision (c) of 2026-10-04, amended on 2026-10-29: the rewrite of how resumed handlers end in `src/http/ngx_http_mruby_async.c`, which includes the resume of a handler after `Nginx::Async::HTTP.sub_request` from its own request). No pull request exists | `next`, in the core stabilization of 3.0.0 | Done for the timer in [#715](https://github.com/matsumotory/ngx_mruby/pull/715), for subrequests in [#722](https://github.com/matsumotory/ngx_mruby/pull/722), and for `Nginx.redirect` in [#728](https://github.com/matsumotory/ngx_mruby/pull/728); a timer still resumes a handler itself only inside an internal redirect that an `mruby_set` handler, a log handler or a filter makes inside the Ruby call |
| The generated reference of the site (Pillar F of the plan): the directives from the `ngx_command_t` tables, the Ruby API with YARD and yard-mruby, the C API with Doxygen. `site/scripts/check-reference.mjs` checks, among other things, that each directive name has a heading in `docs/directives/README.md`; the pages are written by hand | `next` | Ready to start; no step of section 6 of the site proposal produces it yet |
| The words of the docs that do not follow [the glossary](glossary.md) yet, all in [the edge-control proposal](proposals/edge-control.md): "AI traffic" without a definition at its first use (the title), "AI clients" (Purpose and two rows of the ledger, where the glossary writes AI application or agent), "LLM API fallback" (a row and a heading, where it writes model API), and "adapter" in its section on MCP tool profiles, which the site and the guides write as a versioned backend MCP server since the pull request that wrote the Japanese terms in katakana. [#729](https://github.com/matsumotory/ngx_mruby/pull/729) replaced "LLM proxy" as the name of the component (the documents index, the home page, the navigation) and updated the glossary's section "Examples in ngx_mruby's pages" to the words of the pages | `next` | Ready to start: a pull request to the proposal that defines "AI traffic" at its first use with the four kinds of traffic it covers, and writes AI application or agent and model API. The anchor `#llm-api-fallback` stays, since the site links it |

## How a session continues

Use [Continuing shared work](DEVELOPMENT.md#continuing-shared-work) for
startup, ownership, checkpoints, temporary files and resumption. The rules
are in [AGENTS.md](../AGENTS.md#session-handoff); this file records the
queue and decisions, while each PR records its current head and evidence.
The procedure applies to Claude, Codex and human contributors alike.

## Private material

Vulnerability reports and their fixes are handled privately as
[SECURITY.md](../SECURITY.md) describes; this file does not record them.

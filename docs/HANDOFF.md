# Handoff: the state of the work

## State as of 2026-11-03 (16:23 JST)

- Heads: `next` is `60ba72f86`, the merge of
  [#760](https://github.com/matsumotory/ngx_mruby/pull/760); `master` is
  `801d78b48`. `next` contains `master` through `382639258` in
  [#757](https://github.com/matsumotory/ngx_mruby/pull/757). `v2.x` mirrors
  `master`. The latest published release is 2.7.4.
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
- [#734](https://github.com/matsumotory/ngx_mruby/pull/734), the merge of
  `master` at `0f865ed4a` into `next`, is merged (`3dfe8d05f`).
- [#737](https://github.com/matsumotory/ngx_mruby/pull/737) (base
  `next`) is merged: `site.yml` runs on the push to `next` only, without
  the browser lanes, and `npm run check:ci` in `site/` runs its checks and
  every browser check locally (the owner's decision of 2026-11-02 under
  "Decisions").
- The core stabilization is done with #735, and its proposal is archived
  (the row of step 4 under "Queue").
- [#739](https://github.com/matsumotory/ngx_mruby/pull/739) (base
  `master`) is merged (`5440e7a0e`): `site-v2.yml` runs only on
  `workflow_dispatch`, and a pull request to `master` checks the 2.x pages
  locally. It is included in `next` through #746.
- [#740](https://github.com/matsumotory/ngx_mruby/pull/740) is merged on
  `master`: a rewrite handler that returns `Nginx::DECLINED` after
  `Nginx::Async.sleep` keeps the status of the request.
- [#751](https://github.com/matsumotory/ngx_mruby/pull/751), the repeated
  HTTP sleep regression, merged as `63c6b7152` at 03:41 JST. Its local
  validation, independent review, CI and publication checks passed.
- [#756](https://github.com/matsumotory/ngx_mruby/pull/756) merged the HEAD
  connection fix into `next` as `f1f102966` at 04:09 JST. Its combined suite
  passed 759 cases, local soak/performance/nginx-tests/site/example checks
  passed, and the independent review and all 15 CI checks passed. The
  automatic publication and exact public revisions were verified
  ([checkpoint](https://github.com/matsumotory/ngx_mruby/pull/756#issuecomment-6586223151)).
- [#754](https://github.com/matsumotory/ngx_mruby/pull/754) merged into
  `master` as `382639258` at 04:18 JST. It updates the pinned workflow-analysis
  Action from v0.7.1 to v0.8.0 while retaining zizmor 1.31.1 and the existing
  policy. The PR records the local audit, independent review and CI.
- [#757](https://github.com/matsumotory/ngx_mruby/pull/757) merged the
  workflow-analysis Action pin into `next` at 04:38 JST. Publication and
  cleanup are complete. The equivalent next proposal in
  [#755](https://github.com/matsumotory/ngx_mruby/pull/755) was closed.
- [#758](https://github.com/matsumotory/ngx_mruby/pull/758) merged stream
  sleep measurement as `8beaaa381` at 05:10 JST. The 13-scenario soak,
  16-scenario performance comparison, independent review, CI and publication
  checks passed; cleanup is complete
  ([checkpoint](https://github.com/matsumotory/ngx_mruby/pull/758#issuecomment-6587499248)).
- [#759](https://github.com/matsumotory/ngx_mruby/pull/759) merged the public
  2.7.5 release-note check as `f058927cb` at 05:30 JST. The seven preceding
  PRs and English/Japanese notes were compared. Local checks, the 14-scenario
  cumulative performance comparison, all 17 build configurations,
  independent review and publication checks passed; cleanup is complete
  ([checkpoint](https://github.com/matsumotory/ngx_mruby/pull/759#issuecomment-6587883874)).
  The check did not publish a release or create a tag.
- [#760](https://github.com/matsumotory/ngx_mruby/pull/760) merged as
  `60ba72f86` at 14:16 JST. It preserves every copper CTA edge and balances
  the Japanese hero text and logo. The automatic site publication passed.
- Open: the documentation-only clarification of the unchanged
  empty-subrequest response is prepared for review on
  `codex/subrequest-empty-note`. Local site checks and independent semantic
  and visual review passed; its PR records the final head and checks.
- [#750](https://github.com/matsumotory/ngx_mruby/pull/750) added current
  3.x documentation before the existing 2.x footer link in both languages.
  It merged as `c440a15dc`; local checks, independent review, CI and
  [publication verification](https://github.com/matsumotory/ngx_mruby/pull/750#issuecomment-6581730560)
  passed.
- [#752](https://github.com/matsumotory/ngx_mruby/pull/752) merged into
  `master` as `9acbd8530` at 02:22:44 JST. A successful known-length HEAD
  response finalized by the output body filter keeps an otherwise reusable
  connection for the following GET. Author and independent suites matched:
  the test-only commit failed the three new filtered-HEAD cases, and the fix
  passed all 362 tests. All CI checks and both performance comparisons passed;
  [the independent review](https://github.com/matsumotory/ngx_mruby/pull/752#issuecomment-6583615939)
  has no outstanding findings. The automatic site publication and the
  public 2.x revision were verified ([checkpoint](https://github.com/matsumotory/ngx_mruby/pull/752#issuecomment-6584119833)).
- [#753](https://github.com/matsumotory/ngx_mruby/pull/753) groups the
  Japanese homepage introduction into two paragraphs without changing its
  CSS or English text. Its full site checks, independent review, CI and
  [published-page checks](https://github.com/matsumotory/ngx_mruby/pull/753#issuecomment-6584456285)
  passed. The integration retains that component unchanged.
- [#747](https://github.com/matsumotory/ngx_mruby/pull/747), the homepage
  reading-order and local-trial correction, merged at 2026-11-02 23:59:24
  JST as `fad853820`. Its local checks, independent review and CI passed.
  The [site run](https://github.com/matsumotory/ngx_mruby/actions/runs/41467177215)
  passed and published `fad853820`. The public documentation index matched
  that clean revision; twelve live-page checks and the English/Japanese
  desktop/mobile views passed ([publication checkpoint](https://github.com/matsumotory/ngx_mruby/pull/747#issuecomment-6580515876)).
- [#746](https://github.com/matsumotory/ngx_mruby/pull/746) imported the
  earlier master changes and aligned the shared recording and coordination
  rules. Its Linux suite passed with nginx 1.31.8 (Total 753, OK 753,
  KO 0, Crash 0); its full local site check passed on `1f5cc482c` in
  446 seconds. Independent review, all four CI build cells, `ci-ok`, CodeQL
  and zizmor passed.
- [#748](https://github.com/matsumotory/ngx_mruby/pull/748) aligned the
  master recording rules and summarized existing decisions in CI guidance
  and the English/Japanese 2.7.3 release notes. Its full local site check
  passed in 464 seconds without skips, and independent review and CI passed.
  [#749](https://github.com/matsumotory/ngx_mruby/pull/749) brought these
  changes into `next`, retaining its CI guidance and both release-note
  corrections.


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
  records an adopted decision, its date, scope, rationale and constraints,
  and the older rule it replaces. Proposals are labeled separately and
  change no rule.
- A decision of the owner that is not written there yet is recorded under
  "Decisions", in short, with its date, rationale, technical constraints and the
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

These records state the agreed requirements, rationale and technical
constraints, with dates. Proposals are identified separately from adopted
decisions. Conversation quotations and attribution are not a substitute for
checking whether a decision fits the evidence and requirements.

- **2026-11-02, public records.** Public commits, PRs, issues and documents
  contain only the relevant decision and technical requirements. Working
  documents and handoffs, whether public or private, record intent, reasons,
  constraints and decisions without quoting conversations or using attribution
  to justify a conclusion. Do not copy
  private conversation text, message identifiers or personal environment
  details. Link an already-public decision when available. Existing public
  git history is not rewritten without an explicit decision; any sensitive
  historical content is reported privately.
- **2026-11-02, homepage follow-up.** Review the entire page, including the
  hero, section introductions, use cases, local trial steps, documentation
  links and footer.
  Shared styles give each content role a consistent readable width,
  alignment and spacing. Continuous introductory prose stays in one column;
  individual use-case articles may share a row. The four documentation
  links form a compact ordinary list. Keep meaningful paragraphs, glossary
  terms and technical explanations without promotional language. Inspect
  the complete desktop and mobile pages independently; passing mechanical
  checks alone does not establish visual quality. The local trial follows
  prerequisites, startup, request, expected result and further instructions.
  The homepage PR can progress independently of the master-to-next merge.
- **2026-11-02, development coordination.** Codex continues PR preparation,
  independent review, eligible merges, handoff maintenance, release
  preparation and contributor work under AGENTS.md. Independent PRs may
  progress in parallel with explicit ownership, remaining work, blockers and
  next actions. Serialize dependencies, conflicting edits and competing
  expensive checks; use agents where they shorten completion time without
  duplicating work. Review and merge gates remain unchanged. Release
  publication needs permission for that release;
  advisory publication remains with the owner.
- **2026-11-02, release publication.** After the release check and permission
  for that release, the session publishes the release and its tag; the owner
  publishes advisories. #731 and #732 record the procedure in AGENTS.md,
  `docs/releases/README.md` and `docs/DEVELOPMENT.md`. The earlier permission
  of 2026-10-29 applied to 2.7.2 only and was carried out by #624.
- **2026-11-02, CI.** Local checks must be thorough; CI covers other build
  environments and deployment without repeating local browser checks.
  PRs run neither `site.yml` nor `site-v2.yml`. The push to `next` builds,
  checks and deploys the site; a push to `master` dispatches that run.
  `npm run check:ci` supplies the local site and browser checks. A changed
  base requires another PR run only when both sides changed code or tests.
  The build matrix, sanitizers, valgrind and performance lane remain. #737
  and #739 implement this decision. The category comment remains in Queue.
- **2026-11-02, terminology.** Models, agents, their requests and the AI
  gateway use the terms in the glossary and section 7 of the site design.
  Japanese uses katakana for the glossary terms and preserves identifiers
  in English. The homepage heading follows the same terms.
- **2026-11-01, site implementation.** Use Astro and repository-owned
  components in place of Starlight, as section 5.4 of the site design
  describes (#700, #708, #713). Work that can be completed together is not
  split into unnecessary stages. The mobile layout pattern is 402px;
  root sizing follows section 4.4 of that design.
- **2026-11-01, build coverage and next work.** Code/test PRs run four
  standard matrix cells: nginx mainline static, stable dynamic, the
  sanitizer cell and the valgrind cell. Nightly runs, tag runs and the
  pre-tag check with `full-matrix` retain full coverage (#702, #704).
  The harness extension for multiple workers and reload precedes the
  core stability work. Discussions are enabled and the wiki is disabled.
- **2026-11-01, handler semantics.** Q1 to Q6 are recorded in section 9 of
  [the core stabilization proposal](proposals/archive/core-stabilization.md)
  (#710): support the specified waits, apply redirects at handler completion,
  preserve HTTP/1.x continuation after client close and discard a waiting
  fiber without running ensure when its request ends, execute the UDP
  handler once while it waits, raise RuntimeError for sub_request inside
  mruby_set while preserving sleep, and isolate handler results so a
  server rewrite without a result advances to the next phase.
- **2026-10-31, local verification.** Test locally before making a PR ready;
  CI is not the place to discover avoidable implementation errors (#692,
  #693). CodeQL excludes vendored upstream trees, whose existing alerts
  were dismissed as upstream code rather than reported without a confirmed
  defect and patch.
- **2026-10-31, mruby performance.** Keep mruby's default GC settings after
  the measurements failed to remove the extra GC work without increasing
  other work. The accepted mruby 4.1 differences are recorded in #678 and
  "Known differences" in the test guide. #696 implements the specific
  4.0-to-4.1 auth allowance in `test/perf/accepted.txt`; it does not authorize
  a 3.3-to-4.1 allowance before the first v3 tag. Other WARN/FAIL results
  still require the owner's decision.
- **2026-10-31, upstream reports.** Report a confirmed mruby defect only
  when it warrants an upstream fix beyond ngx_mruby's convenience and a
  patch can be provided. This belongs in AGENTS.md's other-repository rules
  when that subsection is next updated.
- **2026-10-31, completed 2.7.3 publication.** The separately published
  stream advisory and the regression fix of #698 shipped with 2.7.3.
  The published releases and advisories are linked in State.
- **2026-10-29, maintained gems.** Update owner-maintained gems when that
  resolves compatibility; removal is acceptable when an underlying library
  is no longer maintained. AGENTS.md records this rule (#637, #639).
- **2026-10-29, v3 scope.** The decisions on mruby 4.1.0-rc2, removal of
  auto-ssl from next, agent-proxy work, subrequest empty responses and empty
  output filters are in items 1, 6 and 15 of section 7 of the v3 plan.
  GitHub releases include the behavior changes in English and Japanese.
  HANDOFF remains English with a Japanese notice.
- **2026-10-04, async behavior, amended 2026-10-29.** Support sleep in a
  content handler. On next, a rewrite handler with neither output nor an
  explicit result proceeds to the next phase (#720); master keeps the
  compatible 2.x behavior. The broader resume rewrite belongs on next,
  while master receives the minimum stability fixes. #715, #722 and #728
  implement the main rewrite; waits inside another mruby call remain queued.
  The plan is updated as the remaining decisions are implemented.
- **Earlier recorded decisions.** The mruby steps and bilingual
  "Why it changed" entries are recorded in the v3 plan and release-note
  guide (#561, #575). The Nginx::Var method-lookup and introspection choice
  is recorded in its archived proposal and v3 notes (#610). The master
  performance lane brings measurement and CI without Nginx::Debug (#601).
  The selected site specimens are recorded in the site design (#607).

## Work in progress

### Japanese pages of the site

- [#705](https://github.com/matsumotory/ngx_mruby/pull/705) (base `next`,
  merged as `fe9a3f2bf`) translated six of the seven pages of
  `NOT_TRANSLATED_YET` in `site/scripts/lib/site.mjs`: the contributing
  page, development, the test guide, the releases page, security and the
  trust boundary. The handoff page stays in English with a Japanese
  notice, as the owner decided on 2026-10-29 (Q2 in section 7 of
  `docs/proposals/site.md`), so
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
| The category comments of `test/ci/changes.sh` describe local site checks and next-push publication after the CI changes of 2026-11-02 (#737 and #739) | `master` and `next` | Updated on `next` with stream measurement; the matching comment-only update on `master` remains |
| Merge `master` into `next` after each merge into `master`. Model: #573. | `next` | Merged through `382639258` in [#757](https://github.com/matsumotory/ngx_mruby/pull/757) |
| Public work records summarize requirements, rationale and constraints, distinguish decisions from proposals, and omit conversation quotations. Shared rules and next documents were aligned in #746; master rules and the corresponding English/Japanese 2.7.3 entries were aligned in #748 | `master` and `next` | #746 and #748 merged; #749 brought the remaining release-note corrections to `next` |
| The homepage shares coherent width, alignment and spacing across the hero, section introductions, use cases and footer; continuous introductions read in one column (see "Decisions") | `next` | Merged in [#747](https://github.com/matsumotory/ngx_mruby/pull/747) as `fad853820`; site deployment and publication checks passed ([checkpoint](https://github.com/matsumotory/ngx_mruby/pull/747#issuecomment-6580515876)) |
| The fixed heading 「アップグレードの前に読む挙動の変更」 of the Japanese release notes ends with one character on its own line at 402 px, in `v2.7.5.ja.md` and in `v2.7.4.ja.md`. The heading and template are corrected in #745, with the previous anchors preserved | `master` (reaches `next` by the merge) | Merged in #745 and included in `next` through #746 |
| Subrequests: the entry of #574 in `docs/releases/v3.0.0.md` and `.ja.md` explains the unchanged 500 from a subrequest content handler that returns `Nginx::HTTP_OK` without output, the 200 from nginx's own `return 200;`, and why `auth_request` treats the retained 500 as an error instead of allowing the request | `next` | Clarified on `codex/subrequest-empty-note`; local site checks and independent semantic and visual review passed |
| A known-length HEAD response finalized by an mruby output body filter keeps its connection for the following GET ([the review of #574](https://github.com/matsumotory/ngx_mruby/pull/574#issuecomment-6166201549), should fix 1; #628 reproduced it) | `master`, then `next` | Fixed on master in [#752](https://github.com/matsumotory/ngx_mruby/pull/752) with failing-test and passing-fix commits, and integrated into next in [#756](https://github.com/matsumotory/ngx_mruby/pull/756). The combined suite passed all 759 tests; local validation, independent review, CI and publication checks passed. Both release lines and the current Filter reference describe the known-length HEAD scope |
| An end-to-end benchmark scenario: throughput and p50 and p99 latency with `oha` or `h2load`, planned in AGENTS.md "Design principles" and in section 8 of the plan, which also records the reference proxy end to end | `next` | Ready to start; where the results are recorded is decided when it is added (AGENTS.md) |
| Site: steps 1 to 4, 6 and 7 are merged (#591, #607, #614, #617–#623, #626, #629–#632, #653–#657), and the site is deployed from `next`. Step 5, the Japanese pages, is merged (#705 for six pages, #703 for the 2.x release notes on `master`); the handoff page stays English with a notice, and `NOTES_ONLY` of `check-japanese-lines.mjs` still lists four release notes (the subsection "Japanese pages of the site" of "Work in progress") | `next` for `site/`; `master` for 2.x sources | Still open: the emptying of `NOTES_ONLY` once `master` is merged into `next`; the site on Astro without Starlight (5.4 of the site proposal, #700, the owner's decision of 2026-11-01), whose first layer, the own shell beside Starlight behind `NGX_MRUBY_SITE_SHELL=own`, is merged in #708, and whose rest is #713 (from a Codex session, taken over by Claude Code for the browser acceptance), which also changes the iPhone width to 402px with the root size of 4.4; the 3.x development banner of 3.4; and the observability and certificate-lookup sample prerequisites of #619. Q9 is done (Discussions on, wiki off, 2026-11-01) |
| nginx-tests with the modules that its skipped files need: a build with the options of `test.sh` and `--with-http_v2_module`, `--with-http_v3_module`, `--with-stream_ssl_module`, `--with-mail` and the other modules that "Results of nginx-tests" in `docs/test/README.md` lists (in the CI run of #602, 189 of the 209 skipped files need a module that `test.sh` does not build), with and without ngx_mruby, in the `nginx-tests` workflow | `next` | Ready to start: #602 is merged |
| nginx-tests with ngx_mruby code configured: runs that add handlers or filters with code for every request through `TEST_NGINX_GLOBALS_HTTP` (the Pillar E row of the plan), compared with the run without code. The pull request decides which code; since [#720](https://github.com/matsumotory/ngx_mruby/pull/720), a rewrite handler that ends without `Nginx.return` goes on to the next phase on `next` | `next` | Ready to start: #602 is merged |
| Test harness rewrite (step 2 of section 6 of the plan; Pillar E): [#635](https://github.com/matsumotory/ngx_mruby/pull/635) (merged, `c4e6ac6cc`) made `test.sh` stop only the nginx that it started, by its pid, with no `killall` or `pkill`, and send SIGTERM again while the single nginx process still runs, because that process can miss a SIGTERM that arrives right before it waits for events (the run at `7926f72`, where nginx stayed in `epoll_wait()` for 20 minutes after it logged the SIGTERM: "Stopping nginx" in `docs/test/README.md` has the cause and the measurements). [#641](https://github.com/matsumotory/ngx_mruby/pull/641) (merged, `be559a017`) added `TEST_SH_PORT_OFFSET`, which moves every port of the suite, so that two checkouts can run `test.sh` at the same time ("Ports" in `docs/test/README.md`). [#706](https://github.com/matsumotory/ngx_mruby/pull/706) added nginx with `master_process on` and several workers, and a reload in the middle of a case: `test/t/cases/_workers.rb` starts such an nginx from `test/conf/workers/`, and `test/t/cases/workers.rb` checks that each of four workers answers from an mrb_state of its own, and that across a SIGHUP the old workers finish an `Nginx::Async.sleep` and an `Nginx::Stream::Async.sleep` in flight while the new configuration answers ("Several workers and reloads" in `docs/test/README.md`). Still to do, in pull requests of their own: requests from CRuby instead of the client built into the test mruby for the other cases, and HTTP/2 and HTTP/3 clients. A should fix of the review of #635 waits for the pull request that next changes `test/build_release.sh`, an input of the `perf` job: its comment still says that `test.sh` kills every running nginx. The readiness wait of #593 is the first part, on `next` since the merge of `master` at `6b27f08da` | `next` | Several workers and reloads: done by [#706](https://github.com/matsumotory/ngx_mruby/pull/706) (decision (3) of 2026-11-01). Requests from CRuby and the HTTP/2 and HTTP/3 clients: ready to start |
| CI runs only the jobs that a change needs: done on both branches by [#676](https://github.com/matsumotory/ngx_mruby/pull/676), [#685](https://github.com/matsumotory/ngx_mruby/pull/685), [#686](https://github.com/matsumotory/ngx_mruby/pull/686) and [#692](https://github.com/matsumotory/ngx_mruby/pull/692) on `next`, and [#679](https://github.com/matsumotory/ngx_mruby/pull/679), [#690](https://github.com/matsumotory/ngx_mruby/pull/690) and [#693](https://github.com/matsumotory/ngx_mruby/pull/693) on `master`; the owner's decisions and rules are in AGENTS.md and `docs/test/README.md`. Left: a pull request to `master` that gives it the lines of `test/ci/changes.sh` and `test/ci/changes_test.sh` that `next` has (on `master`, a change of `test/soak/mock_llm_test.rb` alone runs that check only with the label `perf`); the first run of the whole build matrix through `fromJSON` (should fix 4 of [the review of #686](https://github.com/matsumotory/ngx_mruby/pull/686#issuecomment-6541409852)), which the nightly run under valgrind makes; and from [the review of #693](https://github.com/matsumotory/ngx_mruby/pull/693#issuecomment-6542620420): local commands for the build of the 2.x pages in "The 2.x pages of the site" of `docs/test/README.md` on `master` (should fix 1 and 2), and on both branches, a sentence in "Required status check" that a draft run queued after the ready run cancels it in `site-v2`, `codeql` and `zizmor`, or a concurrency group that includes the draft state (should fix 4). Four cells: code-changing pull requests run four cells of the build matrix: done on both branches by [#702](https://github.com/matsumotory/ngx_mruby/pull/702) on `next` (`bf1b742b7`) and [#704](https://github.com/matsumotory/ngx_mruby/pull/704) on `master` (`166341b93`), with `build` `standard` of `test/ci/changes.sh`; every cell runs only nightly, on a tag, in the check pull request before a tag (the label `full-matrix`, which exists in the repository) and on "Run workflow" without `base` | `master`, `next` | Ready to start |
| nginx floor for v3 (item 2 of section 7 of the plan): drop the cells for nginx 1.26.3 and 1.28.3 from the `build` matrix of `.github/workflows/test.yml` and document the floor of 1.30 stable and 1.31 mainline | `next` | Ready to start: #601's change to `.github/workflows/test.yml` is on `next` since the merge of `master` at `6b27f08da` |
| OpenSSL 3.5 and 4.0 (item 3 of section 7 of the plan): cells for OpenSSL 3.5 as the baseline and 4.0 in `.github/workflows/test.yml`, which builds `1.1.1w` today; drop 1.1.1 and 3.0, and check ENGINE and the removed APIs in ngx_mruby and the gems | `next` | Ready to start: #601's change to `.github/workflows/test.yml` is on `next` since the merge of `master` at `6b27f08da` |
| `build_config.rb` rewrite with explicit gems (step 3 of section 6; Pillar A): `iij/mruby-env` and `iij/mruby-process` replaced by core gems, the choice between core `mruby-regexp` and `mruby-onig-regexp` (item 1 of section 7 keeps onig-regexp for 3.0), `monochromegane/mruby-secure-random` and `iij/mruby-digest` replaced, and `mruby-vedis` and `mruby-localmemcache` out of the default build | `next` | Ready to start: #606, which edits the same file, and #678 (mruby 4.1.0-rc2, whose core gems replace `env` and `process`) are merged |
| mruby 4.1.0 (step 3 of section 6; item 1 of section 7). The owner decided on 2026-10-29 that `next` bundles `4.1.0-rc2` now and moves to 4.1.0 in a small subtree pull request when it is tagged. `next` bundles `4.1.0-rc2` since [#678](https://github.com/matsumotory/ngx_mruby/pull/678). The step to 4.1.0: `./update-mruby-subtree 4.1.0`, `vendor-mruby-prism` if the gitlink of Prism moves, the lock, and the release notes | `next` | The tag `4.1.0` of mruby |
| Step 4 of section 6 of the plan, the core stability work of Pillar B (execution context, response finalization, fiber lifecycle, common layer, headers and variables, and the two agent proxy rows), then `v3.0.0-alpha.1` | `next` | The core stabilization is done: [the core stabilization proposal](proposals/archive/core-stabilization.md) was implemented in [#712](https://github.com/matsumotory/ngx_mruby/pull/712), [#714](https://github.com/matsumotory/ngx_mruby/pull/714), [#715](https://github.com/matsumotory/ngx_mruby/pull/715), [#720](https://github.com/matsumotory/ngx_mruby/pull/720), [#722](https://github.com/matsumotory/ngx_mruby/pull/722), [#727](https://github.com/matsumotory/ngx_mruby/pull/727), [#728](https://github.com/matsumotory/ngx_mruby/pull/728) and [#735](https://github.com/matsumotory/ngx_mruby/pull/735) (the last on 2026-11-02), is archived, and the model is in [How a handler waits](DEVELOPMENT.md#how-a-handler-waits-the-record-of-its-fiber) of `docs/DEVELOPMENT.md`. Left in this step: the Pillar B rows of the plan on the execution-context type, on headers, on `Nginx::Var`, on the filter handler pointers and on the table-driven directives, the common layer beyond the fiber (code loading, upstream switching, error logging, the duplicate directive check), the rest of the async resume rewrite (the row below), and the two agent proxy rows (log handlers before `access_log`, and `mruby_variable`). Started by the owner's decision of 2026-11-01 to extend the harness so that `test.sh` tests `master_process on`, several workers and reloads, and then to rework the core fiber lifetime and response completion. [#706](https://github.com/matsumotory/ngx_mruby/pull/706) made that extension; the requests from CRuby and the HTTP/2 and HTTP/3 clients of the row above for the test harness rewrite stay there |
| nginx-tests required: the `nginx-tests` workflow records its results and fails only when a build, the fetch of the suite or `prove` fails. In the runs of 2026-10-28 and 2026-10-29 the build with ngx_mruby and the build without it have the same counts (511 files, 302 passed, 0 failed, 209 skipped). To do: the job fails when the build with ngx_mruby fails a file that the build without it passes, and the job joins the `needs` of `ci-ok` | `next` | Ready to start: the counts are the same in every run since #602 |
| The `perf` job in the `needs` of `ci-ok`, and the "In CI" text of `docs/test/README.md` (the sentences that call the job advisory and say that a `FAIL` does not block a merge, under "Performance comparison with callgrind") aligned with the rule of AGENTS.md "Design principles", under which a session does not merge while the job reports `FAIL` or `ERROR` | `next`, then `master` | Ready to start |
| Soak: record `Pss` and `Private_Dirty` from `/proc/<pid>/smaps_rollup` beside `VmRSS`, then bound their slope over more windows, set after measuring (the Pillar E row on memory accounting). Today `test/soak/soak.rb` bounds `VmRSS` by a step and a total and checks the counters of `Nginx::Debug.stats` | `next` | Ready to start |
| Soak and perf for stream: the normal TCP `stream_sleep` scenario checks exact response bytes and EOF, observes `stream_timers` and `stream_fibers`, and collects the stream VM before memory samples. The performance build includes stream and counts completed sessions (section 7 of [the core stabilization proposal](proposals/archive/core-stabilization.md)) | `next` | Merged in [#758](https://github.com/matsumotory/ngx_mruby/pull/758) as `8beaaa381`; local checks, independent review, CI, publication verification and cleanup passed |
| The case `async_sleep_many.rb` of section 6 of [the core stabilization proposal](proposals/archive/core-stabilization.md): a handler that sleeps 1,000 times for 1 ms answers, and `Nginx::Debug.stats` shows the same `timers` and `gc_root_fibers` before and after | `next` | Merged in [#751](https://github.com/matsumotory/ngx_mruby/pull/751) as `63c6b7152`; local checks, independent review, CI and publication checks passed. The normal test build enables the counters, and each HTTP exchange has a 60-second limit |
| The comments in `src/` and `test/` that name `docs/proposals/core-stabilization.md` (20 places, `git grep -n core-stabilization -- src test`): the proposal is now `docs/proposals/archive/core-stabilization.md`. To do: the next pull request that changes those files points them at the new path, or at the section "How a handler waits" of `docs/DEVELOPMENT.md` | `next` | The next code pull request that touches those files (a comment-only change of `src/` would run the whole build matrix) |
| The ASan cell with `-DNGX_DEBUG_PALLOC -DNGX_DEBUG_MALLOC` (3.7 of the plan; the cell of `test.yml` sets only `-fsanitize` and `-fno-omit-frame-pointer`), so that ASan sees an access that runs from one pool allocation into the next. To do: a run of the suite with these flags, whose findings follow [SECURITY.md](../SECURITY.md), then the cell | `next`, `master` | Ready to start |
| A test build with `ngx_otel_module` (nginx/nginx-otel, built with CMake against the nginx source of `test.sh`) and an OTLP receiver for the case of the observability sample of 3.2 of the site proposal | `next` | The harness rewrite (the row above), of which this waits for what is left: the requests from CRuby instead of the client built into the test mruby, and the HTTP/2 and HTTP/3 clients. [#706](https://github.com/matsumotory/ngx_mruby/pull/706) added `master_process on`, several workers and reloads |
| Step 7 of section 6 of the plan, the agent proxy, parts (a) to (e); none exists on `next` | `next` | Parts (a) and (c) start "after the safety net of step 2, beside step 4" (step 7 of section 6 of the plan, decided on 2026-10-29 in item 15 of section 7), so they wait for what is left of that safety net: in the row above for the test harness rewrite, the requests from CRuby instead of the client built into the test mruby, and the HTTP/2 and HTTP/3 clients. [#706](https://github.com/matsumotory/ngx_mruby/pull/706) added `master_process on`, several workers and reloads, and its `test/t/cases/_workers.rb` runs the several workers that the test of N concurrent `incr` calls of the shared dictionary needs (section 8 of the plan). (b) and (d) also wait for step 4. The order inside the step is a proposal of the 2026-10-04 amendment until the owner decides it. The `serves:` notes on the rows of the plan name the uses of [the ledger](proposals/edge-control.md#use-cases-and-the-features-they-need) that each part serves |
| The AI uses of v3 beyond the agent proxy: the next work comes from [the ledger of the uses](proposals/edge-control.md#use-cases-and-the-features-they-need), first its rows at `designing` ([MCP tool authorization](proposals/edge-control.md#mcp-tool-authorization), whose first recipe uses two tenants and read and write mock tools, [MCP tool profiles](proposals/edge-control.md#mcp-tool-profiles), [MCP progressive retrieval](proposals/edge-control.md#mcp-progressive-retrieval), and [Model API fallback](proposals/edge-control.md#llm-api-fallback), whose test is in section 8 of the plan), then its rows at `direction`. This row copies the ledger; when they disagree, the ledger holds | `next` | What is left of step 4 of the plan (the row of step 4 above); the fallback also waits for step 7 of the plan (the row above). No API for these uses is designed yet |
| Remove `example/` (`README.md`, `nginx.conf`, `proxy.rb`, `set.rb`, `set2.rb`, `unified_hello.rb`): no CI job starts it, no page links it, and its `/proxy` location picks among `test1.example.com` to `test3.example.com`, which are unreachable; `examples/start/` is checked by `examples.yml` | `next` | Ready to start |
| What is left of the async resume rewrite (decision (c) of 2026-10-04, amended on 2026-10-29: the rewrite of how resumed handlers end): a wait that starts in a handler that nginx runs inside another mruby call (the location of an internal redirect that an `mruby_set` handler, a log handler or a filter makes inside the Ruby call), or after an internal redirect replaced the module context of the handler, is still resumed by its timer or by the end of its subrequest and ended by `ngx_mrb_post_fiber` in `src/http/ngx_http_mruby_async.c`; a content handler there does not keep the request, so the request ends at the sleep. The rest is done in [#715](https://github.com/matsumotory/ngx_mruby/pull/715), [#722](https://github.com/matsumotory/ngx_mruby/pull/722) and [#728](https://github.com/matsumotory/ngx_mruby/pull/728) (section 12 of [the core stabilization proposal](proposals/archive/core-stabilization.md)) | `next` | Ready to start; no design exists yet |
| The generated reference of the site (Pillar F of the plan): the directives from the `ngx_command_t` tables, the Ruby API with YARD and yard-mruby, the C API with Doxygen. `site/scripts/check-reference.mjs` checks, among other things, that each directive name has a heading in `docs/directives/README.md`; the pages are written by hand | `next` | Ready to start; no step of section 6 of the site proposal produces it yet |
| The "Before" line of the entry on `mruby_set` values that are not Strings in [the 3.0.0 release notes](releases/v3.0.0.md) limits the end of the worker process to the handler that does not wait. The review of [#738](https://github.com/matsumotory/ngx_mruby/pull/738) inferred from the 2.x source (`ngx_mrb_var_set_vector`) that a `to_s` returning something other than a String can end the worker after `Nginx::Async.sleep` too; nobody has run it on 2.x | `next` | Ready to start: run the case on `master` (2.7.4), then write the "Before" line of `docs/releases/v3.0.0.md` and `.ja.md` from the result |
| The documentation group of the site footer links the current 3.x documentation before the other version in both languages, without duplicating the existing 3.x link on 2.x pages (4.10 of [the site proposal](proposals/site.md)) | `next` | Merged in [#750](https://github.com/matsumotory/ngx_mruby/pull/750) as `c440a15dc`; local checks, independent review, CI and publication verification passed |
| The 2.x form of the protected conversion of an `mruby_set` value ([#735](https://github.com/matsumotory/ngx_mruby/pull/735) on `next`): convert the value under `mrb_protect_error`, and a `to_s` that is missing, raises or returns a non-String ends the request with 500 instead of reading the result unchecked; a regression test for the three cases, and the entry under "Behavior changes" of `docs/releases/v2.7.5.md` and `.ja.md`. The owner deferred this work on 2026-11-02 (05:25 JST). | `master` | The owner's go |
| On 2.x, a rewrite handler that sleeps in `Nginx::Async.sleep` and returns `Nginx::DECLINED`, followed by an access handler of the same location that calls `Nginx::Async::HTTP.sub_request` and declines, leaves the request without a response (seen by the reviewer of [#740](https://github.com/matsumotory/ngx_mruby/pull/740) before and after its fix; without the sleep the answer is immediate). Assess on `next` first, where the fiber record of [#714](https://github.com/matsumotory/ngx_mruby/pull/714), [#715](https://github.com/matsumotory/ngx_mruby/pull/715) and [#722](https://github.com/matsumotory/ngx_mruby/pull/722) may already cover it; if 2.x still hangs, a fix with its regression test | `next`, then `master` if needed | Assessed on 2026-11-03: the normal composition completes with the `next` runtime of `c440a15dc`. A 100 ms sleep and its no-sleep control each returned 200, the expected static body and EOF in three requests bounded at 8 seconds (nginx 1.31.8, static suite build with GC stress and debug counters; runtime C statements unchanged). No next fix is indicated by these six requests. The 2.x follow-up remains; it was not rerun here |

## How a session continues

Use [Continuing shared work](DEVELOPMENT.md#continuing-shared-work) for
startup, ownership, checkpoints, temporary files and resumption. The rules
are in [AGENTS.md](../AGENTS.md#session-handoff); this file records the
queue and decisions, while each PR records its current head and evidence.
The procedure applies to Claude, Codex and human contributors alike.

## Private material

Vulnerability reports and their fixes are handled privately as
[SECURITY.md](../SECURITY.md) describes; this file does not record them.

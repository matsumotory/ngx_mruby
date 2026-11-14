# Handoff: the state of the work

## State as of 2026-11-15 (04:00 JST)

- Heads: `master` is `91499f767`, the merge of
  [#811](https://github.com/matsumotory/ngx_mruby/pull/811) (2026-11-15
  03:59 JST; documentation only, below), after `f736bae0c`, the tag
  `v2.7.7` (below): the second of the two merges from the advisories,
  after `7a2724265`, the first, and `cc829db6e`, the merge of
  [#809](https://github.com/matsumotory/ngx_mruby/pull/809) (below). `next` is `fef20e671`, the second of the two merges of the same
  fixes from the advisories into `next` (2026-11-15 02:02 JST), after
  `4fbe72294`, the first, and `dc6a6a6cd`, the merge of
  [#808](https://github.com/matsumotory/ngx_mruby/pull/808) (2026-11-14
  19:36 JST), which brought `master` at `7a72306bb` (#807) into `next`.
  This entry is written in [#810](https://github.com/matsumotory/ngx_mruby/pull/810),
  the open pull request to `next` that merges `master` at `91499f767`
  into `next`. `v2.x` mirrors `master`.
  The latest published release is 2.7.7.
- The release 2.7.7: the tag `v2.7.7` is on `f736bae0c`, and
  [the release](https://github.com/matsumotory/ngx_mruby/releases/tag/v2.7.7)
  was published on 2026-11-15 at 02:06 JST. Two advisories were published
  with it at 02:43 JST:
  [GHSA-cjxv-4q9m-62pf](https://github.com/matsumotory/ngx_mruby/security/advisories/GHSA-cjxv-4q9m-62pf)
  (Moderate; the setters of `Nginx::Request`, the path of
  `Nginx::Async::HTTP.sub_request` and `Nginx::Headers_in/out#[]=` read
  an argument that is not a String without checking its type; they now
  raise `TypeError`) and
  [GHSA-pmjr-f94r-j47g](https://github.com/matsumotory/ngx_mruby/security/advisories/GHSA-pmjr-f94r-j47g)
  (Low; the store of `Nginx::Upstream#server=` and
  `Nginx::Stream::Connection#upstream_server=` across a reload with
  `master_process off`). Both fixes were merged from their advisory pages
  into `master` (`7a2724265`, `f736bae0c`) and into `next` (`4fbe72294`,
  `fef20e671`, in `next`'s form, with the stores in
  `src/common/ngx_mruby_upstream.c` and the test on port 18172 instead of
  18192, which `exception_log.rb` uses on `next`). The tree of
  `f736bae0c` is the tree of the head of the second fix's pull request,
  which contains the head of the first. The check before the tag: the pull
  requests merged into `master` from `v2.7.6` to `cc829db6e` (`master`
  before the fixes) are [#800](https://github.com/matsumotory/ngx_mruby/pull/800),
  [#801](https://github.com/matsumotory/ngx_mruby/pull/801),
  [#803](https://github.com/matsumotory/ngx_mruby/pull/803),
  [#804](https://github.com/matsumotory/ngx_mruby/pull/804),
  [#807](https://github.com/matsumotory/ngx_mruby/pull/807) and #809; the
  release notes needed no correction for them. The callgrind comparison of
  `v2.7.6` with `7a72306bb` has all 14 scenarios `ok`; the largest change
  is -2 instructions per request without GC. The whole build matrix at
  `7a72306bb`
  ([run 43594266917](https://github.com/matsumotory/ngx_mruby/actions/runs/43594266917))
  failed in the four cells of nginx 1.26.3: nginx before 1.27.1 does not
  accept a stream server without a content handler, which the stream
  servers that #803 added to `test/conf/conf.d/stream/52-exception-log-script-methods.conf`
  were. #809 gave them a `return` directive (a change of the test
  configuration only), and its run on its head passed in all 17 cells. The
  push of the tag ran the whole matrix at `f736bae0c`
  ([run 43619287702](https://github.com/matsumotory/ngx_mruby/actions/runs/43619287702)):
  17 cells passed. #811 (`91499f767`) added the links of the two
  advisories to `docs/releases/v2.7.7.md` and `.ja.md`, and reworded two
  lines of the Japanese file whose last line held two characters on the
  site (`check-japanese-lines.mjs`); the release body links both
  advisories in English and Japanese. The site: `site.yml` was started on
  `next` after the release at 03:27 JST
  ([run 43626723963](https://github.com/matsumotory/ngx_mruby/actions/runs/43626723963),
  success), and the home page of ngx.mruby.org names v2.7.7 since 03:31
  JST.
- [#807](https://github.com/matsumotory/ngx_mruby/pull/807) (merged into
  `master` on 2026-11-14 at 19:02 JST as `7a72306bb`) brings the decision
  of 2026-11-12 under "Decisions" (local checks first) to the documents
  of `master`: `AGENTS.md`, `.github/PULL_REQUEST_TEMPLATE.md`,
  `docs/test/README.md` and `docs/DEVELOPMENT.md`. Its two reviews found
  that the local list missed the `files` job and `gem-heads`, that CodeQL
  ran in CI with no reason written down, and that the condition of the
  sanitizer and valgrind runs ("C code and build changes") was not
  defined; #807 fixed these on `master`. #808 (merged on 2026-11-14 as
  `dc6a6a6cd`) merged it into `next` and made the same fixes in `next`'s
  text: the check of the added files and
  `gem-heads` in the local list, CodeQL as the one check kept in CI with
  its reason, the sanitizer and valgrind runs when `test/ci/changes.sh`
  gives `build` `standard` or `full`, the OpenSSL of the docker forms
  (3.0.2 of Ubuntu 22.04) against the OpenSSL 3.5.9 of the cells, and how
  to read `vm.mmap_rnd_bits` from a container. On `master`, the auto-ssl
  case is a second check kept in CI for changes outside its paths; `next`
  has no auto-ssl gem or case.
- The site: the deploy of ngx.mruby.org works again. The run of `site.yml`
  on the push of `9cf8f8a4e`
  ([run 43188350847](https://github.com/matsumotory/ngx_mruby/actions/runs/43188350847))
  had failed in `node scripts/check-japanese.mjs` on
  `docs/releases/v2.7.6.ja.md` and `docs/ja/releases/README.md`. #804
  (base `master`) and #805 (base `next`) fixed both pages, and #805 added
  to "Site CI" of `docs/test/README.md` (and its Japanese page) that a
  merge of `master` into `next` runs `npm run check:ci` on its own head,
  and to condition 2 of "Review and merge" in `AGENTS.md` that the
  session that merges reads the run of `site.yml` that the merge started.
  The run of `site.yml` on the push of `246877177`
  ([run 43572439640](https://github.com/matsumotory/ngx_mruby/actions/runs/43572439640))
  succeeded.
- [#803](https://github.com/matsumotory/ngx_mruby/pull/803) (merged into
  `master` on 2026-11-14 at 17:00 JST as `66b284a94`) brings to 2.x the
  protection of the `inspect` and `backtrace` calls that ngx_mruby makes
  when it writes an exception to `error.log` (the 2.x counterpart of #796
  and #799), with its cases (`test/t/cases/exception_log_script_methods.rb`,
  ports 18091, 12383 and 12389) and the entries of
  `docs/releases/v2.7.7.md` and `.ja.md`. Its re-review found no must fix
  and no should fix. [#806](https://github.com/matsumotory/ngx_mruby/pull/806), which merged it into `next`,
  keeps `next`'s `src/` (which has the same protection in
  `src/common/ngx_mruby_log.c`), runs the new cases on `next`'s code, and
  adds the three ports to the list of `AGENTS.md`. Its body has the state
  and the checks.
- The release 2.7.6: the tag `v2.7.6` is on `a8ef5ecb8` (2026-11-12 15:53
  JST), and [the release](https://github.com/matsumotory/ngx_mruby/releases/tag/v2.7.6)
  is published. Two advisories were published with it at 15:58 JST:
  [GHSA-r6wq-r8rh-6rc3](https://github.com/matsumotory/ngx_mruby/security/advisories/GHSA-r6wq-r8rh-6rc3)
  (Moderate; an HTTP log handler's `Nginx.rputs`/`Nginx.echo` could write an
  extra response on a persistent connection) and
  [GHSA-79vp-37cx-547v](https://github.com/matsumotory/ngx_mruby/security/advisories/GHSA-79vp-37cx-547v)
  (Moderate; an mruby content handler or body filter in an SSI subrequest
  could split the parent HTTP response). The release body links both
  advisories in English and Japanese.
  [#801](https://github.com/matsumotory/ngx_mruby/pull/801) (`298e0dd11`)
  added the two advisory ids to `v2.7.6.md`, `.ja.md` and the release body;
  its independent review found no must-fix, the 2.x pages check passed, and
  `ci-ok` passed. [#800](https://github.com/matsumotory/ngx_mruby/pull/800)
  (`aa3d9798a`) added to the "Security fixes" of `docs/releases/README.md`
  how a security fix is merged from the advisory page and the temporary
  `protected-lines` bypass that merge needs. Both #801 and #800 are
  documentation only, and reached `next` with #802. The
  check before the tag: the pull requests merged into `master` from `v2.7.5`
  to the release are #768, #772, #773, #774, #775, #778, #781, #784, #786,
  #790 and #792; each has its entry under "Behavior changes", "Fixes" or
  "Build and test changes" in `v2.7.6.md`/`.ja.md`, or changes nothing a
  configuration, script or build observes (docs, CI and `test.sh`), so no
  separate public check pull request was opened. The whole build matrix ran
  at `65ce972e1` (master before the security fixes) in
  [run 43018470114](https://github.com/matsumotory/ngx_mruby/actions/runs/43018470114)
  (success); the tag push ran the whole matrix at `a8ef5ecb8` in
  [run 43171298562](https://github.com/matsumotory/ngx_mruby/actions/runs/43171298562)
  (success). The callgrind comparison of `v2.7.5` (`801d78b48`) with the
  release tree (`master` + both security fixes, `13195fc71`) has every
  scenario `ok`, the largest change `ruby_call_10` at +0.84% without GC
  (below the 3% WARN threshold); the fixes add a subrequest branch to three
  finalization sites and one read-body check and touch no measured
  scenario's hot path. The two fixes were merged from their advisory pages
  (the log-handler fix, then the SSI subrequest fix) with the
  `protected-lines` admin bypass set to `always` for the merges and
  restored to "pull request only" afterwards.
- The release 2.7.5: [the release](https://github.com/matsumotory/ngx_mruby/releases/tag/v2.7.5)
  was published on 2026-11-04 at 14:49:05 JST. Its tag points to
  `801d78b4831965326adb1f9b216a99740b5ab92e`.
  [GHSA-wx6w-gpg3-cmc3](https://github.com/matsumotory/ngx_mruby/security/advisories/GHSA-wx6w-gpg3-cmc3)
  was published at 15:08:25 JST (Moderate, CVSS 3.1: 5.3): additional
  datagrams could restart a sleeping UDP stream handler and postpone its
  pending wait. The advisory confirms 2.7.4 as affected and 2.7.5 as fixed;
  earlier versions have not been established. The release and advisory
  contain both English and Japanese text. Public access and reference links
  were checked. The site's release-version update
  [passed](https://github.com/matsumotory/ngx_mruby/actions/runs/41781763136).
  The GitHub release body links the advisory in both languages. The
  release-note references for `master` were merged in
  [#763](https://github.com/matsumotory/ngx_mruby/pull/763) at 15:58:32 JST
  as `1a2e97ee1aa1426ade91d833be6472842b81aa04`. Its independent review and
  ready CI passed; the automatic site update started. The 2.7.5 changes
  reached `next` in [#765](https://github.com/matsumotory/ngx_mruby/pull/765).
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
- [#765](https://github.com/matsumotory/ngx_mruby/pull/765) merged `master`
  at `1a2e97ee1` into `next` as `ec8efde7c` on 2026-11-04 at 17:08 JST. It
  keeps the fiber state machine of `next` for the UDP waiting behavior and
  brings the expanded regression tests, the current references and both
  2.7.5 release-note files.
- [#767](https://github.com/matsumotory/ngx_mruby/pull/767) merged into
  `next` as `ea3c5996e` on 2026-11-09 at 18:33 JST. It adds
  [the proposal for the rest of the core before alpha.1](proposals/core-alpha1.md).
- [#766](https://github.com/matsumotory/ngx_mruby/pull/766) merged into
  `next` as `46bf09566` on 2026-11-09 at 19:21 JST: the `build_config.rb`
  rewrite of the queue. `ENV` and `Process` come from mruby's core gems,
  and mruby-vedis and mruby-localmemcache leave the default build. The
  owner accepted its `perf` row `stream_sleep` (`FAIL`, +6.05% without GC)
  on the PR. The replacement of `SecureRandom` and `Digest` is the queue
  row that follows it.
- [#768](https://github.com/matsumotory/ngx_mruby/pull/768) merged into
  `master` as `40578dd63` on 2026-11-09 at 19:25 JST: the 2.x form of the
  protected conversion with `to_s` of an `mruby_set` value and of the
  values of the setter of `Nginx::Var` and `Nginx::Var#set`. Its entries
  are in `docs/releases/v2.7.6.md` and `.ja.md`. On 2.x, a value that
  cannot be converted leaves the variable empty before a wait, as an
  exception of the code does; `next` answers 500 there (#735).
- [#769](https://github.com/matsumotory/ngx_mruby/pull/769) merged
  `master` at `40578dd63` into `next`. It keeps the implementation of
  `next` in `src/`, brings `test/t/cases/var_value_to_s.rb` on port 18189
  with the expectations of `next` for the values that the handler returns,
  and rewrites the "Before" line of the #735 entry in the 3.0.0 release
  notes from what #768 ran on 2.x. Its merge commit is `e8d9ff52f`
  (2026-11-09, 20:27 JST).
- [#773](https://github.com/matsumotory/ngx_mruby/pull/773) merged into
  `master` as `94d8cd84e` on 2026-11-09 at 20:58 JST: `docs/directives/README.md`
  of 2.x says that an `mruby_set` handler that waits in `Nginx::Async.sleep`
  ends the request without a response, unless an earlier handler declined,
  and points to 3.0.0 or to a rewrite or access handler with
  `Nginx::Var#set`. The 2.x code is not changed.
- [#772](https://github.com/matsumotory/ngx_mruby/pull/772) merged into
  `master` as `a52a19dcd` on 2026-11-09 at 21:14 JST: on 2.x, the timer of
  `Nginx::Async.sleep` runs the posted requests of the connection after
  every outcome, so a subrequest that the request posts after the sleep
  starts at once. Its test is `test/t/cases/async_sub_request_after_sleep.rb`
  (port 18190) and its entry is in `docs/releases/v2.7.6.md` and `.ja.md`.
- [#774](https://github.com/matsumotory/ngx_mruby/pull/774) merged into
  `master` as `1001b8b20` on 2026-11-09 at 21:34 JST: the category comments
  of `test/ci/changes.sh` on `master` match those of `next`, and "The 2.x
  pages of the site" in `docs/test/README.md` names the Node.js of
  `site/.node-version`.
- [#770](https://github.com/matsumotory/ngx_mruby/pull/770) merged into
  `next` as `d3fb11439` on 2026-11-09 at 22:28 JST: mruby log handlers run
  before `access_log` and keep the status that was sent, and a local
  `Nginx.redirect` raises in a log handler.
- [#771](https://github.com/matsumotory/ngx_mruby/pull/771) merged into
  `next` as `6196a49f1` on 2026-11-09 at 23:00 JST, the rest of the
  `build_config.rb` rewrite: `Digest` and `SecureRandom` from
  `mrbgems/digest` and `mrbgems/secure-random` on OpenSSL 3, and OpenSSL
  3.5.9 in the build matrix of CI.
- [#775](https://github.com/matsumotory/ngx_mruby/pull/775) merged into
  `master` as `915076528` and [#776](https://github.com/matsumotory/ngx_mruby/pull/776)
  into `next` as `6b642bb0e`, both on 2026-11-09 at 23:40 JST:
  `Nginx.rputs`, `Nginx.echo`, `Nginx.redirect` and `Nginx::Filter#body=`
  raise `TypeError` when `to_s` of the argument does not return a String.
  Their test is `test/t/cases/output_value_to_s.rb` (port 18191), and
  their entries are in `docs/releases/v2.7.6.md` and `v3.0.0.md` with the
  Japanese files.
- [#777](https://github.com/matsumotory/ngx_mruby/pull/777) merges `master`
  through `915076528` into `next`, with #772, #773, #774 and #775. It keeps the implementation of `next` in `src/` and its
  `test/t/cases/output_value_to_s.rb`, brings the test of #772 on port
  18190, and leaves the paragraph of #773 out of the `docs/` of `next`,
  which describe 3.0.0.
- [#778](https://github.com/matsumotory/ngx_mruby/pull/778) merged into
  `master` as `af51f9dbe` on 2026-11-10 at 01:28 JST: the two Japanese
  lines of `docs/releases/v2.7.6.ja.md` that #777 changed on `next`, and
  "The 2.x pages of the site" in `docs/test/README.md` without the number
  of the Node.js version.
- [#781](https://github.com/matsumotory/ngx_mruby/pull/781) into `master`
  as `5bb40f5d9` and [#782](https://github.com/matsumotory/ngx_mruby/pull/782)
  into `next` as `9a09deaeb`, both on 2026-11-10 at 15:00 JST:
  zizmor-action 0.8.1.
- [#784](https://github.com/matsumotory/ngx_mruby/pull/784) merged into
  `master` as `13153ae22` on 2026-11-10 at 20:02 JST: in a location with
  an mruby body filter, a response that a handler wrote with
  `Nginx.rputs` no longer stops after its first write when nginx needs
  more than one write to send it (`limit_rate`, `sendfile_max_chunk`, a
  slow client). Its test is `test/t/cases/body_filter_split_write.rb`
  (port 18141) and its entry is in `docs/releases/v2.7.6.md` and `.ja.md`.
- [#786](https://github.com/matsumotory/ngx_mruby/pull/786) merged into
  `master` as `10c4cd927` on 2026-11-10 at 23:13 JST: in a location with
  an mruby body filter, with or without an mruby header filter, a
  response no longer stops after its first write when an earlier handler
  wrote with `Nginx.rputs` and returned `Nginx::DECLINED`, so that its
  output stayed in the module context. The body filter run drops that
  context; `ngx_http_mruby_body_filter_handler_inner` now gives the
  request an empty context that passes the writer's later calls on. Its
  test is `test/t/cases/body_filter_leftover_chain.rb` (port 18145) and
  its entry is in `docs/releases/v2.7.6.md` and `.ja.md`.
- [#790](https://github.com/matsumotory/ngx_mruby/pull/790) merged into
  `master` as `b9e42c3ad` on 2026-11-11 at 04:31 JST: the README says that
  2.x builds with nginx 1.28 and 1.26, and with nginx 1.24 only without
  the stream module (without `--with-stream`).
  [#792](https://github.com/matsumotory/ngx_mruby/pull/792) merged into
  `master` as `65ce972e1` on 2026-11-11 at 14:34 JST: the lines of
  `test.sh` that make the certificates run in a subshell, and `test.sh`
  stops and names the certificate (localhost or dummy) when `openssl req`
  fails. Neither adds an entry to the release notes.
- [#787](https://github.com/matsumotory/ngx_mruby/pull/787) (merged into
  `next` as `bbd88868f` on 2026-11-11 at 00:01 JST) merged `master` through
  `10c4cd927` into `next`, with #786. The PR body says why the fix works
  the same on `next`, where `ngx_mrb_finalize_rputs` has more branches than
  on `master`.
- [#793](https://github.com/matsumotory/ngx_mruby/pull/793) (open, to
  `next`) merges `master` through `65ce972e1` into `next`, with #790 and
  #792. `README.md` conflicted in the paragraph on the promotion; `next`'s
  text is kept, because `next` already says in the paragraph after it
  that 2.x with nginx 1.24 builds only without the stream module. The
  lines of `test.sh` that make the certificates came from `master`.
- [#785](https://github.com/matsumotory/ngx_mruby/pull/785) (merged into
  `next` as `76ebd2fac` on 2026-11-10 at 21:33 JST) merged `master`
  through `13153ae22` into `next`, with #778, #781 and #784. A test commit before the merge,
  `test/t/cases/body_filter_split_write_status.rb` (port 18142), shows
  the same stop on `next` for output sent with a status set before or
  after it (#779, #783); the merge applies the fix of #784 to the branch
  of `ngx_mrb_finalize_rputs` on `next` that sends the output. The PR
  body has the state, the checks and the other places that clear the
  module context.
- [#799](https://github.com/matsumotory/ngx_mruby/pull/799) (merged
  2026-11-12 17:11 JST at `1791b8bf1`, base `next`) protects the calls of
  `inspect` and `backtrace` in the logging
  of an exception (`src/common/ngx_mruby_log.c`) with `mrb_protect_error`,
  as `ngx_mrb_fiber_resume` protects a resumed fiber, so that a script
  that redefines them so that they raise does not send that exception past
  the nginx functions when the handler runs inside another mruby call. An
  exception whose `inspect` raises or does not return a String is logged
  with its class (an entry under "Behavior changes" of
  `docs/releases/v3.0.0.md` and `.ja.md`). Its test is
  `test/t/cases/exception_log_raising_methods.rb` (port 18198 and the
  stream port 12382). The PR body has the state and the checks.
- [#796](https://github.com/matsumotory/ngx_mruby/pull/796) (merged into
  `next` as `e6d2efdae` on 2026-11-12 at 02:20 JST) moves the logging of an exception of Ruby code, seven functions of
  the HTTP and the stream modules, and the two copies of `Nginx.log` into
  `src/common/ngx_mruby_log.{h,c}`, the row of section 2.8 of
  [the proposal for the rest of the core before alpha.1](proposals/core-alpha1.md).
  The lines of `error.log` keep their text and their level; stream also
  logs the backtrace in a build with `--with-debug` (its entry under
  "Behavior changes" of `docs/releases/v3.0.0.md` and `.ja.md`), and an
  element of a redefined `backtrace` that is not a String is skipped (a
  "Fixes" entry). Its tests are `test/t/cases/exception_log.rb` (ports
  18192, 18193 and 12380) and a case of `test/t/cases/config_hooks.rb`. The
  PR body has the state and the checks.
- [#788](https://github.com/matsumotory/ngx_mruby/pull/788) (merged into
  `next` as `ae8df760e` on 2026-11-11 at 01:51 JST) moves the checks, the parse and the per-peer store that
  `Nginx::Upstream#server=` and `Nginx::Stream::Connection#upstream_server=`
  shared as two copies into `src/common/ngx_mruby_upstream.{h,c}`, the row
  of section 2.7 of
  [the proposal for the rest of the core before alpha.1](proposals/core-alpha1.md).
  No behavior changes. The PR body has the state, the checks and the table
  of what is shared and what each setter keeps.
- [#780](https://github.com/matsumotory/ngx_mruby/pull/780) (merged into
  `next` as `f14cceaeb` on 2026-11-10 at 02:48 JST) adds the directive `mruby_variable` of section 2.11 of
  [the proposal for the rest of the core before alpha.1](proposals/core-alpha1.md),
  the agent proxy row on variable declarations. Its test is
  `test/t/cases/mruby_variable.rb` (port 18171), and its entries are under
  "New features" of `docs/releases/v3.0.0.md` and `.ja.md`.
- [#761](https://github.com/matsumotory/ngx_mruby/pull/761) merged the
  unchanged empty-subrequest response clarification as `8cbdf7748`.
  [#762](https://github.com/matsumotory/ngx_mruby/pull/762) merged the
  capability-based agent model and reasoning-effort guidance as `4eb847421`.
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

- **2026-11-12, local checks first.** CI is the final check in a clean
  environment. Every kind of check that CI runs for a change is run
  locally by the author before the PR is marked ready, and its failures
  are found there: the suite with the static and the dynamic module, the
  suite under AddressSanitizer and UndefinedBehaviorSanitizer and under
  valgrind (for C code and build changes), the callgrind comparison, the
  soak, the steps of `examples/start`, nginx-tests, the site's checks and
  the static analysis of the workflows. On macOS the Linux-only checks
  run in a Linux container. CI keeps only the spread to what one machine
  does not hold: the other nginx versions and link modes of the build
  matrix, the x86-64 runner and a clean environment. Rationale: a check
  whose first run is in CI is found failing there, and each fix costs a
  push and a CI wait; when the runner itself fails, a local result of the
  same check is what separates a code defect from a runner problem. #796
  ran all of these on an arm64 Mac in Docker while three CI attempts on
  the same head stopped in the package installation. This replaces the
  text of 2026-10-31 and 2026-11-02 that sent the sanitizers, valgrind and
  the callgrind comparison to CI as environments a machine does not have;
  the limits on CI time and the base-move condition stay. Written in
  AGENTS.md ("Design principles", "Branches and pull requests", "Review
  and merge", "Build and test"), the PR template and `docs/test/README.md`
  on `next`, and on `master` in #807.
  The following is the sessions' procedure, not part of the decision of
  2026-11-12: #807 (on `master`) and #808 (on `next`) settled it after the
  reviews of #807, and AGENTS.md "Branches and pull requests" and "Build
  and test" hold its current text. The author runs the check of the added
  files for every PR, and the suite with the static and the dynamic
  module, under the sanitizers and under valgrind, when
  `test/ci/changes.sh` gives `build` `standard` or `full`. Besides what
  one machine does not hold, CI keeps the checks whose reason AGENTS.md
  writes down: CodeQL on `next`, and CodeQL and, for changes outside its
  paths, the auto-ssl case on `master`.
- **2026-11-03, agent assignment.** Choose Codex models and reasoning effort
  by role and task complexity, using currently available capabilities rather
  than fixed model names. Routine work uses a sufficient faster, lower-cost
  model; difficult analysis uses stronger reasoning. The task leader keeps
  scope, ownership and validation gates, with independent review. The shared
  coordination rules apply across operating systems and tools; Codex model
  controls do not become requirements for other tools. This adds selection
  guidance to the existing coordination procedure without replacing its
  tests or review and merge gates. The rule is in
  [Assigning agent work](../AGENTS.md#assigning-agent-work).
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
| The category comments of `test/ci/changes.sh` describe local site checks and next-push publication after the CI changes of 2026-11-02 (#737 and #739) | `master` and `next` | Updated on `next` with stream measurement, and on `master` in [#774](https://github.com/matsumotory/ngx_mruby/pull/774) |
| Merge `master` into `next` after each merge into `master`. Model: #573. | `next` | Merged through `915076528` (#775) in [#777](https://github.com/matsumotory/ngx_mruby/pull/777). Merged through `13153ae22` (#778, #781, #784) in [#785](https://github.com/matsumotory/ngx_mruby/pull/785). Merged through `10c4cd927` (#786) in [#787](https://github.com/matsumotory/ngx_mruby/pull/787). Merged through `65ce972e1` (#790, #792) in [#793](https://github.com/matsumotory/ngx_mruby/pull/793), through `aa3d9798a` (v2.7.6, #801, #800) in [#802](https://github.com/matsumotory/ngx_mruby/pull/802), through `39bfae179` (#804) in [#805](https://github.com/matsumotory/ngx_mruby/pull/805), through `66b284a94` (#803) in [#806](https://github.com/matsumotory/ngx_mruby/pull/806), and through `7a72306bb` (#807) in [#808](https://github.com/matsumotory/ngx_mruby/pull/808). [#810](https://github.com/matsumotory/ngx_mruby/pull/810) merges through `91499f767` (#809, v2.7.7 and #811) and waits for its checks, review and merge; the next merge of `master` after it waits for a merge into `master` |
| Public work records summarize requirements, rationale and constraints, distinguish decisions from proposals, and omit conversation quotations. Shared rules and next documents were aligned in #746; master rules and the corresponding English/Japanese 2.7.3 entries were aligned in #748 | `master` and `next` | #746 and #748 merged; #749 brought the remaining release-note corrections to `next` |
| The homepage shares coherent width, alignment and spacing across the hero, section introductions, use cases and footer; continuous introductions read in one column (see "Decisions") | `next` | Merged in [#747](https://github.com/matsumotory/ngx_mruby/pull/747) as `fad853820`; site deployment and publication checks passed ([checkpoint](https://github.com/matsumotory/ngx_mruby/pull/747#issuecomment-6580515876)) |
| The fixed heading 「アップグレードの前に読む挙動の変更」 of the Japanese release notes ends with one character on its own line at 402 px, in `v2.7.5.ja.md` and in `v2.7.4.ja.md`. The heading and template are corrected in #745, with the previous anchors preserved | `master` (reaches `next` by the merge) | Merged in #745 and included in `next` through #746 |
| Subrequests: the entry of #574 in `docs/releases/v3.0.0.md` and `.ja.md` explains the unchanged 500 from a subrequest content handler that returns `Nginx::HTTP_OK` without output, the 200 from nginx's own `return 200;`, and why `auth_request` treats the retained 500 as an error instead of allowing the request | `next` | Merged in [#761](https://github.com/matsumotory/ngx_mruby/pull/761); local site checks and independent semantic and visual review passed |
| A known-length HEAD response finalized by an mruby output body filter keeps its connection for the following GET ([the review of #574](https://github.com/matsumotory/ngx_mruby/pull/574#issuecomment-6166201549), should fix 1; #628 reproduced it) | `master`, then `next` | Fixed on master in [#752](https://github.com/matsumotory/ngx_mruby/pull/752) with failing-test and passing-fix commits, and integrated into next in [#756](https://github.com/matsumotory/ngx_mruby/pull/756). The combined suite passed all 759 tests; local validation, independent review, CI and publication checks passed. Both release lines and the current Filter reference describe the known-length HEAD scope |
| An end-to-end benchmark scenario: throughput and p50 and p99 latency with `oha` or `h2load`, planned in AGENTS.md "Design principles" and in section 8 of the plan, which also records the reference proxy end to end | `next` | Ready to start; where the results are recorded is decided when it is added (AGENTS.md) |
| Site: steps 1 to 4, 6 and 7 are merged (#591, #607, #614, #617–#623, #626, #629–#632, #653–#657), and the site is deployed from `next`. Step 5, the Japanese pages, is merged (#705 for six pages, #703 for the 2.x release notes on `master`); the handoff page stays English with a notice, and `NOTES_ONLY` of `check-japanese-lines.mjs` still lists four release notes (the subsection "Japanese pages of the site" of "Work in progress") | `next` for `site/`; `master` for 2.x sources | Still open: the emptying of `NOTES_ONLY` once `master` is merged into `next`; the site on Astro without Starlight (5.4 of the site proposal, #700, the owner's decision of 2026-11-01), whose first layer, the own shell beside Starlight behind `NGX_MRUBY_SITE_SHELL=own`, is merged in #708, and whose rest is #713 (from a Codex session, taken over by Claude Code for the browser acceptance), which also changes the iPhone width to 402px with the root size of 4.4; the 3.x development banner of 3.4; and the observability and certificate-lookup sample prerequisites of #619. Q9 is done (Discussions on, wiki off, 2026-11-01) |
| nginx-tests with the modules that its skipped files need: a build with the options of `test.sh` and `--with-http_v2_module`, `--with-http_v3_module`, `--with-stream_ssl_module`, `--with-mail` and the other modules that "Results of nginx-tests" in `docs/test/README.md` lists (in the CI run of #602, 189 of the 209 skipped files need a module that `test.sh` does not build), with and without ngx_mruby, in the `nginx-tests` workflow | `next` | Ready to start: #602 is merged |
| nginx-tests with ngx_mruby code configured: runs that add handlers or filters with code for every request through `TEST_NGINX_GLOBALS_HTTP` (the Pillar E row of the plan), compared with the run without code. The pull request decides which code; since [#720](https://github.com/matsumotory/ngx_mruby/pull/720), a rewrite handler that ends without `Nginx.return` goes on to the next phase on `next` | `next` | Ready to start: #602 is merged |
| Test harness rewrite (step 2 of section 6 of the plan; Pillar E): [#635](https://github.com/matsumotory/ngx_mruby/pull/635) (merged, `c4e6ac6cc`) made `test.sh` stop only the nginx that it started, by its pid, with no `killall` or `pkill`, and send SIGTERM again while the single nginx process still runs, because that process can miss a SIGTERM that arrives right before it waits for events (the run at `7926f72`, where nginx stayed in `epoll_wait()` for 20 minutes after it logged the SIGTERM: "Stopping nginx" in `docs/test/README.md` has the cause and the measurements). [#641](https://github.com/matsumotory/ngx_mruby/pull/641) (merged, `be559a017`) added `TEST_SH_PORT_OFFSET`, which moves every port of the suite, so that two checkouts can run `test.sh` at the same time ("Ports" in `docs/test/README.md`). [#706](https://github.com/matsumotory/ngx_mruby/pull/706) added nginx with `master_process on` and several workers, and a reload in the middle of a case: `test/t/cases/_workers.rb` starts such an nginx from `test/conf/workers/`, and `test/t/cases/workers.rb` checks that each of four workers answers from an mrb_state of its own, and that across a SIGHUP the old workers finish an `Nginx::Async.sleep` and an `Nginx::Stream::Async.sleep` in flight while the new configuration answers ("Several workers and reloads" in `docs/test/README.md`). Still to do, in pull requests of their own: requests from CRuby instead of the client built into the test mruby for the other cases, and HTTP/2 and HTTP/3 clients. A should fix of the review of #635 waits for the pull request that next changes `test/build_release.sh`, an input of the `perf` job: its comment still says that `test.sh` kills every running nginx. The readiness wait of #593 is the first part, on `next` since the merge of `master` at `6b27f08da` | `next` | Several workers and reloads: done by [#706](https://github.com/matsumotory/ngx_mruby/pull/706) (decision (3) of 2026-11-01). Requests from CRuby and the HTTP/2 and HTTP/3 clients: ready to start |
| CI runs only the jobs that a change needs: done on both branches by [#676](https://github.com/matsumotory/ngx_mruby/pull/676), [#685](https://github.com/matsumotory/ngx_mruby/pull/685), [#686](https://github.com/matsumotory/ngx_mruby/pull/686) and [#692](https://github.com/matsumotory/ngx_mruby/pull/692) on `next`, and [#679](https://github.com/matsumotory/ngx_mruby/pull/679), [#690](https://github.com/matsumotory/ngx_mruby/pull/690) and [#693](https://github.com/matsumotory/ngx_mruby/pull/693) on `master`; the owner's decisions and rules are in AGENTS.md and `docs/test/README.md`. Left: a pull request to `master` that gives it the lines of `test/ci/changes.sh` and `test/ci/changes_test.sh` that `next` has (on `master`, a change of `test/soak/mock_llm_test.rb` alone runs that check only with the label `perf`); the first run of the whole build matrix through `fromJSON` (should fix 4 of [the review of #686](https://github.com/matsumotory/ngx_mruby/pull/686#issuecomment-6541409852)), which the nightly run under valgrind makes; and from [the review of #693](https://github.com/matsumotory/ngx_mruby/pull/693#issuecomment-6542620420): local commands for the build of the 2.x pages in "The 2.x pages of the site" of `docs/test/README.md` on `master` (should fix 1 and 2), and on both branches, a sentence in "Required status check" that a draft run queued after the ready run cancels it in `site-v2`, `codeql` and `zizmor`, or a concurrency group that includes the draft state (should fix 4). [#778](https://github.com/matsumotory/ngx_mruby/pull/778) made two changes on `master`: "The 2.x pages of the site" in `docs/test/README.md` names `site/.node-version` instead of the number of the Node.js version (should fix 1 of [the review of #774](https://github.com/matsumotory/ngx_mruby/pull/774#issuecomment-6740176012)), and `docs/releases/v2.7.6.ja.md` takes the two edits of `c41981dd5` in [#777](https://github.com/matsumotory/ngx_mruby/pull/777), so that the file is the same on both branches before the 2.7.6 tag. With [#785](https://github.com/matsumotory/ngx_mruby/pull/785), `docs/test/README.md` of `next` takes the same sentence, and `docs/releases/v2.7.6.md` and `.ja.md` are the same on both branches. Four cells: code-changing pull requests run four cells of the build matrix: done on both branches by [#702](https://github.com/matsumotory/ngx_mruby/pull/702) on `next` (`bf1b742b7`) and [#704](https://github.com/matsumotory/ngx_mruby/pull/704) on `master` (`166341b93`), with `build` `standard` of `test/ci/changes.sh`; every cell runs only nightly, on a tag, in the check pull request before a tag (the label `full-matrix`, which exists in the repository) and on "Run workflow" without `base` | `master`, `next` | Ready to start |
| nginx floor for v3 (item 2 of section 7 of the plan): drop the cells for nginx 1.26.3 and 1.28.3 from the `build` matrix of `.github/workflows/test.yml` and document the floor of 1.30 stable and 1.31 mainline | `next` | Done in [#789](https://github.com/matsumotory/ngx_mruby/pull/789), which also removes the `nginx_version` branches of `src/` for nginx older than 1.25.5 and adds the entry of the floor to the 3.0.0 release notes. Each April a pull request moves the matrix and the docs to the new stable and mainline lines |
| 2.x with nginx 1.24 and the stream module: the build stops while it compiles `src/stream/ngx_stream_mruby_core.c`, because nginx 1.24 has no `ngx_stream_listen_opt_t`; the build without the stream module completes (#789 measured both on `master` at `10c4cd927`). Linux distributions such as Ubuntu 24.04 ship nginx 1.24. To decide: make 2.x build with nginx 1.24 and the stream module, or document 2.x with nginx 1.24 as a build without the stream module | `master` | The owner's decision |
| OpenSSL 3.5 and 4.0 (item 3 of section 7 of the plan): the cells of the `build` matrix of `.github/workflows/test.yml` build OpenSSL 3.5.9 in place of `1.1.1w` since [#771](https://github.com/matsumotory/ngx_mruby/pull/771), whose `Digest` and `SecureRandom` need OpenSSL 3.0 or later, and `configure` reads the version of an OpenSSL 3 source tree. Left: a cell for OpenSSL 4.0, the floor of 3.5 in the docs and the build (the soak and perf jobs take the OpenSSL 3.0.2 of the runner), and a check for ENGINE and the removed APIs in ngx_mruby and the gems | `next` | Ready to start: #601's change to `.github/workflows/test.yml` is on `next` since the merge of `master` at `6b27f08da` |
| `build_config.rb` rewrite with explicit gems (step 3 of section 6; Pillar A): done. [#771](https://github.com/matsumotory/ngx_mruby/pull/771) replaces `monochromegane/mruby-secure-random` and `iij/mruby-digest` with `mrbgems/secure-random` (`SecureRandom` on `RAND_bytes` of OpenSSL) and `mrbgems/digest` (`Digest` on the EVP and `EVP_MAC` APIs of OpenSSL 3), as decided on 2026-11-09, keeping the classes and methods of the two gems; the differences are in its entry of the 3.0.0 release notes. The reasons of the decision: the list of mruby gems has no maintained replacement (Asmod4n/mruby-sysrandom replaces mruby-secure-random with another API, and nothing replaces mruby-digest), and gems in this repository are checked by the suite, CI and the `perf` job of ngx_mruby as they are. [#766](https://github.com/matsumotory/ngx_mruby/pull/766) did the rest of the row: `iij/mruby-env` and `iij/mruby-process` replaced by the core gems mruby-env and mruby-process (with mruby-signal), `mruby-onig-regexp` kept as item 1 of section 7 decides, and `mruby-vedis` and `mruby-localmemcache` out of the default build | `next` | Done: [#771](https://github.com/matsumotory/ngx_mruby/pull/771) merged as `6196a49f1` on 2026-11-09 |
| mruby 4.1.0 (step 3 of section 6; item 1 of section 7). The owner decided on 2026-10-29 that `next` bundles `4.1.0-rc2` now and moves to 4.1.0 in a small subtree pull request when it is tagged. `next` bundles `4.1.0-rc2` since [#678](https://github.com/matsumotory/ngx_mruby/pull/678). The step to 4.1.0: `./update-mruby-subtree 4.1.0`, `vendor-mruby-prism` if the gitlink of Prism moves, the lock, and the release notes | `next` | The tag `4.1.0` of mruby |
| Step 4 of section 6 of the plan, the core stability work of Pillar B (execution context, response finalization, fiber lifecycle, common layer, headers and variables, and the two agent proxy rows; [#770](https://github.com/matsumotory/ngx_mruby/pull/770) does the row on log handlers before `access_log`), then `v3.0.0-alpha.1` | `next` | The core stabilization is done: [the core stabilization proposal](proposals/archive/core-stabilization.md) was implemented in [#712](https://github.com/matsumotory/ngx_mruby/pull/712), [#714](https://github.com/matsumotory/ngx_mruby/pull/714), [#715](https://github.com/matsumotory/ngx_mruby/pull/715), [#720](https://github.com/matsumotory/ngx_mruby/pull/720), [#722](https://github.com/matsumotory/ngx_mruby/pull/722), [#727](https://github.com/matsumotory/ngx_mruby/pull/727), [#728](https://github.com/matsumotory/ngx_mruby/pull/728) and [#735](https://github.com/matsumotory/ngx_mruby/pull/735) (the last on 2026-11-02), is archived, and the model is in [How a handler waits](DEVELOPMENT.md#how-a-handler-waits-the-record-of-its-fiber) of `docs/DEVELOPMENT.md`. Left in this step: the work designed in [the proposal for the rest of the core before alpha.1](proposals/core-alpha1.md) (the execution-context type, headers, `Nginx::Var`, the filter handler pointers, the table-driven directives, the common layer beyond the fiber, and the rest of the async resume rewrite; the row on log handlers before `access_log`, with the raise of a local `Nginx.redirect` in log handlers, is done by [#770](https://github.com/matsumotory/ngx_mruby/pull/770), the agent proxy row on `mruby_variable` by [#780](https://github.com/matsumotory/ngx_mruby/pull/780), the row on common upstream switching by [#788](https://github.com/matsumotory/ngx_mruby/pull/788), merged on 2026-11-11, the row on common error logging by [#796](https://github.com/matsumotory/ngx_mruby/pull/796), merged on 2026-11-12, with its follow-up [#799](https://github.com/matsumotory/ngx_mruby/pull/799), merged on 2026-11-12, for the calls of `inspect` and `backtrace` in the logging, and the row on a body with any status by [#779](https://github.com/matsumotory/ngx_mruby/pull/779), merged on 2026-11-10, with its follow-up [#783](https://github.com/matsumotory/ngx_mruby/pull/783), merged on 2026-11-10, for a status set before the output (decision 6), `Nginx::HTTP_CLOSE` with output (decision 7) and the should fix items 2 and 4 of the review of #779), one pull request per row of its section 4, and the check before the tag of its section 3. Its design decisions were made on 2026-11-09 and 2026-11-10 (section 5 of the proposal), and no point of the design is open. Started by the owner's decision of 2026-11-01 to extend the harness so that `test.sh` tests `master_process on`, several workers and reloads, and then to rework the core fiber lifetime and response completion. [#706](https://github.com/matsumotory/ngx_mruby/pull/706) made that extension; the requests from CRuby and the HTTP/2 and HTTP/3 clients of the row above for the test harness rewrite stay there |
| nginx-tests required: the `nginx-tests` workflow records its results and fails only when a build, the fetch of the suite or `prove` fails. In the runs of 2026-10-28 and 2026-10-29 the build with ngx_mruby and the build without it have the same counts (511 files, 302 passed, 0 failed, 209 skipped). To do: the job fails when the build with ngx_mruby fails a file that the build without it passes, and the job joins the `needs` of `ci-ok` | `next` | Ready to start: the counts are the same in every run since #602 |
| The `perf` job in the `needs` of `ci-ok`, and the "In CI" text of `docs/test/README.md` aligned with the rule of AGENTS.md "Design principles", under which a session does not merge while the job reports `FAIL` or `ERROR`. On `next`, [#794](https://github.com/matsumotory/ngx_mruby/pull/794) does it: `ci-ok` needs `perf`, and a `FAIL` that the owner accepted on a pull request passes through a line with the new condition `pull-request` in `test/perf/accepted.txt`. The comparison judges the Ir per request without the GC and without the constant lookups that miss the constant cache of mruby, which made the `stream_sleep` `FAIL` of #766 that another run on the same commits did not repeat, except where the head clears that cache more often, or clears it and misses more lookups than the base ([#795](https://github.com/matsumotory/ngx_mruby/pull/795)); then with the lookups counted. Left: the same on `master`, in a pull request to `master` (its `test.yml`, `test/perf/perf.rb`, `test/perf/accepted.txt`, AGENTS.md and `docs/test/README.md`) | `next`, then `master` | `next`: done by [#794](https://github.com/matsumotory/ngx_mruby/pull/794). `master`: ready to start |
| Soak: record `Pss` and `Private_Dirty` from `/proc/<pid>/smaps_rollup` beside `VmRSS`, then bound their slope over more windows, set after measuring (the Pillar E row on memory accounting). Today `test/soak/soak.rb` bounds `VmRSS` by a step and a total and checks the counters of `Nginx::Debug.stats` | `next` | Ready to start |
| Soak and perf for stream: the normal TCP `stream_sleep` scenario checks exact response bytes and EOF, observes `stream_timers` and `stream_fibers`, and collects the stream VM before memory samples. The performance build includes stream and counts completed sessions (section 7 of [the core stabilization proposal](proposals/archive/core-stabilization.md)) | `next` | Merged in [#758](https://github.com/matsumotory/ngx_mruby/pull/758) as `8beaaa381`; local checks, independent review, CI, publication verification and cleanup passed |
| The case `async_sleep_many.rb` of section 6 of [the core stabilization proposal](proposals/archive/core-stabilization.md): a handler that sleeps 1,000 times for 1 ms answers, and `Nginx::Debug.stats` shows the same `timers` and `gc_root_fibers` before and after | `next` | Merged in [#751](https://github.com/matsumotory/ngx_mruby/pull/751) as `63c6b7152`; local checks, independent review, CI and publication checks passed. The normal test build enables the counters, and each HTTP exchange has a 60-second limit |
| The comments in `src/` and `test/` that name `docs/proposals/core-stabilization.md` (20 places, `git grep -n core-stabilization -- src test`): the proposal is now `docs/proposals/archive/core-stabilization.md`. To do: the next pull request that changes those files points them at the new path, or at the section "How a handler waits" of `docs/DEVELOPMENT.md` | `next` | The next code pull request that touches those files (a comment-only change of `src/` would run the whole build matrix) |
| The ASan cell with `-DNGX_DEBUG_PALLOC -DNGX_DEBUG_MALLOC` (3.7 of the plan; the cell of `test.yml` sets only `-fsanitize` and `-fno-omit-frame-pointer`), so that ASan sees an access that runs from one pool allocation into the next. To do: a run of the suite with these flags, whose findings follow [SECURITY.md](../SECURITY.md), then the cell | `next`, `master` | Ready to start |
| A test build with `ngx_otel_module` (nginx/nginx-otel, built with CMake against the nginx source of `test.sh`) and an OTLP receiver for the case of the observability sample of 3.2 of the site proposal | `next` | The harness rewrite (the row above), of which this waits for what is left: the requests from CRuby instead of the client built into the test mruby, and the HTTP/2 and HTTP/3 clients. [#706](https://github.com/matsumotory/ngx_mruby/pull/706) added `master_process on`, several workers and reloads |
| Step 7 of section 6 of the plan, the agent proxy, parts (a) to (e); none exists on `next` | `next` | Parts (a) and (c) start "after the safety net of step 2, beside step 4" (step 7 of section 6 of the plan, decided on 2026-10-29 in item 15 of section 7), so they wait for what is left of that safety net: in the row above for the test harness rewrite, the requests from CRuby instead of the client built into the test mruby, and the HTTP/2 and HTTP/3 clients. [#706](https://github.com/matsumotory/ngx_mruby/pull/706) added `master_process on`, several workers and reloads, and its `test/t/cases/_workers.rb` runs the several workers that the test of N concurrent `incr` calls of the shared dictionary needs (section 8 of the plan). (b) and (d) also wait for step 4. The order inside the step is a proposal of the 2026-10-04 amendment until the owner decides it. The `serves:` notes on the rows of the plan name the uses of [the ledger](proposals/edge-control.md#use-cases-and-the-features-they-need) that each part serves |
| The AI uses of v3 beyond the agent proxy: the next work comes from [the ledger of the uses](proposals/edge-control.md#use-cases-and-the-features-they-need), first its rows at `designing` ([MCP tool authorization](proposals/edge-control.md#mcp-tool-authorization), whose first recipe uses two tenants and read and write mock tools, [MCP tool profiles](proposals/edge-control.md#mcp-tool-profiles), [MCP progressive retrieval](proposals/edge-control.md#mcp-progressive-retrieval), and [Model API fallback](proposals/edge-control.md#llm-api-fallback), whose test is in section 8 of the plan), then its rows at `direction`. This row copies the ledger; when they disagree, the ledger holds | `next` | What is left of step 4 of the plan (the row of step 4 above); the fallback also waits for step 7 of the plan (the row above). No API for these uses is designed yet |
| Remove `example/` (`README.md`, `nginx.conf`, `proxy.rb`, `set.rb`, `set2.rb`, `unified_hello.rb`): no CI job starts it, no page links it, and its `/proxy` location picks among `test1.example.com` to `test3.example.com`, which are unreachable; `examples/start/` is checked by `examples.yml` | `next` | Done in [#791](https://github.com/matsumotory/ngx_mruby/pull/791): the directory and the sentence about `example/nginx.conf` in `docs/proposals/site.md` are removed; no other reference existed, and no release note is needed because no configuration, script or build reads the directory |
| What is left of the async resume rewrite (decision (c) of 2026-10-04, amended on 2026-10-29: the rewrite of how resumed handlers end): a wait that starts in a handler that nginx runs inside another mruby call (the location of an internal redirect that an `mruby_set` handler, a log handler or a filter makes inside the Ruby call), or after an internal redirect replaced the module context of the handler, is still resumed by its timer or by the end of its subrequest and ended by `ngx_mrb_post_fiber` in `src/http/ngx_http_mruby_async.c`; a content handler there does not keep the request, so the request ends at the sleep. The rest is done in [#715](https://github.com/matsumotory/ngx_mruby/pull/715), [#722](https://github.com/matsumotory/ngx_mruby/pull/722) and [#728](https://github.com/matsumotory/ngx_mruby/pull/728) (section 12 of [the core stabilization proposal](proposals/archive/core-stabilization.md)) | `next` | Designed in section 2.9 of [the proposal for the rest of the core before alpha.1](proposals/core-alpha1.md): `Nginx.redirect` with a local URI raises in these handlers (decision 1 of 2026-11-09), and `ngx_mrb_post_fiber` is removed. Ready to start; it waits for no other pull request |
| The generated reference of the site (Pillar F of the plan): the directives from the `ngx_command_t` tables, the Ruby API with YARD and yard-mruby, the C API with Doxygen. `site/scripts/check-reference.mjs` checks, among other things, that each directive name has a heading in `docs/directives/README.md`; the pages are written by hand | `next` | Ready to start; no step of section 6 of the site proposal produces it yet |
| The "Before" line of the entry on `mruby_set` values that are not Strings in [the 3.0.0 release notes](releases/v3.0.0.md) | `next` | Done in [#769](https://github.com/matsumotory/ngx_mruby/pull/769). [#768](https://github.com/matsumotory/ngx_mruby/pull/768) ran the cases on `master` before its fix: a `to_s` that returns something other than a String ended the worker with a segmentation fault before and after `Nginx::Async.sleep`, and a value without `to_s` or whose `to_s` raises was read as a String although it was the exception, which stayed in the `mrb_state` of the worker. The line in `docs/releases/v3.0.0.md` and `.ja.md` now says this |
| The documentation group of the site footer links the current 3.x documentation before the other version in both languages, without duplicating the existing 3.x link on 2.x pages (4.10 of [the site proposal](proposals/site.md)) | `next` | Merged in [#750](https://github.com/matsumotory/ngx_mruby/pull/750) as `c440a15dc`; local checks, independent review, CI and publication verification passed |
| The 2.x form of the protected conversion of an `mruby_set` value ([#735](https://github.com/matsumotory/ngx_mruby/pull/735) on `next`) | `master` | Done in [#768](https://github.com/matsumotory/ngx_mruby/pull/768) (`40578dd63`, 2026-11-09 19:25 JST), with its entries in `docs/releases/v2.7.6.md` and `.ja.md`. On 2.x, a value that cannot be converted counts as an exception of the code: before a wait the variable is empty and the request goes on, after `Nginx::Async.sleep` the request gets 500. It reached `next` in [#769](https://github.com/matsumotory/ngx_mruby/pull/769), which keeps the form of #735 |
| `Nginx.rputs` and `Nginx.echo` (`ngx_mrb_rputs_inner` in `src/http/ngx_http_mruby_core.c`, the function that both methods call), `Nginx.redirect` (`ngx_mrb_redirect` there) and `Nginx::Filter#body=` (`ngx_mrb_set_filter_body` in `src/http/ngx_http_mruby_filter.c`) call `to_s` on a value that is not a String and read the result with `RSTRING_PTR` without checking that it is a String. They run in Ruby code, so a `to_s` that raises raises in the script, but a `to_s` that returns another object is read as a String. `master` and `next` have the same code. Found while testing [#768](https://github.com/matsumotory/ngx_mruby/pull/768) ("Not changed, found while testing" in its body) | `master`, `next` | Done in [#775](https://github.com/matsumotory/ngx_mruby/pull/775) on `master` and [#776](https://github.com/matsumotory/ngx_mruby/pull/776) on `next`, which convert the argument with `ngx_mrb_var_to_string()` and raise `TypeError` when `to_s` does not return a String, as the setter of `Nginx::Var` does; each has its regression test in `test/t/cases/output_value_to_s.rb` (port 18191) before the fix and its entry under "Behavior changes" (`v2.7.6` and `v3.0.0`). The setters of `Nginx::Request` (`uri=`, `args=` and the others of `NGX_MRUBY_DEFINE_METHOD_NGX_SET_REQUEST_MEMBER_STR`), `Nginx::Headers_in#[]=`, `Nginx::Headers_out#[]=` and the path of `Nginx::Async::HTTP.sub_request`, which these two PRs left, raise `TypeError` for an argument that is not a String since 2.7.7, on `master` and on `next` ([GHSA-cjxv-4q9m-62pf](https://github.com/matsumotory/ngx_mruby/security/advisories/GHSA-cjxv-4q9m-62pf)). Left, to fix in public pull requests: the second argument of `Nginx.redirect` (`ngx_mrb_redirect` reads it as an Integer without checking its type) and `:address` of `Nginx::Stream.add_listener` (`ngx_stream_mrb_add_listener` in `src/stream/ngx_stream_mruby_core.c` reads it as a String without checking its type) |
| On 2.x, an `mruby_set` handler that ends normally after `Nginx::Async.sleep` in the location `/set/` of `test/conf/conf.d/83-var-value-to-s.conf` ends the request without a response: the timer handler finalizes the request with the `NGX_OK` of `ngx_mrb_finalize_rputs`, and the phases do not go on (seen while testing #768; `/sleep_with_proxy_set_code` on port 18080 gets its response). On `next`, `test/t/cases/async_set_var.rb` checks that such a handler sets its variable and the request goes on (#715); the location of `var_value_to_s` has not been run with a valid value after the sleep on `next` | `master` | Done: the 2.x code is not changed, and [#773](https://github.com/matsumotory/ngx_mruby/pull/773) writes the limit in `docs/directives/README.md` of 2.x; 3.0.0 fixed it in [#715](https://github.com/matsumotory/ngx_mruby/pull/715). The decision of 2026-10-29 under "Decisions" puts the rewrite of the async resume on `next` and gives `master` the minimum stability fixes |
| `test.sh` makes its certificates with `cd ${NGINX_INSTALL_DIR}/html && ... openssl req ... && cd -`. When `openssl req` fails, `set -e` does not stop the script inside the `&&` list, the shell stays in `html`, and the next command does not find `test/t/cases/_wait_for_listen.rb`, which hides the cause (seen in the CI runs of [#771](https://github.com/matsumotory/ngx_mruby/pull/771)). To do: `test.sh` stops when a command of the certificates fails and says which one | `next`, `master` | Done: [#792](https://github.com/matsumotory/ngx_mruby/pull/792) on `master` and, by the merge of `master` in [#793](https://github.com/matsumotory/ngx_mruby/pull/793), on `next` |
| On 2.x, a rewrite handler that sleeps in `Nginx::Async.sleep` and returns `Nginx::DECLINED`, followed by an access handler of the same location that calls `Nginx::Async::HTTP.sub_request` and declines, leaves the request without a response (seen by the reviewer of [#740](https://github.com/matsumotory/ngx_mruby/pull/740) before and after its fix; without the sleep the answer is immediate). Assess on `next` first, where the fiber record of [#714](https://github.com/matsumotory/ngx_mruby/pull/714), [#715](https://github.com/matsumotory/ngx_mruby/pull/715) and [#722](https://github.com/matsumotory/ngx_mruby/pull/722) may already cover it; if 2.x still hangs, a fix with its regression test | `next`, then `master` if needed | Assessed on 2026-11-03: the normal composition completes with the `next` runtime of `c440a15dc`. A 100 ms sleep and its no-sleep control each returned 200, the expected static body and EOF in three requests bounded at 8 seconds (nginx 1.31.8, static suite build with GC stress and debug counters; runtime C statements unchanged). No next fix is indicated by these six requests. The 2.x follow-up is done in [#772](https://github.com/matsumotory/ngx_mruby/pull/772), whose test `async_sub_request_after_sleep.rb` also runs on `next` since [#777](https://github.com/matsumotory/ngx_mruby/pull/777) |
| A body filter whose request lost its module context while the response was still being written: [the review of #785](https://github.com/matsumotory/ngx_mruby/pull/785#issuecomment-6767421067) (should fix, "The other place that clears the module context") found that the body filter drops the context when an earlier handler's `Nginx.rputs` output is still in it, and that the response then stopped after its first write until `send_timeout` | `master`, then `next` | Done: fixed on `master` in [#786](https://github.com/matsumotory/ngx_mruby/pull/786) (`10c4cd927`), for locations with and without an mruby header filter, and brought to `next` by [#787](https://github.com/matsumotory/ngx_mruby/pull/787) |
| Make an mruby body filter run once on a proxied response that goes out in one write after an earlier handler's `Nginx.rputs` (should fix 4 of [the review of #786](https://github.com/matsumotory/ngx_mruby/pull/786#issuecomment-6768923430)). Today the empty last buffer that `ngx_http_upstream_finalize_request` sends runs the code of the body filter a second time on an empty body, and `$sent_http_content_length` logs `0` instead of the length. Since #786, a response sent in more than one write runs the code once and logs the length, so the logged value depends on the number of writes | `next` (a behavior change, not for 2.x) | Ready to start: a test of the one-write case with a proxied location of `test/conf/conf.d/90-body-filter-leftover-chain.conf`, a fix and an entry under "Behavior changes" of `docs/releases/v3.0.0.md` and `.ja.md` |
| Local checks first (the decision of 2026-11-12 under "Decisions") on `master`: the same change to AGENTS.md ("Design principles", "Branches and pull requests", "Review and merge", "Build and test"), `.github/PULL_REQUEST_TEMPLATE.md` and `docs/test/README.md` of `master` | `master` | Done: [#807](https://github.com/matsumotory/ngx_mruby/pull/807), merged on 2026-11-14 as `7a72306bb`; its fixes reach `next` in [#808](https://github.com/matsumotory/ngx_mruby/pull/808) |
| Candidates to add to the release procedure (`docs/releases/README.md`, "Before the tag" and "Security fixes"), seen in the 2.7.7 release: the pull requests of the fixes in the advisories' private forks did not check the release notes they changed as 3.x pages (the check of "The 2.x pages of the site" in `docs/test/README.md` on `master`), so two lines of `v2.7.7.ja.md` failed `check-japanese-lines.mjs` first in #810; the step that starts `site.yml` on `next` after the release was missed until 03:27 JST, so the home page named 2.7.6 until then; the check before the tag was not a public pull request (as for 2.7.6, it is recorded in this file); the "patched versions" of an advisory draft are set before it is published; the commit messages of the fixes in a private fork name neither the advisory id nor the details of the defect; and the whole build matrix runs on the public `master` before the tag | `master` (the procedure of 2.x releases), then `next` by the merge | Not started: a documentation pull request to `master` |
| An mruby body filter on a subrequest of SSI (`<!--# include virtual=... -->`): the included part is missing and the main response stops until `send_timeout`, also without any `Nginx.rputs` and with only a body filter (a note of [the review of #786](https://github.com/matsumotory/ngx_mruby/pull/786#issuecomment-6768923430), seen on `master` before and after #786) | `master`, then `next` by the merge | Ready to start: a regression test in a commit of its own, then the fix; the cause is not investigated yet |

## How a session continues

Use [Continuing shared work](DEVELOPMENT.md#continuing-shared-work) for
startup, ownership, checkpoints, temporary files and resumption. The rules
are in [AGENTS.md](../AGENTS.md#session-handoff); this file records the
queue and decisions, while each PR records its current head and evidence.
The procedure applies to Claude, Codex and human contributors alike.

## Private material

Vulnerability reports and their fixes are handled privately as
[SECURITY.md](../SECURITY.md) describes; this file does not record them.

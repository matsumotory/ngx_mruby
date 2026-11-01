# AGENTS.md

Instructions for AI coding agents (and a quick reference for humans) working on
ngx_mruby. Tool-specific notes live in separate files (for example `CLAUDE.md`).

## What ngx_mruby is

ngx_mruby embeds the mruby VM in nginx so that HTTP phase handlers, header/body
filters, SSL handshake handlers and stream (TCP/UDP) handlers can be written in
Ruby. It is built as a static or dynamic module of unpatched nginx.

- `src/http/`, `src/stream/`: the C module (HTTP and stream are separate code paths)
- `mrbgems/`: Ruby-side gems bundled into the build
- `build_config.rb`: mruby build configuration and the third-party mrbgems fetched at build time
- `mruby/`, `dependence/ngx_devel_kit/`: vendored upstream trees (see "Do not")
- `test/`: integration tests that start a real nginx (`test/conf/`, `test/html/`, `test/t/`)
- `docs/`: user documentation (install, directives, classes and methods) and
  release notes (`docs/releases/`)

## Design principles

The owner decided these on 2026-10-04. They hold on `master` and `next`:

- One `mrb_state` per worker, shared by the requests of that worker, and no
  `mrb_state` per request. A state per request would be safer, but it would
  be slow, and sharing objects between states is costly. Changes keep this
  balance of performance, security and convenience in mind.
- No blocking.
- Keep the existing performance.
- Measure performance regularly.

The rest of this section is how sessions apply these decisions. It is their
procedure, not a decision of the owner, and it changes through PRs to this
file. Read it before you change `src/`, `mrbgems/` or the build.

- Where the state is. nginx creates the `mrb_state` of an `http {}` block
  (and one for each `stream {}` block) while it reads the configuration, and
  each worker gets its own copy when it is forked. The state of a request
  lives in the request's module context (`ngx_http_get_module_ctx`; in
  stream, the session's). The server configuration, which all requests and
  connections of the server share, holds only state whose lifetime is
  explicit: it is set before the code that uses it and cleared after that
  code. Nothing fixed (a class reference, a symbol name, a buffer) is looked
  up or allocated per request when it can be prepared once at
  initialization.
- What the rule against blocking covers. ngx_mruby's own code (`src/`,
  `mrbgems/`) waits only through nginx: its events and timers, the return
  codes `NGX_DONE` and `NGX_AGAIN`, and the fiber-based `Nginx::Async`
  (`Nginx::Stream::Async` in stream), which suspends the Ruby code and
  resumes it from an nginx timer or at the end of a subrequest. A change adds
  no other wait: not for the network, a process or a timer, and not for a
  local file on the request path unless the PR gives the reason. These
  places block today:
  - a handler script without `cache` or `mruby_cache on` is read from disk
    on every request (`fopen`), and when a script gives `Nginx::SSL` the
    paths of a certificate and a key, they are read during the handshake
    (`BIO_new_file`, `SSL_use_PrivateKey_file`);
  - the bundled `auto-ssl` gem runs the dehydrated ACME client and waits
    for it to finish;
  - `Nginx::Upstream#server=` resolves a host name with the system resolver
    when it is called (`ngx_parse_url` without `no_resolve`) and waits for
    the answer; an IP address does not wait;
  - an operator's script blocks its worker when it uses mruby-sleep,
    mruby-socket or mruby-io, which the default build includes on both
    branches, or matsumotory/mruby-redis (a hiredis client), which the
    default build includes again since 2.7.2. The rule is for ngx_mruby's own code, not for such scripts.
- Which changes are measured. A PR that changes an input of the measured
  binary is compared with its base in the callgrind lane ("Performance
  comparison with callgrind" in `docs/test/README.md`). The inputs are
  those that "In CI" in `docs/test/README.md` lists: `src/`, `mrbgems/`,
  `mruby/`, `dependence/`, `build_config.rb`, `configure`, `config.in`,
  `Makefile.in`, `build.sh`, `nginx_version`, and on `next` the gem lock
  `build_config.rb.lock` (`master` commits no lock). The `perf` job of
  `.github/workflows/test.yml` runs the comparison on such PRs, on `master`
  and on `next`.
  - The author quotes the comparison in the PR body, under "Leak /
    performance impact" (see `.github/PULL_REQUEST_TEMPLATE.md`): the table
    with the header lines of `report.txt` above it (the line with `N`,
    `WARMUP` and the thresholds, and the lines on the gems; in the job's
    log), the run of the `perf` job, and the commits that its log prints
    (`base: ..., head: ...`). When the base branch gains a change to a
    measured input before the merge, the comparison is made and quoted
    again by the CI run that condition 2 of "Review and merge" asks for.
  - The lane builds nginx without `--with-stream` and has no stream
    scenario, so for a change to `src/stream/` alone both builds are the same
    binary. Such a PR says so and states instead what the change adds per
    session, as read from the diff (calls, allocations, copies).
  - The reviewer writes, for the scenario with the largest change and for
    each row that is not `ok`: its base and head Ir per request without GC,
    and the change in instructions per request and in percent.
  - A scenario at `WARN` (3% or more instructions per request without GC
    than the base) or `FAIL` (5% or more) holds the merge until the owner
    accepts the difference on the PR; the session asks the owner. `ERROR`
    means that the scenario was not measured: fix the run or run it again.
  - The scenarios with an upstream vary with when the upstream's response
    arrives; the report prints their relay calls per request
    (`non_buffered_calls`). Such a scenario at `WARN` or `FAIL` is measured
    a second time only when the first report's line for it ends with the
    note `the change of this scenario may come from when the response arrived`,
    which the report prints when the difference of those calls alone makes
    half of the `WARN` threshold or more ("Agent proxy scenarios in the
    comparison" in `docs/test/README.md`). Both runs are quoted, and the
    second replaces the first. In every other case, the `WARN` or `FAIL`
    goes to the owner without a second run.
  - A session does not merge a PR while the latest run of its `perf` job
    reports `FAIL` or `ERROR`, except for a `FAIL` that the owner accepted
    on the PR. This holds although `ci-ok` does not need the job yet (on
    `next`, "In CI" in `docs/test/README.md` still calls the job advisory;
    a follow-up PR to `next` aligns that text). The plan (Pillar E of
    `docs/proposals/v3-plan.md` on `next`) adds the job to the `needs` of
    `ci-ok` once it has run on code changes without false alarms; from then
    on a `FAIL` or an `ERROR` also fails `ci-ok`.
- Before a tag. Each PR is compared only with its base, so changes that
  stay below `WARN` can add up. The check PR of "Before the tag" (see
  `docs/releases/README.md`) therefore also compares its head with the tag
  where the range of the check starts. The base is that tag, and the head
  must contain the tip of its base branch, so update the branch first. From
  a checkout of the check PR's head commit (`<base>` is `master` or
  `next`):

  ```sh
  git fetch origin <base> --tags
  git merge-base --is-ancestor origin/<base> HEAD   # exits 1 when the branch is behind: update it first
  D=$HOME/ngx_mruby-perf   # any directory outside the checkout
  rm -rf "$D" && mkdir -p "$D/base" "$D/head"
  git archive <tag> | tar -x -C "$D/base"
  git archive HEAD | tar -x -C "$D/head"
  cd "$D/head" && sh test/perf/compare.sh "$D/base"
  ```

  The last line needs Linux and valgrind. On macOS, run this line in its
  place; it runs `compare.sh` in a Linux container with `$D` mounted at the
  same path:

  ```sh
  docker run --rm -v "$D:$D" -w "$D/head" -e D="$D" ubuntu:22.04 sh -c 'apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y build-essential rake ruby bison git gperf wget ca-certificates zlib1g-dev libpcre3-dev libssl-dev valgrind >/dev/null && sh test/perf/compare.sh "$D/base"'
  ```

  The report is in `$D/head/build_perf/report.txt`. The measurement
  (`test/perf/`, the scenarios in `test/soak/`) comes from the head, so a
  tag from before the lane was added is measured as well. The check PR
  quotes the table as above, and a `WARN` or `FAIL` there goes to the
  owner.
- Planned, not in place yet: a benchmark of the test nginx for throughput
  and latency (Pillar E and section 8 of `docs/proposals/v3-plan.md` on
  `next`). Where its results are recorded is decided when it is added.

## Branches and pull requests

| Branch | Role | Who changes it |
|---|---|---|
| `master` | 2.x line until v3 is promoted, then 3.x | PRs only; merged as described in "Review and merge" |
| `next` | v3 development (pre-release tags `vX.Y.Z-alpha.N`/`-beta.N`/`-rc.N`) | PRs only; merged as described in "Review and merge" |
| `v2.x` | 2.x maintenance; an automatic mirror of `master` until v3 is promoted | Mirror automation; after promotion, PRs merged as described in "Review and merge" |

The 2.x line (`master` until v3 is promoted, then `v2.x`) puts compatibility
first; this is the owner's decision of 2026-10-04. It takes stability fixes
(crashes, hangs, leaks, build fixes) and security fixes, and changes behavior
that a configuration, script or build can observe only as far as the fix of a
defect requires, with its entry under "Behavior changes: read before
upgrading". New behavior, API cleanups and features go to `next`.

- 2.x fixes: PR with base `master` until v3 is promoted (afterwards: base `v2.x`).
  A fix that also applies to v3 still goes to `master`; it reaches `next` when
  `master` is merged into `next`, so do not open a duplicate PR unless asked.
- v3 work: PR with base `next`.
- Never push to `master`, `next` or `v2.x` directly. Until v3 is promoted, `v2.x`
  is written only by the mirror automation: never commit to it or open PRs against it.
- Topic branches: `claude/<topic>` (other tools: `<tool>/<topic>`).
  Backports to 2.x: `backport/v2.x/<topic>`.
- Never create branches named like tags (`v2.7.1`, `v3.0.0-rc.1`), and never
  create `next/*` or `v2.x/*` branches (they clash with the existing branch refs).
- Agents open PRs and fill in every section of the PR template. A PR is a
  draft while its author's work is not finished: the implementation, or a
  verification that the template asks for, is still to do. A draft runs no
  CI: the workflows skip their jobs for a draft, and `test.yml` reports
  `ci-ok (draft)`, not `ci-ok`. Before marking the PR ready, the author
  runs the local checks that the change needs (the suite, `sh
  test/ci/changes_test.sh`, the site's checks, and what the template asks
  for) and quotes them under "How was this tested". Then the author marks
  the PR ready for review (`gh pr ready`), which starts the CI run and asks
  for the review below; every later push to the head runs CI again, and
  cancels the run of the previous head. A PR is not kept as a draft
  because it waits for that review, and is not marked ready to see what CI
  says. Ready means handed to review, not approved and not allowed to
  merge: the conditions of "Review and merge" decide that. A PR that stays
  a draft says at the top of its body why (what is unfinished or not
  verified), who continues it, and what ends the draft.
- CI is limited to what cannot run locally, the environments that a
  machine does not have (the cells of the build matrix, the sanitizers,
  valgrind, the callgrind comparison), and to the deploy of the site; the
  tests are run locally. The owner set the rule on 2026-10-31: CI is only
  the final check in a clean environment, the tests are done thoroughly
  locally, and CI is not packed with so many tests that a run takes tens
  of minutes. On 2026-11-02 the owner added that CI is not relied on: when
  the local tests are thorough, CI is the minimum, and CI that covers many
  environments stays, but what runs locally is not repeated in CI at the
  cost of time and money (the owner's words of both days are quoted in
  "Decisions" of `docs/HANDOFF.md` on `next`). So a PR to `next` runs no
  job of `site.yml`: the author runs `npm run check:ci` in `site/`, and
  `site.yml` runs on the push to `next`, where it builds, checks without a
  browser, deploys and checks the published site ("Site CI" in
  `docs/test/README.md` on `next`). In the same way, a PR to `master`
  runs no job of `site-v2.yml`: its author checks the 2.x pages locally
  ("The 2.x pages of the site" in `docs/test/README.md`), and the push to
  `master` starts `site.yml` on `next` through `site-dispatch.yml`, which
  builds `/v2/` from the new `master` before it deploys. The sessions
  apply the rule this way (their procedure, not a
  decision of the owner): the author runs the checks that the change
  touches locally before marking the PR ready (the suite among them when
  `test/ci/changes.sh` gives `build` `standard` or `full`), and quotes the
  commands and their results under "How was this tested"; a check that
  can run locally is not left to CI ("Build and test" lists the local
  commands). The run of a ready PR runs the smallest set of jobs that the
  change needs ("Which jobs a run starts" in `docs/test/README.md`). The
  owner decided on 2026-11-01 that a change of the code runs four cells
  of the build matrix, and every cell the scheduled run and the check
  before a release ("Decisions" in `docs/HANDOFF.md` on `next`). The
  sessions apply it this way (their procedure): a change of the code or
  the tests runs nginx 1.31.8 with the static module, 1.30.6 with the
  dynamic module, the sanitizer cell and the cell under valgrind; every
  cell runs in the nightly run, on the push of a tag, in the check PR
  before a tag (the label `full-matrix`) and on "Run workflow" without the
  input `base`. The run finishes in about
  fifteen minutes, not in tens of minutes: on
  2026-10-31, a cell of the build matrix took 6 to 14 minutes and the run
  of `test.yml` with the whole matrix 15 minutes ("Required status check"
  in `docs/test/README.md`). A proposal to add a check to CI says whether it
  can run locally, why CI needs it, and how many minutes it adds to the
  run.
- The PR body says which commits each result stands for: for the runs
  under "How was this tested", the commit they ran on; for the CI run that
  condition 2 of "Review and merge" counts, the head commit and the base
  commit of its merge ref. A job that a run skipped passed nothing, except
  where "Which jobs a run starts" in `docs/test/README.md` says that
  `ci-ok` passes the skip. Which jobs a run starts depends on the kind of
  files that the PR changes, as `test/ci/changes.sh` classifies them (the
  table in "Which jobs a run starts"): a check that the change cannot
  affect is not run for the sake of it. When the base moves, the session
  that holds the PR says, by condition 2 of "Review and merge", whether
  the run still counts.
- A PR that changes behavior a configuration, script or build can observe (a
  bug fix, a raised build requirement and a change of the bundled mruby or
  default mrbgems included; see `docs/releases/README.md` for what counts)
  adds its entry under "Behavior changes: read before upgrading" in
  `docs/releases/<version>.md`, in the same PR: before, now, why it changed,
  what is affected, what to do. The same PR adds the entry in Japanese to
  `docs/releases/<version>.ja.md`, and creates that file by translating the
  whole English file if the release has none yet (see "Who writes the
  entries, and when" in `docs/releases/README.md`). Users have built on the
  old behavior, so the new release must warn them.
- Agents never move or delete tags, and create a tag only as part of a
  release (`gh release create` creates it); they never publish security
  advisories: the owner publishes the advisory. A session publishes a
  release, and with it the tag, after the owner, asked by the session,
  has given the go-ahead for that release, once the check of "Before the
  tag" is merged and, for a security fix, the owner has merged the fix
  from the advisory's private fork (the owner's decision of 2026-11-02).
  Before a tag, a PR checks the release notes against every PR merged since
  the previous release (see "Before the tag" in `docs/releases/README.md`),
  and compares the performance with that release (see "Design principles").

### Review and merge

Every PR gets a review by an agent (or person) that did not write it, with
this checklist: the change is inside the agreed scope (`docs/proposals/` on
`next`, an issue, or a fix with evidence); the code and tests are correct when read
against `src/` and, where it matters, the nginx source; a bug fix has its
regression test in a commit of its own before the fix commit, and the
reviewer has run the suite at both commits (failing, then passing, with
results matching what the author quoted); expectations assert
on real responses, not only on "not 500"; "How was this tested" in the PR
body quotes the local runs of the checks that the change touches (the
suite among them when `test/ci/changes.sh` gives `build` `standard` or
`full`), with their commands and results (see "Branches and pull
requests"); the CI result on the head commit;
when an input of the measured binary changed, the performance comparison
quoted in the PR body and the numbers that "Design principles" asks the
reviewer to write;
compatibility notes in the PR body match the diff; a change of behavior that a
configuration, script or build can observe has an entry under "Behavior
changes: read before upgrading" in `docs/releases/<version>.md` with every
line of the template, and the same entry in Japanese in
`docs/releases/<version>.ja.md` (see "Who writes the entries, and when" in
`docs/releases/README.md`), and `docs/directives/`,
`docs/class_and_method/` or `docs/install/` describe the new behavior; a PR
that moves the pin of one of the owner's gems links the
gem's PR, which has its review and the suite results (see "Other
repositories"); nothing in the diff, the
commit messages or the PR text discloses an unpublished vulnerability or a
secret; and `docs/` is updated when a directive, Ruby method, build option or
the test harness changes. The reviewer posts the findings as a PR comment,
split into "must fix" (blocks the merge) and "should fix". A behavior change
of the PR without that entry, an entry of the PR that lacks a line of the
template, and an entry of the PR whose Japanese version is missing or says
something other than the English entry are each a "must fix" (which entries
count as the PR's own, also when the PR creates the Japanese file of an
earlier release file, is in "Who writes the entries, and when" in
`docs/releases/README.md`). A missing "New features", "Fixes" or "Build and
test changes" entry, and a missing or different Japanese version of one, are
a "should fix". The author fixes every "must fix" and asks for a re-review of
those items only.

The session that owns the PR merges it, with a merge commit, when all of
these hold:

1. The base branch follows the branch table above.
2. Every CI check on the head commit passed (`ci-ok`, the check that the
   branch rules of `master` and `next` require) on the PR's latest run
   for that commit. When the base has moved since that run, the branch is
   updated and CI runs again only when both the PR and the base's new
   commits change `code` or `tests`: with `BASE_AT_RUN` the base commit
   of the run's merge ref (the first parent of `refs/pull/N/merge` at
   that time, which the `changes` job prints), the output of `sh
   test/ci/changes.sh BASE_AT_RUN origin/<base>` (the base's new files)
   and that of `sh test/ci/changes.sh "$(git merge-base origin/<base>
   HEAD)" HEAD` (the PR's own files) both give `code` or `tests` `true`
   (one of them in each output is enough, since the build runs the tests
   on the code). An overlap of `docs`, `site`, `examples` or `workflows`
   alone runs nothing again. The owner decided on 2026-11-02 that CI is
   not relied on for what runs locally (the owner's words are quoted in
   "Decisions" of `docs/HANDOFF.md` on `next`). The sessions apply it
   this way (their procedure, not a decision of the owner): the checks of
   those categories are the author's local runs under "How was this
   tested" (`npm run check:ci` in `site/` of `next` for `docs`, `site`
   and `examples`, on `master` the checks of "The 2.x pages of the site"
   in `docs/test/README.md`, zizmor for `workflows`; "Build and test"),
   which a run
   on a moved base would only repeat, and on `next` the run of `site.yml`
   on the push of the merge builds and checks the merged tree before it
   deploys, and fails there instead of publishing (a push to `master`
   starts that run on `next` through `site-dispatch.yml`). A failure
   there is fixed by a PR of its own. The rulesets do not require an
   up-to-date branch, so this condition is the check. A run made green by
   skipping or disabling tests does not count. A run in which the
   `changes` job of `test.yml` skipped jobs that the PR's files do not
   need counts ("Which jobs a run starts" in `docs/test/README.md` has
   the table of what runs for which category).
3. The change is inside the agreed scope, or is a bug fix with the two-commit
   evidence described under "Writing tests", or changes documentation only.
   In every case, a change of behavior that a configuration, script or build
   can observe has an entry under "Behavior changes: read before upgrading"
   in `docs/releases/<version>.md` with every line of the template, the same
   entry in Japanese in `docs/releases/<version>.ja.md`, and the docs
   describe the new behavior.
4. The review above is recorded on the PR and no "must fix" item is open.
5. The scrub for secrets and unpublished vulnerability details passed.
6. The PR has no conflicts with its base.
7. The PR is marked ready for review (GitHub does not merge a draft).

If any condition cannot be met, the session says which one and why, and asks
the owner instead of merging.

### Other repositories

The owner decided on 2026-10-04 that sessions may change the mrbgem
repositories that the owner maintains (`matsumotory/mruby-*`), mruby-uname
included.

The owner decided on 2026-10-29, in the words 「僕管理のmrbgemは更新して対応できるなら更新すべき、なんでも外すとかではなく。只中で使ってるライブラリとかの更新が止まってたらもういいかな」
("a gem I maintain should be updated, if updating copes with the change, not
removed; if a library it uses inside has stopped being updated, it is fine to
drop it"): a gem that the owner maintains is updated to cope with a change and not
removed from a build. Removing one is
acceptable when a library that the gem uses inside has stopped being updated.

The rest of this subsection is the sessions' procedure, not a decision of
the owner. It names the branches as they are until v3 is promoted, as the
branch table does; step 4 of "Promoting v3 to master" in
`docs/DEVELOPMENT.md` rewrites both. `master` commits no gem lock (its
`.gitignore` lists `build_config.rb.lock`), and mruby clones a `github:`
gem at the head of its `master` branch when no lock pins it. A merge into
a gem's `master` branch therefore reaches every later build of `master`,
CI included, and every source build of a released 2.x tag, without a PR
here. The 2.x policy and the release notes rule above apply to such a
merge as to a PR here.

- Each change is a PR on the gem's repository, from a branch of that
  repository to its default branch. An agent that did not write it reviews
  it with the checklist of "Review and merge", as far as it applies, and
  posts the findings on that PR.
- Before the merge, the author runs ngx_mruby's suite (`sh test.sh`) on a
  checkout of `master` and on one of `next`, each with the gem at the head
  commit of the gem's PR, and quotes both results on the gem's PR, with the
  command, the nginx version and the commits of ngx_mruby and of the gem. To
  build a gem at a commit, add `checksum_hash: '<commit>'` to each
  `conf.gem github: 'matsumotory/<gem>'` line of `build_config.rb` (a local
  edit, not committed) and remove `mruby/build` first. On `next`, the build
  also rewrites the committed `build_config.rb.lock`: restore both files
  afterwards with `git checkout -- build_config.rb build_config.rb.lock`. A
  gem that the default build leaves out has no such line (its line is
  commented out, or there is none): enable it in
  the same local edit for the run and say so with the quoted results, or
  quote the gem's own tests and name the later PR that enables it, whose
  suite runs then cover it. The gem's own tests run as well where it has
  them. Most of these gems have no CI of their own, and mruby-userdata has
  no tests, so ngx_mruby's suite is the evidence that counts.
- The change keeps the behavior that a configuration, script or build of
  2.x observes, unless it fixes a defect. For a fix that changes such
  behavior, a PR to `master` adds the entry under "Behavior changes: read
  before upgrading" (see `docs/releases/README.md`), naming the gem's PR,
  and is merged before the gem's PR. A change that is not a defect fix,
  such as a new method, an API change or a cleanup, is not merged into the
  gem's `master` branch, which 2.x builds take: the 2.x policy sends such
  changes to `next`, so the session asks the owner. Other fixes and build
  changes that the release notes list get their entry through a PR to
  `master` as well, so that "Before the tag" in `docs/releases/README.md`
  finds them.
- The session that owns the gem's PR (the one that opened it, or one that
  took it over in a comment on it) merges it, with a merge commit, when all
  of these hold: the review is recorded on the gem's PR and no "must fix"
  item is open; both suite results are for the PR's current head commit,
  which is up to date with the gem's default branch, and pass; every entry
  that the release notes need for the change (a behavior change, a fix or a
  build change) is merged through a PR to `master`; nothing in the gem's
  PR discloses an unpublished vulnerability or a secret; and the PR has no
  conflicts. If any of these cannot be met, the session asks the owner
  instead of merging.
- Afterwards, a PR to `next` moves the gem's pin in `build_config.rb.lock`
  to the merge commit on the gem's default branch. The `perf` job measures
  it like any change of the lock.
- A possible vulnerability in a gem goes to the security process of
  `SECURITY.md`, as "Security" below says, not into a PR on the gem. For
  other defects, do not rewrite a patch from private material into a gem:
  derive the fix from the symptom (the failing build, test or output).

## Session handoff

The owner decided on 2026-10-04 that the information about the work that
may be public is kept in the repository, so that another session can
continue it.

How sessions do it (their procedure, not a decision of the owner):

- `docs/HANDOFF.md` on `next` records the state of the work: the heads of
  the branches, the open PRs and their stage, the owner's decisions with
  their dates and the place where each will be written, the work in
  progress, and the queue. The heads and stages are a snapshot as of the
  date in its heading; check them with `git` and `gh` before you act on
  them.
- A PR with base `next` updates the file in the same PR when it changes
  what the file records, its own row and the item of the queue that it
  finishes included. A PR with base `master` cannot, because the file is
  only on `next`: after the merge, the session that merged it updates the
  file in a small PR to `next`, or in the merge of `master` into `next` if
  that comes first. A release is recorded in the same way by the first
  session that finds its tag missing from the file.
- It records state. The rules live in this file and in the plan
  (`docs/proposals/v3-plan.md` on `next`). A decision of the owner that is
  not written there yet is recorded in `docs/HANDOFF.md` with its date. It
  holds over an older text here until a PR writes it here, but only when
  its row links the owner's comment or quotes the owner's words; a row
  without either is a proposal of the sessions and changes no rule.
- It never holds unpublished vulnerabilities, the ids of advisories that
  are not published, names of private branches, files from outside the
  repository, or which release or work carries the fix of a vulnerability
  that is not published. A published advisory, its id and the release
  that fixed it may be named, as the release notes name them.
- There is no copy on `master`. From a checkout of `master`, read it with
  `git fetch origin next` and `git show origin/next:docs/HANDOFF.md`.
- Before a session hands a PR over, to another session, another tool or a
  person, or stops while the PR is open, it checks and writes down:
  whether the PR is a draft or ready, and why; the head commit; the CI
  result with the head and base commits it stands for; the review items
  still open; and who continues it. The top of the PR body (its "State"
  paragraph or the dated checkpoint comment that "Continuing shared work"
  in `docs/DEVELOPMENT.md` asks for) and the row in `docs/HANDOFF.md` say
  the same state, and text that the state has left behind (a "WIP"
  paragraph, "the comparison is not finished", "keep as a draft for X") is
  rewritten in the same change. The next session reads the state from the
  final diff and the recorded results, not from the names of earlier WIP
  commits; rewriting the branch's history is not how the record is fixed,
  an ordinary commit is.
- A tool's own instructions for this repository (`CLAUDE.md` for Claude
  Code, and the like) add conventions of that tool, such as where it keeps
  worktrees and temporary files. What a draft and ready mean, what a CI
  result stands for, and what a handover records are decided here and in
  "Required status check" of `docs/test/README.md`; a tool's file that
  says otherwise is corrected.
- These records are shared by human, Claude and Codex sessions. A tool's
  memory may help locate evidence, but is not the source of the current
  scope, decisions or validation. Use the repository and the PR, following
  [Continuing shared work](docs/DEVELOPMENT.md#continuing-shared-work).
- At the start or resumption of work, check the current branch heads, open
  PRs and their latest comments before claiming a queue item. Before a
  takeover, confirm that the previous writer has stopped and preserve its
  worktree and uncommitted changes. One writer owns each task worktree;
  independent reviewers read it without changing it. Record ownership on
  the PR before pushing another session's branch.
- Keep the PR body current when its head, scope or verification changes.
  Before a planned stop or transfer, leave a dated checkpoint in the PR
  with the head and base, completed work, commands and results tied to
  commits, checks still running or not run, unresolved decisions or
  blockers, and the next concrete step. Link to existing review/CI evidence
  instead of copying raw logs. Update HANDOFF as above when the queue or
  state changes; do not make another private handoff file the only record.
- Public checkpoints use repository-relative paths and public commit/PR/run
  links. Do not commit private conversation logs, absolute local paths,
  personal reference images, credentials or scratch outputs. Keep local
  work records outside the checkout or under narrowly ignored directories;
  inspect ignored, untracked, tracked and staged files before committing.
  An ignore rule does not remove a tracked file. An interruption does not
  justify deleting another session's files, rewriting history or changing
  tests to make a check green.

## Build and test

Requirements are listed in `docs/install/` (C compiler, `make`, `bison`, `git`,
Ruby with `rake`, OpenSSL). nginx also needs the PCRE and zlib development
headers, and `test.sh` uses `wget` and the `openssl` command. mruby is built with
`rake`: if it is not on `PATH` because Ruby is managed by a version manager
(rbenv, asdf, ...), put that Ruby's `bin` directory on `PATH` first.

```sh
sh test.sh                          # full run: fetch nginx (version in ./nginx_version), configure, build, test
ONLY_BUILD_NGX_MRUBY=1 sh test.sh   # fast loop: skip fetch/configure, rebuild changed sources, re-run tests
BUILD_DYNAMIC_MODULE=1 sh test.sh   # build as a dynamic module (uses build_dynamic/ instead of build/)
NGINX_RUNNER=valgrind sh test.sh   # run nginx under valgrind (NGINX_HEATTIME, 60 s by default, bounds each wait of test.sh for ports and for nginx)
sh test/perf/compare.sh BASE_DIR    # callgrind Ir per request, BASE_DIR vs this checkout (Linux, valgrind; builds in build_perf/, ports 12370-12372)
```

- Run these before a PR is marked ready: CI runs only what cannot run
  locally, and is not the place where a change is first tested (see
  "Branches and pull requests"). Run the local commands of the checks that the
  change touches: the suite when `test/ci/changes.sh` gives `build`
  `standard` or `full`, `sh test/ci/changes_test.sh` for `test/ci/`, the build of
  the 2.x pages for `docs/` ("The 2.x pages of the site" in
  `docs/test/README.md`), zizmor for `.github/` ("Static analysis of the
  workflows" there), and `sh test/perf/compare.sh` where the change
  affects what it measures. `docs/test/README.md` describes each of them.
- The first full run takes a few minutes (it clones mrbgems from GitHub and builds
  mruby and nginx). After that, use `ONLY_BUILD_NGX_MRUBY=1`.
- `ONLY_BUILD_NGX_MRUBY=1` reuses the last configure. After changing
  `BUILD_DYNAMIC_MODULE`, configure options or `nginx_version`, nginx has to be
  configured again: "Testing" in `docs/test/README.md` says when a full run does
  that and what to remove first.
- Extra arguments to `test.sh` are passed to `./configure`
  (for example `sh test.sh --with-openssl-src=/path/to/openssl`).
- Headers in `src/` are not make dependencies: after editing a `.h`, `touch` the
  `.c` files that include it.
- `test.sh` adds `-DMRB_GC_STRESS` to `NGX_MRUBY_CFLAGS`. An existing mruby build is
  not rebuilt when only these flags change; use a separate worktree/checkout for
  sanitizer builds.
- Results: the test runner exits non-zero on a failed assertion. nginx logs are in
  `build/nginx/logs/` (`build_dynamic/nginx/logs/` for dynamic builds);
  `error.log` is at debug level. valgrind errors do **not** change the exit status
  of `test.sh`: run valgrind with the options of CI and read the `ERROR SUMMARY`
  line of its log yourself. In CI, the step "Check the valgrind reports" fails a
  cell on that line: one cell runs under valgrind on the pull requests whose
  run starts the build matrix, and every
  cell except the sanitizer cell in the nightly run ("valgrind in CI" in `docs/test/README.md` has the options,
  what counts as an error and the suppressions).
- `test.sh` listens on fixed ports (18080-18090, 18101-18103, 18110-18131,
  18133-18139, 18143-18144, 18147-18158, 18171-18174, 18187, 12345-12359,
  12363-12365, 12368-12369, 12374-12378, 12384-12388, 12390-12391; 18116, 12357 and 12385-12388 belong to the second nginx that
  `test/t/cases/_second_instance.rb` starts, 18158 to the nginx that
  `test/t/cases/config_hooks.rb` starts, 18173 and 18174 to the nginx that
  `test/t/cases/auto_ssl.rb` starts, 12399 to a test in
  `test/t/ngx_mruby.rb`; with the services of `test/auto_ssl/deps.sh`, also
  6379, 8053, 8055, 14000, 14001, 15000 and 15001, see "Testing the auto-ssl mrbgem" in
  `docs/test/README.md`) and
  kills every running `nginx` process before it starts. Run only one `test.sh` per
  machine at a time, and wait if an nginx you did not start is running.
- `test/perf/compare.sh` builds the base and the head in `build_perf/` (it does not
  touch the `test.sh` build), listens on 12370 and 12371, and starts the mock LLM
  upstream (`test/soak/mock_llm.rb`) on 12372 for the agent proxy scenarios
  (`PERF_PORT_BASE` moves all three). It stops only the processes it started.
  `test.sh` kills its nginx too, so do not run both at the same time on one
  machine. It needs valgrind's `callgrind_control` and `vgdb`: on macOS, run it
  in a Linux container. See "Performance comparison with callgrind" in
  `docs/test/README.md`.

### When nginx.org is unreachable

`test.sh` downloads `http://nginx.org/download/nginx-X.Y.Z.tar.gz` only if
`build/nginx-X.Y.Z` does not exist. Pre-populate it from the nginx GitHub tag;
the Makefile handles git checkouts (which have `auto/configure` instead of `configure`):

```sh
. ./nginx_version
git clone --depth 1 --branch release-${NGINX_SRC_MAJOR}.${NGINX_SRC_MINOR}.${NGINX_SRC_PATCH} \
  https://github.com/nginx/nginx build/${NGINX_SRC_VER}    # build_dynamic/... for BUILD_DYNAMIC_MODULE
sh test.sh
```

## Writing tests

- Prefer a fragment and a case file of their own: a `server {}` in
  `test/conf/conf.d/<name>.conf` (stream: `test/conf/conf.d/stream/`) on a
  port of its own (HTTP 18110 and up, stream 12353 and up), scripts in
  `test/html/`, and assertions in `test/t/cases/<name>.rb` (see
  `docs/test/README.md`). Edit `test/conf/nginx.conf` and
  `test/t/ngx_mruby.rb` only for tests that need the main server.
- A bug fix comes as two commits: the first adds the regression test and
  nothing else, the second adds the fix.
  - The author runs the suite at each commit (it fails at the first because
    of the new test and nothing else, and passes at the second) and quotes
    both results in the PR body, with the command and the nginx version. The reviewer checks out each commit and repeats
    the two runs. A test that is only shown failing on the base branch in
    prose, or that lands in the same commit as the fix, does not count.
  - For a bug that only valgrind or a sanitizer reports (a leak, an
    undefined-behavior report), "fails" means the report in
    `build/nginx/logs/error.log` or the valgrind output that the new test
    provokes (quote it; see `docs/test/README.md`). Sanitizer builds need a
    checkout of their own.
  - When switching between the two commits, touch the `.c` files that
    include a changed header before building: headers in `src/` are not
    make dependencies, so an unchanged `.c` is not rebuilt otherwise.
  - The merge commit keeps the red first commit in the history, so
    `git bisect` needs `git bisect skip` on it.
  - When no harness test can express the bug (build, CI or packaging
    problems), say so in the PR and ask the owner what evidence to use
    instead.
- Assert on the actual response (body, headers, status), not only on "not 500".
- Do not change existing expectations, or remove or skip tests, without the
  owner's approval. If an expectation looks wrong, say so in the PR instead.
- Do not shorten the `Nginx::Stream::Async.sleep 3000` of the 12352 server in
  `test/conf/nginx.stream.conf` or the `sleep 0.3` in `test/t/issue-268-test.rb`:
  these delays are what those tests exercise.
- The main test server (port 18080) has server-level handlers
  (`mruby_set_code`, `mruby_server_rewrite_handler_code`,
  `mruby_post_read_handler_code`) that run for all of its locations. Tests of
  phase or return-code behavior may need their own `server {}`.

## Do not

- Edit `mruby/` or `dependence/ngx_devel_kit/` by hand. They are vendored with
  git subtree and updated only with `./update-mruby-subtree [ref]` and
  `./update-devkit-subtree [ref]` (see `docs/DEVELOPMENT.md`), in a PR of their own.
- Edit generated files: `config`, `Makefile`, `config.status`, `config.log`
  (outputs of `./configure`; edit `config.in` / `Makefile.in` instead).
  `configure` is autoconf output: edit `configure.in`, regenerate with `autoconf`
  and commit both.
- Run `killall nginx` or `pkill nginx` yourself (outside `test.sh`): other
  sessions may own those processes. Stop only processes you started.
- Run `make clobber`: it deletes the build directory (including the nginx source
  tree) and the mruby build. Only do it when the owner asks.
- Reformat code you did not change. Format only your changed lines with the
  repository `.clang-format`: stage your changes, then run
  `git clang-format origin/<base>` (it refuses files with unstaged changes).

## Security

Report vulnerabilities privately as described in `SECURITY.md`. Never put
vulnerability details or reproducers in public issues, PRs, commit messages,
test names or files. If you find a possible vulnerability while working, stop
and report it to the person you are working for instead of fixing it in public.

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
  release notes (`docs/releases/`); `docs/ja/` holds the Japanese pages
- `site/` (on `next`): the ngx.mruby.org site, Astro and repository-owned components, built
  from `docs/` (see "The site" under "Build and test", and
  `docs/proposals/site.md`)
- `examples/` (on `next`): examples that run with `docker compose`, each
  with a `README.md` whose commands and outputs the `examples` workflow
  checks (`examples/check_example.py`); `examples/start/` is the start
  page of the site

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
  - an operator's script blocks its worker when it uses mruby-sleep,
    mruby-socket or mruby-io, which the default build includes on both
    branches, or matsumotory/mruby-redis (a hiredis client), which the
    default build includes again since 2.7.2. The rule is for ngx_mruby's
    own code, not for such scripts.
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
  owner. The accepted differences of `test/perf/accepted.txt` ("Known
  differences" in `docs/test/README.md` on `next`) apply to this comparison
  too: a row within the allowance of a line whose condition both builds
  match is `ok (accepted: ...)`, and a change above it keeps its `WARN` or
  `FAIL`.
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
- CI is the final check in a clean environment, and the tests are run
  locally. The owner set this rule on 2026-10-31 (the owner's words are
  quoted in "Decisions" of `docs/HANDOFF.md` on `next`): CI is only the
  final check in a clean environment, the tests are done thoroughly
  locally, and CI is not packed with so many tests that a run takes tens
  of minutes. The sessions apply it this way (their procedure, not a
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
  2026-10-31, a cell of the build matrix took 6 to 14 minutes, the run of
  `test.yml` with the whole matrix 15 minutes, and a browser lane of the
  site 3 to 8 minutes, the lanes in parallel ("Required status check" in
  `docs/test/README.md`). A proposal to add a check to CI says whether it
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
- Agents never create, move or delete tags, and never publish releases or
  security advisories. Those stay with the owner. Before a tag, a PR checks
  the release notes against every PR merged since the previous release (see
  "Before the tag" in `docs/releases/README.md`), and compares the
  performance with that release (see "Design principles").

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
   for that commit. The run counts as long as the base has gained no file
   of a category that the PR also changes since the base of that run. With
   `BASE_AT_RUN` the base commit of the run's merge ref (the first parent
   of `refs/pull/N/merge` at that time, which the `changes` job prints),
   compare the output of `sh test/ci/changes.sh BASE_AT_RUN origin/<base>`
   with that of `sh test/ci/changes.sh "$(git merge-base origin/<base>
   HEAD)" HEAD` (the PR's own files). Three groups
   count as one category each, because their checks read each other's
   files: `code` and `tests` (the build runs the tests on the code), `docs`,
   `site` and `examples` (the site builds and checks all three), and
   `workflows`. When a group is `true` in both outputs, the branch is
   updated and CI runs again; otherwise it is not. The checks of the site
   and the examples also read `src/`, `test/` and `build_config.rb` (the
   directive tables, the cases, the gems), so a change of `code` or
   `tests` in the base can break a PR of the second group that this rule
   lets merge; the run of `site.yml` on the push to `next`, which must pass
   before it deploys, catches it, and the fix is a PR of its own (a push to
   `master` starts that run on `next` through `site-dispatch.yml`). On
   `master`, `site-v2.yml` checks the 2.x pages of every ready PR to
   `master`, and those pages link to any file that git tracks (the
   workflows, `nginx_version`, `.travis.yml`), so a base change of
   `workflows` that renames or removes such a file can break a `docs` PR in
   the same way; the same push run catches it. The rulesets do
   not require an up-to-date branch, so this condition is the check. A run
   made green by skipping or disabling tests does not count. A run in
   which the `changes` job of `test.yml` skipped jobs that the PR's files
   do not need counts ("Which jobs a run starts" in `docs/test/README.md`
   has the table of what runs for which category).
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
Ruby 3.0 or later with `rake`, OpenSSL). nginx also needs the PCRE and zlib development
headers, and `test.sh` uses `wget` and the `openssl` command. mruby is built with
`rake`: if it is not on `PATH` because Ruby is managed by a version manager
(rbenv, asdf, ...), put that Ruby's `bin` directory on `PATH` first.

```sh
sh test.sh                          # full run: fetch nginx (version in ./nginx_version), configure, build, test
ONLY_BUILD_NGX_MRUBY=1 sh test.sh   # fast loop: skip fetch/configure, rebuild changed sources, re-run tests
BUILD_DYNAMIC_MODULE=1 sh test.sh   # build as a dynamic module (uses build_dynamic/ instead of build/)
NGINX_RUNNER=valgrind sh test.sh   # run nginx under valgrind (NGINX_HEATTIME, 60 s by default, bounds each wait of test.sh for ports and for nginx)
sh test/soak/run.sh                 # memory soak test (Linux; own build in build_soak/, ports 12360-12362)
sh test/perf/compare.sh BASE_DIR    # callgrind Ir per request, BASE_DIR vs this checkout (Linux, valgrind; builds in build_perf/, ports 12370-12372)
```

- Run these before a PR is marked ready: CI is the final check in a clean
  environment, not the place where a change is first tested (see "Branches
  and pull requests"). Run the local commands of the checks that the
  change touches: the suite when `test/ci/changes.sh` gives `build`
  `standard` or `full`, `sh test/ci/changes_test.sh` for
  `test/ci/`, the site's checks for `site/` and `docs/` ("The site"
  below), zizmor for `.github/` ("Static analysis of the workflows" in
  `docs/test/README.md`), and `sh test/soak/run.sh` or `sh
  test/perf/compare.sh` where the change affects what they measure.
  `docs/test/README.md` describes each of them.
- The first full run takes a few minutes (it clones the third-party mrbgems from
  GitHub at the commits in `build_config.rb.lock`, and builds mruby and nginx).
  After that, use `ONLY_BUILD_NGX_MRUBY=1`.
- `build_config.rb.lock` pins the third-party mrbgems by commit (see "Gem
  commits" in `docs/install/README.md`). rake writes it again at the end of every
  build; on the default gem list the content does not change. rake does not
  fetch into an existing clone: after any change of the lock, including one
  that a pull or a merge (for example of `next` into your branch) brings in,
  run `rm -rf mruby/build` before the next run. Otherwise `sh test.sh` and
  `ONLY_BUILD_NGX_MRUBY=1 sh test.sh` stop with `fatal: reference is not a
  tree` when a clone does not have the new commit. `make clean_mruby` stops
  with the same error, because it runs rake, which checks the clones out at
  the commits of the lock, before it removes anything. To move a gem to
  another commit: change its `commit:` in each section of the lock that has
  an entry for it (or delete those entries to take the head of its branch),
  `rm -rf mruby/build`, run a full `sh test.sh`, and commit the lock that
  rake wrote.
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
- `test.sh` listens on these ports by default (18080-18090, 18101-18103, 18110-18140,
  18143-18144, 18147-18170, 18176-18181, 18199, 12345-12359, 12363-12366,
  12368-12369, 12372-12379, 12390-12391; 18116 and 12357 belong to the second nginx that
  `test/t/cases/_second_instance.rb` starts, 18180, 18181 and 12379 to the
  nginx with several workers that `test/t/cases/_workers.rb` starts, 18158 to the nginx that
  `test/t/cases/config_hooks.rb` starts, 12372 and 12373 to the mock LLM
  upstream that `test/t/cases/_agent_proxy_client.rb` starts, 12399 to a test
  in `test/t/ngx_mruby.rb`). `TEST_SH_PORT_OFFSET=N` moves every port of the
  suite by N (from -2345 to 47336): two checkouts can run `test.sh` at the
  same time on one machine with offsets 120 or more apart (the other limits
  are under "Ports" in `docs/test/README.md`); with the same ports, the
  second run fails when it finds them taken. A new test writes each port as
  five digits within 12345-12399 or 18080-18199, and runs a CRuby helper
  through `suite_path` (see "Ports" in `docs/test/README.md`). `test.sh` stops only the
  nginx that it started, by its pid, and at the start the nginx that an
  earlier run in the same build directory left running (the pid in
  `logs/nginx.pid`); it never stops a process by its name. See "Stopping
  nginx" in `docs/test/README.md`.
- `test/soak/run.sh` builds its own nginx in `build_soak/` (it does not touch the
  `test.sh` build), listens on 12360 and 12361, and starts the mock LLM upstream
  (`test/soak/mock_llm.rb`) on 12362 for the `agent_*` scenarios
  (`SOAK_PORT_BASE` moves all three). It stops only the processes it started,
  and its ports are not those of `test.sh`. The soak reads `/proc`: on macOS, run
  it in a Linux container. See "Soak test for memory" in `docs/test/README.md`.
  A `.c` file in `src/http/` or `src/stream/` that calls `mrb_gc_register` or
  `mrb_gc_unregister` must include `ngx_http_mruby_debug.h`, which counts the
  calls for `Nginx::Debug.stats`; `run.sh` checks this before it builds.
- `test/perf/compare.sh` builds the base and the head in `build_perf/` (it does not
  touch the `test.sh` build), listens on 12370 and 12371, and starts the mock LLM
  upstream on 12372 for the agent proxy scenarios (`PERF_PORT_BASE` moves all
  three). It stops only the processes it started. `test.sh` uses 12372 for its
  own mock too, so do not run both at the same time on one machine. It needs valgrind's `callgrind_control` and
  `vgdb`: on macOS, run it in a Linux container. See "Performance comparison with
  callgrind" in `docs/test/README.md`.

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

### The site

CI scope and independent lanes are defined in
[Browser scope and parallel lanes](docs/test/README.md#browser-scope-and-parallel-lanes).
Static checks remain complete. Only a verified local-document edit in a pull
request narrows the 3.x browser pages; a push or dispatch, which deploys, and
shared or unknown changes remain full, and the independently changing v2 input
retains its checks. Same-run artifact identity and `site-ok`
are required before publication. Standalone script defaults remain full. Do not
use targeted evidence for a shared layout change or replace missing evidence
with a successful skip.

- The layout and wrapping checks of the site measure two patterns only, PC
  at full screen (1440px, Chromium) and iPhone Safari (402px, WebKit);
  no other widths, browsers or font combinations are added to the checks.
  The owner's words (2026-11-01):
  「pcビューは決められた幅の表示領域で全画面とかでもちゃんと表示されてたらいいし、モバイルはiPhone17とかのサファリの幅で十分。勝手に色々なパターンを用意して複雑にするな」.
  The patterns are in `site/scripts/lib/patterns.mjs`.
  The iPhone width is 402px (Safari on an iPhone 17 Pro). At 640px and
  below, the root font size grows with the screen so that the text column
  keeps the 21.875em it has at 390px (4.4 of `docs/proposals/site.md`).


The site uses Astro with the repository's route, schema, layout and components.
There is no shell-selection environment flag or Starlight runtime dependency.
Migration parity compares a build of the recorded base commit with the head
build, using the same 2.x input. Record both commits and the input in the PR;
static HTML parity does not replace browser, layout or interaction evidence.

`site/` (on `next`) builds the ngx.mruby.org site from `docs/` with Astro
and its own components (`docs/proposals/site.md`). It needs git with the whole
history and Node.js at the version in `site/.node-version` (22.23.3), with
its npm. The proposal says "Node 22.12 or later"; the packages of
`site/package-lock.json` need 22.22.0 or later. Install Node.js for your
user (nvm, fnm, volta, or the archive from nodejs.org), not system-wide.

```sh
cd site
npm ci --ignore-scripts   # the exact versions of package-lock.json, without install scripts
npm run build             # scripts/sync-docs.mjs writes docs/ into src/content/docs/, then astro build writes dist/
npm run build:v2 -- --tree DIR   # the 2.x pages under dist/v2/ from docs/ of DIR, a work tree of master (below)
npm run test              # the generator on its fixtures
npm run check             # the checks of the built site that need no browser (below; after build:v2)
npm run check:v2          # the checks of step 6 on the 2.x pages, with the search in Chromium (below)
npm run check:browser     # the checks in Chromium and WebKit (below)
npm run screenshots       # the screenshots of step 3 (below)
npm run preview           # serves dist/ at http://localhost:4321/
```

- Machine-readable documentation: the same generator also writes complete
  Markdown bodies to ignored `generated/markdown/`. `scripts/export-docs.mjs`
  adds version, channel, language, revision, source hash and canonical URLs
  after the HTML build, under `dist/markdown/` and `dist/docs-index.json`.
  `build:v2` makes independent `/v2/` outputs and retains its canonical bodies
  in ignored `generated/markdown-v2/` for verification. Missing Japanese
  translations link to English Markdown. A release line is not a release tag.
  A source must exist at HEAD before export; a modified source is marked
  `source_at_revision: false` with no source URL, and untracked files count
  towards the working tree's dirty state. Review previews accordingly.
  Display-only word breaks and diagram SVG are omitted from Markdown;
  diagram labels, development status, source ranges, commit and date remain.
  Literal code and tested samples stay intact. `npm run check` compares every
  complete exported body with the generator's canonical body, metadata and
  source hashes, and checks per-version/fallback links. The generator tests
  verify identifier search, literal code and diagram provenance. Do not
  maintain separate agent prose or infer missing API contracts from 2.x.
- Pages: `scripts/sync-docs.mjs` writes the pages of `docs/` into
  `src/content/docs/` (gitignored), `docs/README.md` as `/docs/`; the home
  pages `/` and `/ja/` are the committed `src/content/docs/index.mdx` and
  `ja/index.mdx`. A page takes the route of its path under `docs/`, except
  the pages of `SOURCE_ROUTES` in `scripts/lib/site.mjs`, which sort the
  existing files into the four kinds of page of 3.1 of the proposal
  (`docs/install/README.md` is `/guides/install/`,
  `docs/directives/README.md` `/reference/directives/`, and so on) and add
  `examples/start/README.md` as `/start/`, `SECURITY.md` as `/security/`
  and `CONTRIBUTING.md` as `/contributing/`; a Japanese page takes the route
  of its English page under `/ja/`. The Japanese source of `docs/<path>.md`
  is `docs/ja/<path>.md` (of a release file, `docs/releases/<version>.ja.md`),
  and that of a page from outside `docs/` is `docs/ja/<route>/README.md`
  (`docs/ja/start/README.md`, `docs/ja/security/README.md`,
  `docs/ja/contributing/README.md`). Every page written by hand has one
  (Q2 of the proposal), except the generated reference of
  `GENERATED_REFERENCE` in `scripts/lib/site.mjs` (the directives and the
  Ruby classes and methods), which `/ja/` shows in English with a notice
  that says why (`src/components/FallbackContentNotice.astro`), and the pages
  of `NOT_TRANSLATED_YET` there, which step 5 empties. A link from a
  Japanese page to an English page goes to that page under `/ja/`; to link
  to the English page itself, write its absolute URL
  (`https://ngx.mruby.org/<route>/`), which `check-built-links.mjs` checks
  as an internal link. A
  Japanese page keeps the code blocks of its English page, and its h2 have
  `<wbr>` at their phrase boundaries (4.4 of the proposal). The sidebar of `astro.config.mjs` has
  the links Overview (`/docs/`) and Start, then the groups Guides,
  Reference, Concepts, Releases, Security and Contributing, each made from the
  folder of its routes and ordered by `SIDEBAR_ORDER` of
  `scripts/lib/site.mjs`. The header, the menu, the footer and the language link
  of 4.10 are component overrides in `src/components/` (`Header`,
  `PageFrame`, `Footer`, `MobileMenuFooter`, and `FallbackContentNotice`
  for the notice above an English page under `/ja/`), with their links in
  `src/site-nav.mjs`.
- The 2.x pages (3.4 and step 6 of the proposal). `/v2/` holds the
  documentation of 2.x, built from `docs/` of `master` (`v2.x` after the
  promotion). `node scripts/build-v2.mjs --tree DIR`, after `npm run
  build`, runs the same build in a copy of `site/` (`generated/v2-site/`)
  with `NGX_MRUBY_SITE_VERSION=2` and `NGX_MRUBY_SITE_REPO=DIR`, which
  `scripts/lib/site.mjs` reads: the pages of `DIR/docs/` (and `SECURITY.md`
  and `CONTRIBUTING.md`) at the routes of `SOURCE_ROUTES` under `/v2/`,
  `docs/README.md` as `/v2/`, links to other files going to GitHub at
  `master`, the sidebar of the 2.x pages in `astro.config.mjs`, and the
  2.x banner of 3.4 on every page (`src/components/Banner.astro`). It
  writes them into `dist/v2/`, with their own search index in
  `dist/v2/pagefind/` (the 3.x index of `dist/pagefind/` stays without
  them), and their list into `generated/pages-v2.json`. DIR needs the whole
  history, like the 3.x build; locally, a worktree of `origin/master` does.
  The version link of the header leads from 3.x pages to `/v2/` and from
  2.x pages to `/docs/`. The checks of steps 1 to 5 read the 3.x pages
  (`htmlFiles()` leaves `dist/v2/` out), except `check-built-links.mjs`,
  which reads the 2.x pages too, so `npm run check` needs the 2.x build
  first, and `check-css.mjs`, which walks the HTML of `dist/v2/` as well
  but reads the stylesheets of `dist/_astro/` only (those of
  `dist/v2/_astro/` come from the same sources).
- Samples and diagrams (3.5 of the proposal). A fenced block with the
  language `sample` in `docs/` names a case of `test/t/cases/` and its
  configuration, script, request and response files; the generator writes
  them as code blocks with a line that names the case and the date of the
  last commit to them (`scripts/lib/samples.mjs`; the home pages use
  `src/components/Sample.astro`). A block may name several scripts, and,
  for a case whose client prints values instead of whole responses, files
  of the compared values (`compared:`) in place of the request and the
  response. `label: development` in a sample or diagram block marks a
  feature of v3 before v3.0.0 with the label "Development version, New in
  3.0". A fenced block with the language
  `diagram` names a drawing `src/diagrams/<name>.svg` (and
  `<name>.narrow.svg`), its caption, the source lines it describes and
  their commit (`at:`), and the labels as `key: text`; the generator
  writes a figure with the drawings inlined and the labels as HTML
  (`scripts/lib/diagrams.mjs`), placed by `src/diagrams/<name>.css`. The
  build stops on a sample whose file or case is missing and on a diagram
  block whose keys differ from those of its drawing.
- After `astro build`, `npm run build` runs `scripts/mark-num-cells.mjs`,
  which gives the table cells that hold only numbers the class `num`
  (monospace, 4.3 item 2), because the Markdown processor of Astro 7 runs
  no rehype plugin without another package. The generator puts `<wbr>`
  into long names in the text of a page outside code and outside URLs
  (`breakName` in `scripts/sync-docs.mjs`): after `::`, before `#`, `.`
  and `(`, and after an underscore that four or more characters of the
  name follow, so that a heading or list item breaks there on a narrow
  screen.
- `npm run build` needs no network after `npm ci`. It stops in a shallow
  clone (the last-updated date of a page is the date of the last commit
  to its source), on a file of `docs/` without a heading or whose first
  heading, the page title, contains HTML, and on a relative link to a path
  that git does not track.
- The design comes from `site/src/styles/tokens.css` (step 2 of the
  proposal, section 4): every color of the site is a token there, and no
  other file under `site/src/` writes a hex color. `src/styles/site.css`
  applies the tokens to the site's pages, `ec.config.mjs` sets Expressive
  Code's themes (written from `tokens.css` by `scripts/lib/code-themes.mjs`)
  and frames, and `scripts/lib/postcss-theme-colors.mjs` removes
  Pagefind's own color variables from its stylesheet at
  build time, so that the built CSS holds only the tokens' colors.
- Before starting or resuming site work, human, Claude and Codex contributors
  read [Site design acceptance](docs/proposals/site.md#site-design-acceptance),
  then its linked layout rules. This applies to content and documentation
  entry pages as well as CSS. Record the intended reader task and its source
  evidence before editing. Independent review must reconstruct the use case
  and next action from actual desktop/mobile pages without the author's pitch;
  a checklist score or passing browser test does not establish comprehension.
  Keep the read paths and the review's answers in the PR checkpoint so a new
  session can repeat the procedure without private memory or installed skills.
- The checks of the proposal (section 6) are scripts under `site/scripts/`
  that exit 1 on a failure. `npm run check` runs the ten that need no
  browser; the first four take `--dist`, `--repo` and `--manifest` to run
  on a copy, `check-css.mjs` takes `--dist`, `check-home.mjs` `--dist` and
  `--repo`, and `check-diagrams.mjs` `--repo`:
  - `sh site/scripts/check-fresh-clone.sh [--keep DIR] [REV]`: a clone of
    the commit (default `HEAD`) builds with `npm ci --ignore-scripts` and
    `npm run build`;
  - `node scripts/check-built-links.mjs`: every internal link of the built
    HTML resolves, and no link attribute is empty or broken;
  - `node scripts/check-pages.mjs`: every page has a title and the
    last-updated date of its source;
  - `node scripts/check-japanese.mjs`: every English page written by hand
    has a Japanese page, outside `GENERATED_REFERENCE` and
    `NOT_TRANSLATED_YET`, whose pages under `/ja/` show their notice; every
    page has `lang` and the `hreflang` links en, ja and x-default to the
    absolute URLs of both languages; the pages from `docs/ja/` are under
    `/ja/` with `lang="ja"`, and the `<wbr>` of their h2 are elements of
    the built h2; no space between Japanese and Latin text in the Japanese
    sources outside code and URLs; a Japanese page has the code blocks of
    its English page; no `<title>`, h1, sidebar or table-of-contents entry
    or heading `id` under `/ja/` contains `wbr`; and every diagram under
    `/ja/` shows the labels of the Japanese source;
  - `node scripts/check-no-js.mjs`: the text of each source is in the HTML
    without running scripts;
  - `node scripts/check-css.mjs`: the built CSS has no hex color outside
    the declarations of `tokens.css` and Expressive Code's stylesheet, no
    `text-wrap: pretty` or `balance`, `keep-all` only on the h2 of Japanese
    pages and diagram labels, transitions only of the properties of 4.8
    and for 200 ms or less, no terminal frame and no font from another
    host, and `site/src/` no hex color outside `tokens.css`;
  - `node scripts/check-home.mjs`: the home pages show the files that the
    example's case compares, with the case, the date and the commit, and
    no benchmark image or performance figure (Q8);
  - `node scripts/check-samples.mjs [--repo DIR] [--dist DIR]`: every
    sample block of the pages names a case of `test/t/cases/` and files
    that exist, every use case of `docs/use_case/README.md` has a sample,
    a link to a page with one, or a paragraph "**Untested.**" with the
    reason (3.5), and every sample and diagram block of the agent proxy
    page carries `label: development`, shown once for each in the built
    page;
  - `node scripts/check-reference.mjs [--repo DIR]`: every directive of
    the `ngx_command_t` tables of `src/` has a heading in
    `docs/directives/README.md`, `mruby_output_filter` appears in `docs/`
    only in removal notes, and the list "Default mrbgems" of
    `docs/reference/build.md` equals the `conf.gem` lines of the host
    build of `build_config.rb` that are not comments and have no
    condition;
  - `node scripts/check-v2.mjs [--dist DIR] [--manifest FILE]
    [--no-browser]` (`npm run check:v2`, not in `npm run check`, because
    it opens Chromium): every page of `generated/pages-v2.json` is built
    under `/v2/`; every 2.x page carries the 2.x banner (`data-banner="v2"`)
    in its language with its link to the 3.x documentation, and no 3.x page
    does; the version links lead from 3.x to `/v2/` and from 2.x to
    `/docs/`, and the language links of the 2.x pages stay under `/v2/`;
    and the search of a 3.x and of a 2.x page, in both languages, shows
    results of its own version only and loads only its own index;
  - `node scripts/check-diagrams.mjs`: the drawings hold lines and boxes
    only (no `<text>`, no color outside the tokens' classes), the source
    files and lines of each diagram exist at its commit, and the diagrams
    whose lines changed since then are listed (also in the run summary);
  - `node scripts/check-deploy.mjs [--dist DIR]`: the files of
    `VERBATIM_FILES` in `scripts/lib/site.mjs`, the Google verification
    file `googleba3435e4002729b6.html` that Q5 of the proposal keeps from
    the old site, are in the built site with the 54 bytes and the SHA-256
    of the `gh-pages` copy and equal to their copy in `public/`, no HTML
    or JavaScript file names Google Analytics, Google Tag Manager or
    `gtag` (Q6), and no `<script src>` of an HTML file points at another
    host. It reads names and `src` attributes only: a loader that builds a
    host name at run time, or an `import` from another host inside a
    script, passes it. The checks of pages leave those files out
    (`htmlFiles`).
  `node scripts/check-ruby-blocks.mjs --mrbc PATH` (not in `npm run
  check`, because it needs mrbc) compiles every Ruby block of the pages
  and every script of their samples with the mrbc of the bundled mruby,
  built alone in about ten seconds with `cd mruby &&
  MRUBY_CONFIG=build_config/mrbc.rb MRUBY_BUILD_DIR=DIR rake`
  (`DIR/mrbc/bin/mrbc`); a block that shows a syntax error on purpose is
  marked ```` ```ruby syntax-error ```` and must not compile. `site.yml`
  runs both.
  `npm run check:browser` runs five on `site/dist/` (`--dist`; the first
  three also `--engine chromium|webkit`). Validate every Japanese page with
  the served Noto Sans JP; supplement this only with a Hiragino Sans check
  of the Japanese home page where that face is available. This is a validation
  scope, not a runtime font change: the existing stack still prefers Hiragino
  Sans where installed and otherwise uses Noto Sans JP. Do not add further
  browser/font combinations:
  - `node scripts/check-styles.mjs` (`npm run check:styles`;
    `--pages /,/ja/` limits a local run to known pages, while CI keeps the
    default complete page set): computed
    styles in the two patterns, 1440 by 900 px in Chromium and 402 by
    664 px in WebKit: font sizes of the scale of each language, token colors (code
    blocks and the colors of highlighted spans included), monospace only
    for code and numbers, no shadow, gradient or backdrop filter (also
    with the search dialog open, while its results load and after, and
    with the menu open), margins, paddings, gaps and radii from the sets
    of 4.5, durations of 4.8, at most 90 characters per English line at
    1440 px, no horizontal scroll, gutters of 20 px or more at 402 px, the
    line count of the home page heading, the right edge of Japanese text
    at 402 px and no `text-wrap` pretty or balance on
    English text, no paragraph, list item, caption, table cell or heading
    whose last line holds one or two characters, in both patterns, the
    diagrams (`role="img"` and an `aria-label`, drawings
    hidden from screen readers, labels of 14 px or more inside their
    place, the drawing and its labels within one screen), and the theme
    without JavaScript;
  - `node scripts/check-japanese-lines.mjs` (`npm run
    check:japanese-lines`; `--pages /ja/a/,/ja/b/` for some pages only):
    every page under `/ja/` from a Japanese source but the home page, in
    the two patterns, 1440 by 900 px in Chromium and 402 by 664 px in
    WebKit: at most 40 Japanese characters on a line of body text and a
    line height of 1.75 to 2.0 at 1440 px, the page title on one line at
    402 px, the right edge of Japanese blocks at 402 px (2 em; an h2 at
    most two lines and 6 em), no last line of one or two characters in
    either pattern, and diagram labels of 14 px or more inside their place
    in both, and the notice above an English
    page under `/ja/` on one page of each kind; on the release notes of
    `NOTES_ONLY` in the script, failures are notes until step 5 rewrites
    them;
  - `node scripts/check-focus.mjs`: tabbing through each page in Chromium
    and WebKit (Option-Tab there), every focused element has a focus ring
    and the fixed header does not cover it;
  - `node scripts/check-language-links.mjs`: every language link leads to
    the same path in the other language and answers 200, and `/` with
    `Accept-Language: ja` answers in English without a redirect;
  - `node scripts/check-lighthouse.mjs`: Lighthouse's accessibility
    category with no failed audit on three page types in both languages
    (`lighthouse` of `package-lock.json`, in Playwright's Chromium).
  The others:
  - `python3 scripts/contrast.py [--tokens FILE] [--markdown]` (`npm run
    check:contrast`): the contrast of palette A of 4.6 and of the code
    colors in both themes, read from `tokens.css`;
  - `sh scripts/check-offline-build.sh [SITE_DIR]` (`npm run
    check:offline`): `npm run build` succeeds with network access blocked
    (`sudo unshare --net` on Linux, `sandbox-exec` on macOS), after a probe
    shows that the sandbox refuses a request;
- `npm run screenshots` (`node scripts/screenshots.mjs [--dist DIR] [--out
  DIR]`) writes the screenshots of step 3 to `build-screenshots/`: the
  home page, the page of the request phases diagram and a reference page,
  in both languages, light and dark, in the two configured patterns, 1440 by 900 px in Chromium and
  402 by 664 px in WebKit, and in `review/` the definition and the
  diagram that the owner reviews, with an `index.md`. No image is
  committed or attached to a pull request (4.12). The browser checks and
  the screenshots need Chromium and WebKit for the `playwright` of
  `package-lock.json`: `npx playwright install chromium webkit` (locally,
  with `PLAYWRIGHT_BROWSERS_PATH` set to a directory under `.claude/tmp/`
  to keep them out of your home directory).
- `node scripts/test-sync-docs.mjs` (`npm run test`) runs the generator
  on fixtures in temporary repositories: links in raw HTML inside
  blockquotes and list items, an attribute value that stops the build, a
  sample and a diagram, and the samples and diagram blocks that stop it.
- `.github/workflows/site.yml` runs the checks and `npm test` (generator
  fixtures and release-state classification), plus complete Markdown export
  and metadata checks after both version builds, on
  pull requests to `next` that touch `site/` or `docs/`, on every push
  to `next` (a push that removes a file that `docs/` links to fails
  there) and on `workflow_dispatch`, and uploads `site/dist/` (with
  `dist/v2/`) as the artifact `site`, the
  screenshots as the artifact `screenshots`, and `site/dist/` again with
  `actions/upload-pages-artifact` as the artifact `github-pages`, a step
  that runs only when every step before it passed.
  It checks out `master` with its whole history and builds `/v2/` from
  it.
- Deployment (5.3 of the proposal). The job `deploy` of `site.yml` runs
  after the job `build` passed, on a push to `next` and on a
  `workflow_dispatch` on `next`, in this repository only (not in forks),
  never for a pull request: it reads the
  Pages settings with `actions/configure-pages`, stops unless they give
  the origin `https://ngx.mruby.org`, and publishes the artifact
  `github-pages` with `actions/deploy-pages` into the environment
  `github-pages`, with only `pages: write` and `id-token: write`, one
  deployment at a time. The repository settings are the owner's, made
  once, in this order:
  1. Settings, Pages, "Build and deployment": "Source" changed from
     "Deploy from a branch" to "GitHub Actions", with the custom domain
     `ngx.mruby.org` kept and "Enforce HTTPS" checked. `gh-pages` stays as
     history.
  2. Settings, Environments, `github-pages`: "Deployment branches" set to
     "Selected branches and tags", with one rule added by "Add deployment
     branch or tag rule", "Ref type" "Branch" and the name `next`
     (`master` after the promotion), in place of any rule that setting 1
     added.

  Without setting 2, a workflow pushed on any branch could publish the
  site. After the first deployment, and after a deployment that should
  change what the site serves, a session builds the deployed commit and
  runs `node scripts/check-live.mjs` (`npm run check:live`; not in CI):
  `https://ngx.mruby.org/` answers 200 with the built `index.html`,
  `http://` redirects to `https://`, the verification file answers 200
  with its 54 bytes, `gh api` reads back the environment's branch policies
  (only `next`) and that the latest deployment came from `next`, and
  Lighthouse runs on the live home page with no failed accessibility
  audit (`--no-gh` and `--no-lighthouse` leave those out).
- Two workflows on `master` serve the 2.x pages (5.3 of the proposal).
  `site-v2.yml` runs on every pull request to `master` (no path filter:
  the 2.x pages link to files anywhere in the repository): it builds the
  site from `site/` of `next`, with the 3.x pages of `next` and
  the 2.x pages from the pull request, and runs `check_links.py` on the
  sources of the 2.x pages, `check-built-links.mjs` and `check-v2.mjs`, so
  a pull request that breaks a `/v2/` link fails there. `site-dispatch.yml`
  runs on every push to `master` and starts `site.yml` on `next` with
  `gh workflow run site.yml --ref next` and the job's `GITHUB_TOKEN`
  (`actions: write`); it fails when it cannot name the run that the
  dispatch started. A change to `site/` that breaks `/v2/` fails
  `site.yml` on its pull request to `next`, which builds `/v2/` from
  `master`.
- `site/package.json` and `site/package-lock.json` pin exact versions:
  change them with `npm install --save-exact <package>@<version>` and
  commit both. Nothing that the build generates is committed:
  `site/.gitignore` ignores it, and `test/forbidden_paths.txt` fails a
  forced add of `site/dist/`, `site/build-screenshots/`,
  `site/generated/` or `site/.astro/`.
- `python3 site/scripts/check_links.py REPO_ROOT FILE...` checks the
  relative links and anchors of Markdown files. `site.yml` runs it on every
  Markdown file that git tracks outside `mruby/` and `dependence/`
  (`git ls-files -z -- '*.md' ':!:mruby/' ':!:dependence/' | xargs -0
  python3 site/scripts/check_links.py .`).
- `python3 examples/check_example.py [--files-only] examples/<use>` runs
  the commands of the example's `README.md` in order and compares their
  output with what the README states, and compares each code block titled
  with a file name (`title="nginx.conf"`) with that file of the example.
  It needs Docker with Compose; `--files-only` runs no command. The
  `examples` workflow runs it on pull requests to `next` and pushes to
  `next` that change `examples/`, the workflow or an input of the build
  (`src/`, `mrbgems/`, `mruby/`, `dependence/`, `build.sh` and the files it
  reads).

## Writing tests

- Prefer a fragment and a case file of their own: a `server {}` in
  `test/conf/conf.d/<name>.conf` (stream: `test/conf/conf.d/stream/`) on a
  port of its own (HTTP 18110 to 18199, stream 12353 to 12399), scripts in
  `test/html/`, and assertions in `test/t/cases/<name>.rb` (see
  `docs/test/README.md`). Edit `test/conf/nginx.conf` and
  `test/t/ngx_mruby.rb` only for tests that need the main server.
- The test nginx of `test.sh` is a single process. A test that needs a
  master process with several workers, or a reload, adds a mode to
  `test/t/cases/_workers.rb` with its configuration in
  `test/conf/workers/<mode>.conf`, and asserts in a case file on what the
  helper prints ("Several workers and reloads" in `docs/test/README.md`);
  the other tests keep the single process.
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
  The Prism sources under `mruby/mrbgems/mruby-compiler/lib/prism`, which
  mruby's tree has as a submodule, are vendored only with
  `./vendor-mruby-prism`, right after the merge commit of an mruby update.
- Edit generated files: `config`, `Makefile`, `config.status`, `config.log`
  (outputs of `./configure`; edit `config.in` / `Makefile.in` instead).
  `configure` is autoconf output: edit `configure.in`, regenerate with `autoconf`
  and commit both.
- Run `killall nginx` or `pkill nginx`: other sessions may own those
  processes. Stop only processes you started, by their pid, as `test.sh` does.
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

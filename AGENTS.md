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
  - an operator's script blocks its worker when it uses mruby-sleep,
    mruby-socket or mruby-io, which the default build includes on both
    branches, or matsumotory/mruby-redis (a hiredis client) in a build that
    includes it. The rule is for ngx_mruby's own code, not for such scripts.
- Which changes are measured. A PR that changes an input of the measured
  binary is compared with its base in the callgrind lane ("Performance
  comparison with callgrind" in `docs/test/README.md` on `next`). The inputs
  are those that "In CI" in `docs/test/README.md` on `next` lists: `src/`,
  `mrbgems/`, `mruby/`, `dependence/`, `build_config.rb`, `configure`,
  `config.in`, `Makefile.in`, `build.sh`, `nginx_version`, and on `next` the
  gem lock `build_config.rb.lock`. On `next`, the `perf` job runs the
  comparison on such PRs. On `master`, which has no `perf` job yet, the
  author runs the commands below.
  - The author quotes the comparison in the PR body, under "Leak /
    performance impact" (see `.github/PULL_REQUEST_TEMPLATE.md`): the table
    with the header lines of `report.txt` above it (the line with `N`,
    `WARMUP` and the thresholds, and the lines on the gems; on `next`, in
    the job's log), and the commits compared. On `next`, these are the run
    of the `perf` job and the commits that its log prints (`base: ...,
    head: ...`). On `master`, they are the `origin/master` commit used as
    the base, the head commit, and the `next` commit that the lane came
    from. When the base branch gains a change to a measured input before
    the merge, the comparison is made and quoted again: on `next` by the CI
    run that condition 2 of "Review and merge" asks for, on `master` by the
    author with the commands below.
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
    comparison" in `docs/test/README.md` on `next`). Both runs are quoted,
    and the second replaces the first. In every other case, the `WARN` or
    `FAIL` goes to the owner without a second run.
  - A session does not merge a PR while the latest run of its `perf` job
    reports `FAIL` or `ERROR`, except for a `FAIL` that the owner accepted
    on the PR. This holds although `ci-ok` does not need the job yet, and
    although "In CI" in `docs/test/README.md` on `next` calls the job
    advisory; a follow-up PR to `next` aligns that text. The plan (Pillar E
    of `docs/proposals/v3-plan.md` on `next`) adds the job to the `needs` of
    `ci-ok` once it has run on code changes without false alarms; from then
    on a `FAIL` or an `ERROR` also fails `ci-ok`. On `master`, which has no
    `perf` job, the reviewer checks the author's table by the same rules.
- The `master` commands. Until the lane is ported to `master`, a `master`
  change is measured with the lane of `next` (`test/perf/`, the scenarios in
  `test/soak/` and `test/build_release.sh`), added to a copy of the tree
  outside the checkout. The base is the tip of `origin/master`, so update
  the branch to it first: a branch that is behind shows the newer `master`
  commits as reverse differences. From a checkout of the PR's head commit:

  ```sh
  git fetch origin master next
  git merge-base --is-ancestor origin/master HEAD   # exits 1 when the branch is behind: update it first
  D=$HOME/ngx_mruby-perf   # any directory outside the checkout
  rm -rf "$D" && mkdir -p "$D/base" "$D/head"
  git archive origin/master | tar -x -C "$D/base"
  git archive HEAD | tar -x -C "$D/head"
  git archive origin/next test/perf test/soak test/build_release.sh | tar -x -C "$D/head"
  cd "$D/head" && sh test/perf/compare.sh "$D/base"
  ```

  The last line needs Linux and valgrind. On macOS, run this line in its
  place; it runs `compare.sh` in a Linux container with `$D` mounted at the
  same path:

  ```sh
  docker run --rm -v "$D:$D" -w "$D/head" -e D="$D" ubuntu:22.04 sh -c 'apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y build-essential rake ruby bison git gperf wget ca-certificates zlib1g-dev libpcre3-dev libssl-dev valgrind >/dev/null && sh test/perf/compare.sh "$D/base"'
  ```

  The report is in `$D/head/build_perf/report.txt`.
- Before a tag. Each PR is compared only with its base, so changes that
  stay below `WARN` can add up. The check PR of "Before the tag" (see
  `docs/releases/README.md`) therefore also compares its head with the tag
  where the range of the check starts. It uses the commands above with the
  base made from that tag (`git archive <tag> | tar -x -C "$D/base"`); on
  `next`, the up-to-date check is against `origin/next`, and the line that
  adds the lane is left out. It quotes the table as above, and a `WARN` or
  `FAIL` there goes to the owner.
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
- Agents open PRs and fill in every section of the PR template. Open them as
  drafts while CI and the review below are running.
- A PR that changes behavior a configuration, script or build can observe (a
  bug fix, a raised build requirement and a change of the bundled mruby or
  default mrbgems included; see `docs/releases/README.md` for what counts)
  adds its entry under "Behavior changes: read before upgrading" in
  `docs/releases/<version>.md`, in the same PR: before, now, what is affected,
  what to do. Users have built on the old behavior, so the new release must
  warn them.
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
on real responses, not only on "not 500"; the CI result on the head commit;
when an input of the measured binary changed, the performance comparison
quoted in the PR body and the numbers that "Design principles" asks the
reviewer to write;
compatibility notes in the PR body match the diff; a change of behavior that a
configuration, script or build can observe has an entry under "Behavior
changes: read before upgrading" in `docs/releases/<version>.md`, and
`docs/directives/`, `docs/class_and_method/` or `docs/install/` describe the
new behavior; a PR that moves the pin of one of the owner's gems links the
gem's PR, which has its review and the suite results (see "Other
repositories"); nothing in the diff, the
commit messages or the PR text discloses an unpublished vulnerability or a
secret; and `docs/` is updated when a directive, Ruby method, build option or
the test harness changes. The reviewer posts the findings as a PR comment,
split into "must fix" (blocks the merge) and "should fix". A behavior change
without that entry is a "must fix"; a missing "New features", "Fixes" or
"Build and test changes" entry is a "should fix". The author fixes
every "must fix" and asks for a re-review of those items only.

The session that owns the PR merges it, with a merge commit, when all of
these hold:

1. The base branch follows the branch table above.
2. Every CI check on the head commit passed (`ci-ok` once it is required),
   on a run whose merge ref includes the current base. When the base moved
   after the last run, update the branch and let CI run again. A run made
   green by skipping or disabling tests does not count.
3. The change is inside the agreed scope, or is a bug fix with the two-commit
   evidence described under "Writing tests", or changes documentation only.
   In every case, a change of behavior that a configuration, script or build
   can observe has an entry under "Behavior changes: read before upgrading"
   in `docs/releases/<version>.md`, and the docs describe the new behavior.
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
  gem that the default build leaves out (matsumotory/mruby-redis, whose
  line is commented out on both branches) has no such line: enable it in
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
- It never holds unpublished vulnerabilities, advisory ids, names of private
  branches, files from outside the repository, or which release or work
  carries a security fix.
- There is no copy on `master`. From a checkout of `master`, read it with
  `git fetch origin next` and `git show origin/next:docs/HANDOFF.md`.

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
NGINX_RUNNER=valgrind NGINX_HEATTIME=10 sh test.sh   # run nginx under valgrind
```

- The first full run takes a few minutes (it clones mrbgems from GitHub and builds
  mruby and nginx). After that, use `ONLY_BUILD_NGX_MRUBY=1`.
- `ONLY_BUILD_NGX_MRUBY=1` reuses the last configure. Do a full run again after
  changing `BUILD_DYNAMIC_MODULE`, configure options or `nginx_version`.
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
  of `test.sh`: read the valgrind output (ERROR SUMMARY, leak summary) yourself.
- `test.sh` listens on fixed ports (18080-18088, 18101-18103, 18110-18131,
  12345-12358; 18116 and 12357 belong to the second nginx that
  `test/t/cases/_second_instance.rb` starts, 12399 to a test in
  `test/t/ngx_mruby.rb`) and
  kills every running `nginx` process before it starts. Run only one `test.sh` per
  machine at a time, and wait if an nginx you did not start is running.

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

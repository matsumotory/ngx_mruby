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
- `docs/`: user documentation (install, directives, classes and methods)

## Branches and pull requests

| Branch | Role | Who changes it |
|---|---|---|
| `master` | 2.x line until v3 is promoted, then 3.x | PRs only; merged as described in "Review and merge" |
| `next` | v3 development (pre-release tags `vX.Y.Z-alpha.N`/`-beta.N`/`-rc.N`) | PRs only; merged as described in "Review and merge" |
| `v2.x` | 2.x maintenance; an automatic mirror of `master` until v3 is promoted | Mirror automation; after promotion, PRs merged as described in "Review and merge" |

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
- Agents never create, move or delete tags, and never publish releases or
  security advisories. Those stay with the owner.

### Review and merge

Every PR gets a review by an agent (or person) that did not write it, with
this checklist: the change is inside the agreed scope (`docs/proposals/` on
`next`, an issue, or a fix with evidence); the code and tests are correct when read
against `src/` and, where it matters, the nginx source; a bug fix has its
regression test in a commit of its own before the fix commit, and the
reviewer has run the suite at both commits (failing, then passing, with
results matching what the author quoted); expectations assert
on real responses, not only on "not 500"; the CI result on the head commit;
compatibility notes in the PR body match the diff; nothing in the diff, the
commit messages or the PR text discloses an unpublished vulnerability or a
secret; and `docs/` is updated when a directive, Ruby method, build option or
the test harness changes. The reviewer posts the findings as a PR comment,
split into "must fix" (blocks the merge) and "should fix". The author fixes
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
4. The review above is recorded on the PR and no "must fix" item is open.
5. The scrub for secrets and unpublished vulnerability details passed.
6. The PR has no conflicts with its base.
7. The PR is marked ready for review (GitHub does not merge a draft).

If any condition cannot be met, the session says which one and why, and asks
the owner instead of merging.

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
sh test/soak/run.sh                 # memory soak test (Linux; own build in build_soak/, ports 12360-12362)
sh test/perf/compare.sh BASE_DIR    # callgrind Ir per request, BASE_DIR vs this checkout (Linux, valgrind; builds in build_perf/, ports 12370-12372)
```

- The first full run takes a few minutes (it clones mrbgems from GitHub and builds
  mruby and nginx). After that, use `ONLY_BUILD_NGX_MRUBY=1`.
- `ONLY_BUILD_NGX_MRUBY=1` reuses the last configure. Do a full run again after
  changing `BUILD_DYNAMIC_MODULE`, configure options or `nginx_version`.
- `NGX_MRUBY_AUTO_SSL=1` adds the auto-ssl mrbgem to the mruby build. Remove
  `mruby/build` before changing it: a full run builds the new gem list, but
  `libmruby.a` keeps the objects of a dropped gem and `mruby/build/host/LEGAL`
  is not written again (see `docs/install/README.md`).
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
- `test.sh` listens on fixed ports (18080-18088, 18101-18103, 18110-18132,
  12345-12358, 12372-12373; 18116 and 12357 belong to the second nginx that
  `test/t/cases/_second_instance.rb` starts, 12372 and 12373 to the mock LLM
  upstream that `test/t/cases/_agent_proxy_client.rb` starts, 12399 to a test
  in `test/t/ngx_mruby.rb`) and
  kills every running `nginx` process before it starts. Run only one `test.sh` per
  machine at a time, and wait if an nginx you did not start is running.
- `test/soak/run.sh` builds its own nginx in `build_soak/` (it does not touch the
  `test.sh` build), listens on 12360 and 12361, and starts the mock LLM upstream
  (`test/soak/mock_llm.rb`) on 12362 for the `agent_*` scenarios
  (`SOAK_PORT_BASE` moves all three). It stops only the processes it started.
  `test.sh` kills the soak's nginx too, so do not
  run both at the same time on one machine. The soak reads `/proc`: on macOS, run
  it in a Linux container. See "Soak test for memory" in `docs/test/README.md`.
  A `.c` file in `src/http/` or `src/stream/` that calls `mrb_gc_register` or
  `mrb_gc_unregister` must include `ngx_http_mruby_debug.h`, which counts the
  calls for `Nginx::Debug.stats`; `run.sh` checks this before it builds.
- `test/perf/compare.sh` builds the base and the head in `build_perf/` (it does not
  touch the `test.sh` build), listens on 12370 and 12371, and starts the mock LLM
  upstream on 12372 for the agent proxy scenarios (`PERF_PORT_BASE` moves all
  three). It stops only the processes it started. `test.sh` kills it too (and uses
  12372 for its own mock), so do not run
  both at the same time on one machine. It needs valgrind's `callgrind_control` and
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

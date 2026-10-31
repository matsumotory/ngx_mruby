ngx_mruby test uses mruby test.
ngx_mruby test is very earlier and experimental version. 

Welcome pull-request!
## Add test
##### Add location config to ``test/conf/nginx.conf``
```nginx
# Nginx.hello test
location /mruby {
    mruby_content_handler build/nginx/html/unified_hello.rb cache;
}
```
##### Add hook script into ``test/html/`` if you need the script for location config
```ruby
# test/htdocs/unified_hello.rb
if server_name == "NGINX"
  Server = Nginx
elsif server_name == "Apache"
  Server = Apache
end

Server::rputs "Hello #{Server::module_name}/#{Server::module_version} world!"
```
##### Add test code to ``test/t/ngx_mruby.rb``
```ruby
assert('ngx_mruby', 'location /mruby') do
  res = HttpRequest.new.get base + '/mruby'
  assert_equal 'Hello ngx_mruby/0.0.1 world!', res["body"]
end
```

The test client (the `test` build of `build_config.rb`) is built with
`NO_SSL`, so `HttpRequest` and `SimpleHttp` cannot send `https` requests.
For HTTPS, run `curl -k` with a URL from `base_ssl(port)`, or
`openssl s_client -connect localhost:<port>`, as the existing tests do (for
example `` `curl -s -k #{base_ssl(18082) + '/'}` `` in `test/t/ngx_mruby.rb`).

## Add a test as a fragment and a case file

Instead of editing `test/conf/nginx.conf` and `test/t/ngx_mruby.rb`, a test
can live in files of its own:

- `test/conf/conf.d/<name>.conf`: a fragment included at the end of the
  `http {}` block. It holds its own `server {}` on a port of its own (18110
  to 18199; 18116 is taken by the second nginx that
  `test/t/cases/_second_instance.rb` starts). Fragments for `stream {}` go
  to `test/conf/conf.d/stream/` (ports 12353 to 12399; 12357 is taken by the
  second nginx). Write each port as five digits in these ranges, so that
  `TEST_SH_PORT_OFFSET` moves it ("Ports" below).
- `test/t/cases/<name>.rb`: a test file run after `test/t/ngx_mruby.rb`,
  with `test/t/cases/_prelude.rb` prepended. The prelude defines `base`,
  `base_ssl`, `http_host`, `html_path`, `nginx_t` (runs `nginx -t` on a
  generated configuration), `tcp_client`, `second_instance` and
  `suite_path` (the path of a file of the suite in the copy that `test.sh`
  runs: run a CRuby helper as `` `ruby #{suite_path('test/t/cases/_x.rb')}` ``,
  see "Ports" below). It starts
  with `SimpleTest.new` and ends with `t.report`. Files whose name starts
  with `_` are helpers and are not run as cases; `_tcp_client.rb`,
  `_filter_connection_client.rb`, `_request_body_client.rb` and
  `_second_instance.rb` are CRuby scripts that the prelude helpers and the
  cases run with `ruby`, and `_wait_for_listen.rb` is the CRuby script that
  test.sh runs to wait for nginx (see "Waiting for nginx to listen" below).
  `_agent_proxy_client.rb` is a CRuby script (3.0 or
  later) that `agent_proxy.rb` runs itself: it loads `test/soak/mock_llm.rb`
  and `test/soak/http_client.rb`, runs the mock LLM upstream on 12372 and
  12373 while it sends its requests (see "Mock LLM upstream" below), and
  prints `key=value` lines.
- Hook scripts go to `test/html/` as before; the fragment refers to them as
  `build/nginx/html/<name>.rb`.

`test.sh` copies the fragments, from its copy of the suite ("Ports" below),
into the built nginx's `conf/conf.d/` with the same substitutions as
`nginx.conf`, and runs every case file in turn. A
failing case makes `test.sh` exit non-zero, like a failing assertion in
`test/t/ngx_mruby.rb`.

A case that starts nginx itself (`nginx_t`, `second_instance`) also runs in
the sanitizer cell of CI, where LeakSanitizer appends its report to the
output of a process that leaked and changes that process's exit status. Run
such a case once with the sanitizer build (see "Running the tests under
AddressSanitizer and UndefinedBehaviorSanitizer" below) before opening the
PR. `nginx_t` turns leak detection off for its `nginx -t` run, because
`nginx -t` returns without freeing the configuration it read, so every
allocation of nginx itself would be reported. The stream-only test at the end
of `test/t/ngx_mruby.rb` does the same for the `nginx -s quit` that stops the
nginx it started: that process returns from nginx's `main()` without freeing
the pool that `main()` creates first, and its report would go to the test
runner's `stderr.log`. `second_instance` returns the first sanitizer line of
the second nginx's `error.log` or `stderr.log` as `sanitizer`, and the cases
print the second nginx's `error.log` when the line is set.

## Required status check

`.github/workflows/test.yml` runs on pull requests to `master`, `next` and
`v*.x`, on pushes to those branches and to `v*` tags, and on "Run workflow".
Its `ci-ok` job is the status check that rulesets require: it fails unless
every job that it lists in `needs` passed. These are the `changes` job,
every job of the `build` matrix and the `files` job, and on `next` also the
`soak` job. On `next`, the job of the cell that runs nginx under valgrind
on every run of the matrix is one of them, so a valgrind error in that cell
fails `ci-ok` ([valgrind in CI](#valgrind-in-ci)). The `perf` job (see "In
CI" under "Performance comparison with callgrind") is not among them yet.

### Which jobs a run starts

The `changes` job decides whether a run needs the jobs that build and test
the module: the `build` matrix (16 cells, the cell under valgrind among them
on `next`, and the sanitizer cell), the `soak` job on `next` and the `perf`
job. The paths are filtered in that job, not with `on.paths` of the
workflow, so that the run, and with it `ci-ok`, exists for every pull
request. The `files` job and `ci-ok` run in every run.

| Run | The build, soak and perf jobs |
|---|---|
| Pull request that changes an input of the binary or the tests | Run (`perf` only when it changes what "In CI" of the performance comparison lists, or has the label `perf`) |
| Pull request whose files are all outside these inputs | Skipped |
| Push to `master` or `next` | Skipped |
| Push to a `v*.x` branch or a `v*` tag | Run (`perf` runs on pull requests only) |
| "Run workflow", the nightly run under valgrind included | Run (`perf` runs on pull requests only) |

For a pull request, the job lists the files that the merge commit
(`refs/pull/N/merge`) changes against its first parent, the base. The run
skips the build jobs when every one of them is one of these, which no job
of the run builds or tests with:

- `docs/`, `site/` and `examples/`: the `site` and `examples` workflows
  check them;
- `.github/workflows/` except `test.yml`, `.github/dependabot.yml`,
  `.github/zizmor.yml` and `.github/PULL_REQUEST_TEMPLATE.md`: the `zizmor`
  workflow checks the workflows;
- the Markdown files at the top (`README.md`, `AGENTS.md`, ...) and
  `AUTHORS`, `LEGAL` and `MITL`.

Every other file counts as an input, `test.yml`, `test/` and `test.sh`
included, so a file of a new kind runs the build until the list in the
`changes` job names it. The list is the variable `not_inputs` of that job;
a pull request that adds to it says why the files are not inputs.

A push to `master` or `next` runs only `changes`, `files` and `ci-ok`. Both
branches take changes only through pull requests, which merge only after a
run of `ci-ok` on a merge ref that includes the current base (condition 2
of "Review and merge" in [AGENTS.md](../../AGENTS.md)), so the push brings
the tree that the run of the pull request tested. The build of a branch tip
on its own comes from "Run workflow" (`gh workflow run test.yml --ref
next`), which also runs the nightly run under valgrind on `next`
([valgrind in CI](#valgrind-in-ci)). The other workflows decide on their
own when they run (`nginx-tests`, `examples`, `site`, `zizmor` and the
others in `.github/workflows/`).

`ci-ok` passes a skipped `build` or `soak` job only when `changes` passed
and decided that the run does not need it. A `build` or `soak` job that was
skipped for another reason (a failed `changes` job) fails `ci-ok`, as does a
needed job that did not pass. A pull request whose run skipped the build
jobs meets condition 2 of "Review and merge" with that run.

### Files that do not belong in the repository

The `files` job runs `test/check_added_files.sh BASE HEAD TIP`. The script
checks two lists of files:

- the files that the change adds: the paths that `HEAD` has and `BASE` does
  not have (`git diff --no-renames --diff-filter=A`, so a file that is renamed
  or moved counts as added at its new path);
- the files that its commits add: each commit from `TIP` back along first
  parents to `BASE` (`git log --first-parent BASE..TIP`), compared with its
  first parent. A file that one commit adds and a later commit removes stays
  in the history after the merge, so it is checked as well.

A file of either list fails with exit status 1 when it matches a pattern of
`test/forbidden_paths.txt`: a session directory or the local settings of an AI
coding agent under `.claude/` (everything there except
`.claude/settings.json`, `.claude/commands/` and `.claude/skills/`, which also
fail below another `.claude/`), a build directory at the top (`build/`,
`build_dynamic/`, `build_soak/`, `build_perf/`) or `mruby/build/`, the build
of the site (`site/dist/`, `site/build-screenshots/`, `site/generated/`,
`site/.astro/`), a file
that `./configure` or the Makefile writes at the top (`Makefile`, `config`,
`config.status`, `autom4te.cache/`, `mrbgems_config`, `.mruby_version`, the
`.openssl_*_done` files), `.vagrant/`, a tag file of GNU Global or ctags, a
`.log` file, `.env` or `.env.*`, private key material, an editor or OS
leftover, `node_modules/`, `__pycache__/` or a `.pyc` file, or a core dump. A
file of the first list also fails when it is empty (0 bytes), unless its name
is `.gitkeep` or `.keep`. Both lists include submodule entries (gitlinks),
whatever the git configuration or `.gitmodules` says about ignoring
submodules.

The script prints each failing path with the pattern and its line in the
pattern file, or with "empty file", and with the commit that added it. When
every file passes, it prints how many files it checked and exits 0. It exits
2 when the pattern file is missing, a pattern is invalid, a revision is not
in the repository, the repository is a shallow clone or a git command fails.
It reads only the pattern file and the git repository.

The commits follow first parents only. A merge commit among them is compared
with its first parent, so the files that its second parent brings in are
checked at the paths they have in the repository, and the commits of the
second parent are not checked one by one. This keeps out the squashed commit
of a subtree merge (`./update-mruby-subtree`), whose paths lack the `mruby/`
prefix. It also means that the check does not see a file that a commit of a
merged side branch adds and a later commit of that side branch removes.

For a pull request, the job checks out the merge commit of the pull request
with the whole history (`fetch-depth: 0`). It compares the merge commit with
its first parent, the base branch that the pull request was merged into, and
checks the commits from the head of the pull request (the second parent) back
to that base. So a pull request whose branch is behind its base is not blamed
for the files that the base removed in the meantime. For a push to a branch,
the job compares the previous tip of the branch (`github.event.before`) with
the pushed commit, and checks the commits between them. A tag push, a push
that creates a branch and a manual run have nothing to compare, and the job
passes. A pull request that changes the script or the pattern file is checked
with its own version of them, so the review of the pull request covers that
change.

`test/forbidden_paths.txt` holds one POSIX extended regular expression (as
`grep -E` reads it) per line, matched against the path from the top of the
repository. A line that starts with `!` is an exception, and the last line
that a path matches decides, as in `.gitignore`: `.claude/skills/a/SKILL.md`
matches `(^|/)\.claude/` and then the exception `!(^|/)\.claude/skills/`, so
it passes, while `.claude/skills/a/.DS_Store` also matches `(^|/)\.DS_Store$`
further down and fails. Empty lines and lines that start with `#` are
comments. The patterns must be generic: no names of other projects, people or
hosts.

To run the check before opening a pull request, commit the change and compare
it with the base branch (`origin/next` for a change to `next`). With two
arguments, the script also checks the commits from `HEAD` back to the base.
It needs the whole history, so run it in a clone that is not shallow:

```console
$ git fetch origin master
$ sh test/check_added_files.sh origin/master HEAD
check_added_files.sh: 2 added file(s) checked between origin/master and HEAD and in the 2 commit(s) of origin/master..HEAD, none forbidden or empty
```

When a file fails, remove it from the change (`git rm --cached <path>` keeps
it on disk), or, if it belongs in the repository, change
`test/forbidden_paths.txt` (for an empty file, the script) in the same pull
request and say why in its description. A file that a commit adds and a later
commit removes stays in the history: remove it from the commit that added it
(for example with `git rebase -i`), or squash the commits.

## The 2.x pages of the site

The site ngx.mruby.org is built on `next` (`site/` there, and
`docs/proposals/site.md` there for the plan). Its 2.x pages under `/v2/`
are built from `docs/` on `master`. Two workflows serve them:

- `.github/workflows/site-v2.yml` runs on every pull request to `master`,
  without a path filter, since the 2.x pages link to files anywhere in the
  repository (`.travis.yml`, `nginx_version`, the workflows). It checks
  out `next` beside the pull request, builds the site with `site/` and
  the 3.x pages of `next` and the 2.x pages from the pull request's
  `docs/` (`node site/scripts/build-v2.mjs --tree DIR` of `next`), and
  fails on a relative link or anchor of the sources of the
  2.x pages that does not resolve, on a link to a file that git does not
  track, on a broken link of the built site, on a 2.x page without its
  banner, and when the search of a version shows pages of the other. The
  built site is the workflow artifact `site-v2`.
- `.github/workflows/site-dispatch.yml` runs on every push to `master`,
  and starts `site.yml` on `next` with `gh workflow run site.yml --ref
  next`, so that the site is built again with the new 2.x pages. It fails
  when GitHub refuses the dispatch or it cannot name the run that the
  dispatch started.

Neither is in the `needs` of `ci-ok`.

## Supply chain checks

Three more workflows check the supply chain of the build. None of them is in
the `needs` of `ci-ok`, so none of them blocks a merge through the ruleset;
"Review and merge" in `AGENTS.md` asks for every CI check on the head commit
to pass, which includes the `zizmor` job of a pull request that runs it.

### Static analysis of the workflows

`.github/workflows/zizmor.yml` runs [zizmor](https://docs.zizmor.sh/) on
pull requests and pushes that change `.github/workflows/`,
`.github/dependabot.yml` or `.github/zizmor.yml`, and on "Run workflow". It
audits the files under `.github/` with the default persona, including the
audits that query GitHub (for example known vulnerable actions and commits
that are not on the action's repository), and fails on any finding. The
vendored `mruby/` tree has workflows of its own, which ngx_mruby does not
run; they are not audited. The version of zizmor is pinned in the workflow
(`version:`): Dependabot updates the pin of the action but not that input.

A finding is fixed in the workflow, or accepted with its reason: by a
`# zizmor: ignore[<audit>]` comment on a line of the finding, with the
reason in a comment above it, or by an `ignore` rule in `.github/zizmor.yml`
with the reason next to it. To run the same check before opening a pull
request (the online audits need a GitHub token):

```console
$ python3 -m venv .claude/tmp/zizmor && .claude/tmp/zizmor/bin/pip install zizmor==1.31.1
$ GH_TOKEN=$(gh auth token) .claude/tmp/zizmor/bin/zizmor --config .github/zizmor.yml .github
```

### OpenSSF Scorecard

`.github/workflows/scorecard.yml` runs
[OpenSSF Scorecard](https://github.com/ossf/scorecard-action) on pushes to
`master`, weekly, and on "Run workflow". Scorecard supports only the default
branch, so pull requests do not run it. It publishes the results to the Scorecard API
(<https://api.scorecard.dev/projects/github.com/matsumotory/ngx_mruby>),
uploads them to code scanning (the repository's Security tab), and keeps the
SARIF file as an artifact of the run for 5 days. Publishing makes the
Scorecard API check the workflow itself, so the workflow has no run steps and
no `defaults`; the comment at its top lists the restrictions.

GitHub disables the scheduled workflows of a public repository after 60 days
without activity in the repository. Then neither this workflow nor the next
one runs on its schedule, and nothing fails. "Run workflow", or enabling the
workflow again (`gh workflow enable scorecard.yml`, `gh workflow enable
gem-heads.yml`), starts them again.

### Heads of the GitHub gems

`.github/workflows/gem-heads.yml` runs `test/gem_heads.sh` every Monday, on
"Run workflow", and on pull requests that change `build_config.rb`, the
script or the workflow. For each `conf.gem github:` line of
`build_config.rb`, it reports the head of the branch that a build clones
(the line's `branch:`, or `master`, mruby's default when the line has
none), whether the gem's default branch is another branch, whether the
repository was renamed or archived, and whether the head moved since the
previous report. The `conf.gem mgem:` line (`mruby-secure-random`) is not
checked: mruby resolves it through the mgem-list repository.

The previous report is the artifact `gem-heads` of the newest successful
scheduled or manual run of the workflow on `master`; artifacts are kept for
90 days. `master` commits no `build_config.rb.lock`, so this report is the
only record of the heads that earlier builds took. A run with no previous
report reports every gem as `new`. A moved head is a warning annotation and
a row in the job summary, with a link that compares the two commits; the job
still passes. A gem whose repository or branch cannot be read fails the job,
and so does a failure to list the earlier runs. A previous report that cannot
be downloaded is a warning, and every gem is then reported as `new`.

To run the script on a checkout (it needs `gh` with a token):

```console
$ bash test/gem_heads.sh build_config.rb "" .claude/tmp/gem-heads.tsv
```

When a run reports a move, a session does the following. This is the
sessions' procedure, not a decision of the owner.

- Read the commits behind the comparison link. Every build of `master`, CI
  included, and every source build of a released 2.x tag already takes the
  new head; CI does not run for a move by itself, so run the `test` workflow
  on `master` (`gh workflow run test.yml --ref master`) and read its result.
- When the new head breaks the build or the suite, or changes what a 2.x
  configuration, script or build observes, report it to the owner with the
  run, and propose a pull request to `master`: a fix, or a `checksum_hash:`
  that pins the gem to the last good commit, with its release notes entry
  (see `docs/releases/README.md`). For the owner's gems
  (`matsumotory/mruby-*`), "Other repositories" in `AGENTS.md` applies.
- On `next`, `build_config.rb.lock` pins each gem, so the move reaches `next`
  only through a pull request that moves the pin; the `perf` job measures
  that pull request like any change of the lock.

## Testing
##### build nginx into ``./build/nginx`` and test on ``./build/nginx``
```
sh test.sh
```

`test.sh` configures nginx with `--with-debug`, `--with-http_stub_status_module`,
`--with-http_ssl_module`, `--with-http_auth_request_module` and `--with-stream`
(see `NGINX_DEFAULT_OPT` and `NGINX_CONFIG_OPT` in `test.sh`), so the test
configuration can use the directives of these modules. CI runs the same
`test.sh` on a fresh checkout. A local build directory keeps the options that
nginx was first configured with: the Makefile configures nginx again only when
`build/nginx-X.Y.Z/objs/Makefile` does not exist (`build_dynamic/...` for
`BUILD_DYNAMIC_MODULE`). After these options change, remove that file and run
`test.sh` once without `ONLY_BUILD_NGX_MRUBY`; otherwise nginx stops at the
test configuration with an "unknown directive" error. After changing
`nginx_version` or `BUILD_DYNAMIC_MODULE`, run `test.sh` once without
`ONLY_BUILD_NGX_MRUBY` as well: it then uses another build directory
(`build/nginx-X.Y.Z` of the new version, or `build_dynamic/`), and configures
nginx there when that file is missing in it.

To run nginx under valgrind, set the environment variable `NGINX_RUNNER`:

```console
$ NGINX_RUNNER=valgrind sh test.sh
```

valgrind writes its report when nginx exits at the end of `test.sh`, and
`test.sh` does not take valgrind's errors into its exit status (it prints
the exit status of nginx, 99 with the option `--error-exitcode=99` below
when valgrind counted errors). To check a
run as CI does, give valgrind the options of CI and read the `ERROR SUMMARY`
line of the log (see [valgrind in CI](#valgrind-in-ci)):

```console
$ rm -rf build/valgrind && mkdir -p build/valgrind
$ NGINX_RUNNER="valgrind --error-exitcode=99 --leak-check=full --show-leak-kinds=definite,indirect,possible --errors-for-leak-kinds=definite,indirect --suppressions=$PWD/test/valgrind.supp --log-file=$PWD/build/valgrind/valgrind.%p.log" sh test.sh
$ grep 'ERROR SUMMARY' build/valgrind/valgrind.*.log
```

### Waiting for nginx to listen

`test.sh` starts the test nginx in the background (`$NGINX_RUNNER
build/nginx/sbin/nginx &`) and sends the first request only after nginx
accepts TCP connections. It runs `test/t/cases/_wait_for_listen.rb` with
CRuby twice:

- Before it starts nginx, the script waits until no process accepts a
  connection on the ports below. A port that another process listens on
  would make the wait after the start succeed without nginx, so the run
  fails when one still accepts after `NGINX_HEATTIME` seconds, with the
  ports:

  ```text
  wait_for_listen: before nginx starts, 1 of 33 ports still accept connections after 60.05 seconds (limit 60.00): 18080; another process listens on them
  ```

- After it starts nginx, the script connects to each port every 0.1
  seconds until every port has accepted one connection, and prints the time
  that took, counted from the start of the script, right after nginx was
  started:

  ```text
  wait_for_listen: nginx (pid 1234) accepted connections on all 33 ports after 0.21 seconds (limit 60.00)
  ```

  It fails when the nginx process ends first, or when `NGINX_HEATTIME`
  seconds pass, and names the ports that still refused connections:

  ```text
  wait_for_listen: nginx (pid 1234) ended after 0.47 seconds, before it accepted connections on 33 of 33 ports: 18080, 18081, ...; see its output above and logs/error.log
  wait_for_listen: nginx (pid 1234) did not accept connections within 60.00 seconds (NGINX_HEATTIME) on 33 of 33 ports: 18080, 18081, ...
  ```

The ports are those of every `listen` directive in `test/conf/nginx.conf`
and `test/conf/conf.d/*.conf`, in the copy that "Ports" below describes,
with `TEST_SH_PORT_OFFSET` applied: the `http {}` servers (57 ports on `next` as of
2026-10-30). nginx opens all its listening sockets in one loop
(`ngx_open_listening_sockets()`) after it has read the whole configuration,
so one port would almost always show that the others are open. Each port
costs one connection of well under a millisecond, though, and checking every
one leaves no gap between the first socket and the last, and also catches a
fragment of `conf.d` that did not reach the installed configuration. The
`stream {}` ports (`test/conf/nginx.stream.conf` and
`test/conf/conf.d/stream/`) are left out: a connection to a stream server
runs that server's session code, such as the `Nginx::Stream::Async.sleep
3000` of the 12352 server, and the cases read what that code writes to
`error.log`. nginx opens the stream sockets in the same loop, right after
those of `http {}`, and the first test that connects to a stream port
runs after many HTTP tests of `test/t/ngx_mruby.rb` have passed. The ports that
`Nginx::Server#add_listener` and `Nginx::Stream.add_listener` add are opened
in the same loop as well, and are not checked.

`NGINX_HEATTIME` is the upper bound, in seconds, of each of the two waits.
The default is 60, and CI does not set it. A command that sets it, such as
`NGINX_RUNNER=valgrind NGINX_HEATTIME=10 sh test.sh`, waits at most that
long: the run goes on as soon as nginx listens, and fails at 10 seconds only
when nginx is not listening by then, where a first request sent at that time
would have been refused (`Errno::ECONNREFUSED`).

The default rests on these measurements. On 2026-10-19, the test nginx
built from `master` at 03aad7031 (nginx 1.31.6, static module) was started
the way `test.sh` starts it, in a container of Ubuntu 22.04 on an aarch64
host with 11 CPUs whose load average was about 15 from other builds, and
the script above measured the time until all ports accepted connections:

- `NGINX_RUNNER=exec`, 10 starts: 0.10 to 0.11 seconds each, that is, every
  port accepted on the second round of attempts (the script tries every 0.1
  seconds);
- `NGINX_RUNNER=valgrind` (valgrind 3.18.1), 5 starts: 2.27 to 2.61 seconds.

In CI, a cell under valgrind (nginx 1.28.3 on an x86_64 runner) was still
reading the configuration 10 seconds after the start: valgrind's report at
the SIGTERM of `test.sh` shows nginx inside `ngx_conf_parse()`
([the run](https://github.com/matsumotory/ngx_mruby/actions/runs/37181065564),
reported in
[#564](https://github.com/matsumotory/ngx_mruby/pull/564#issuecomment-5977252444)).
The time is longer on a loaded CI runner, under valgrind (here more than 20
times the time without it), with the sanitizer build (not measured here) and
with more configuration to read. 60 seconds is 6 times the 10 seconds of
that CI run and about 23 times the slowest start under valgrind above.

The upper bound can create these races:

- A start slower than the bound fails the run although nginx would have
  started. Raise `NGINX_HEATTIME` for slower setups; the wait still ends as
  soon as nginx listens, so a higher bound costs time only when nginx hangs
  without ending (an nginx that exits is reported at once).
- A listening socket is not yet a running handler. The kernel accepts a
  connection as soon as nginx listens, and the test nginx is a single
  process (`master_process off`) that runs the `init_worker` hooks before it
  reads any connection. The first request then waits in the socket's backlog
  until nginx reads it; the test client (mruby-simplehttp) reads without a
  timeout, so it waits too.
- nginx later reads each probe connection of the wait, finds it closed
  without a request, and closes it. No handler runs for it, and nginx writes
  only `debug` lines about it to `error.log`.

### Stopping nginx

`test.sh` stops only the nginx processes that it started, by their pid. It
never signals a process by its name (`killall`, `pkill`), so the nginx
processes of other checkouts, of the soak test, of nginx-tests and of other
users keep running. Two runs of `test.sh` on one machine need different
ports ("Ports" below); with the same ports, the second run fails in the
wait before the start, as "Waiting for nginx to listen" above shows.

- When `test.sh` exits, after the last case, after a failure, or on SIGHUP,
  SIGINT or SIGTERM, it stops the test nginx with SIGTERM and waits until the
  process has ended. It then prints how long that took and the exit status
  of nginx; the status does not change the exit status of `test.sh`:

  ```text
  test.sh: nginx (pid 374) ended within about 0.1 seconds of the first SIGTERM; SIGTERM sent 1 times
  test.sh: nginx (pid 374) exit status 0
  ```

  The shell runs the trap of a signal only after the command that runs at
  that moment has ended, such as the wait for nginx, `test/t/ngx_mruby.rb`
  or the current case file, so the stop starts then. A shell that is not
  interactive also starts a command run with `&` with SIGINT ignored, so
  `sh test.sh &` does not stop on SIGINT; send SIGTERM instead.

- Before each signal, `test.sh` checks that the pid still runs
  `build/nginx/sbin/nginx` of this checkout: its command line, from `ps -ww
  -o args=`, contains that absolute path, also under valgrind. The shell
  collects a background process that has ended, so after a crash of nginx
  its pid may belong to another process by the time of the stop. Such a pid
  counts as ended and gets no signal:

  ```text
  test.sh: nginx (pid 374) had ended before the stop; no signal sent
  ```

- Before it starts nginx, `test.sh` reads `build/nginx/logs/nginx.pid`
  (`build_dynamic/...` for `BUILD_DYNAMIC_MODULE`). When an earlier run was
  killed before it could stop its nginx, that nginx still runs and the file
  names it. `test.sh` stops it in the same way if the process runs
  `build/nginx/sbin/nginx` of this checkout, by the check above, and leaves
  any other process alone:

  ```text
  test.sh: stopping the nginx (pid 7) that an earlier run left running
  test.sh: logs/nginx.pid names pid 7, which does not run /path/to/build/nginx/sbin/nginx; left running
  ```

The test nginx is a single process (`master_process off`). It checks for a
signal only after it has handled its events, in the loop of
`ngx_single_process_cycle()`: the signal handler sets `ngx_terminate`, and
the loop exits once `ngx_process_events_and_timers()` returns. A SIGTERM
that arrives after that check and before the next `epoll_wait()` does not
interrupt the wait, and with no timer and no connection, `epoll_wait()`
waits without a time limit. nginx then logs `signal 15 (SIGTERM) received`
and keeps running. A master process does not have this gap: it waits for
signals with `sigsuspend()`, and while its workers still run after a
SIGTERM, it sends them the command to terminate again, over the socket pair
of each worker that the worker's event loop watches (SIGTERM only where that
write fails), with a delay that starts at 50 milliseconds and doubles, and
it sends SIGKILL once the delay exceeds one second, about 1.6 seconds after
the first signal (`ngx_master_process_cycle()`). `test.sh` does the same for
the single process with the signal: it sends SIGTERM again 1, 3, 7, 15 and
31 seconds after the first one while the process still runs, and a SIGTERM
that arrives during `epoll_wait()` ends the wait. It waits longer than the
master before SIGKILL because the test nginx may run under valgrind, which
checks for leaks at the exit, and SIGKILL would lose that report. After
`NGINX_STOPTIME` seconds (default 60) it sends SIGKILL, prints

```text
test.sh: nginx (pid 374) did not end within 60 seconds (NGINX_STOPTIME) after 6 SIGTERM; sent SIGKILL
```

and exits 1. `test.sh` counts these times in rounds of `sleep 0.1` and a
`ps`, so the real times are somewhat longer than the printed ones. The
second nginx of `test/t/cases/_second_instance.rb`, also a single process,
is stopped with SIGQUIT, sent again in the same way.

How often a run hits the gap was measured on 2026-10-29, with the test
nginx built from `next` at `c9c49023e` (nginx 1.31.6, static module), started
as `test.sh` starts it, in a container of Ubuntu 22.04 on an aarch64 host
with 11 CPUs:

- 800 starts of the test nginx, each followed by one SIGTERM: 400 right after
  the response to one request, and 400 at 0 to 20 milliseconds after three
  requests were sent. nginx ended after the one SIGTERM every time. The gap
  lasts from the check of `ngx_terminate` to the call of `epoll_wait()`, a
  debug log line and a lookup of the timer tree, so a loop of this size does
  not find it.
- gdb attached to the test nginx, waited until nginx had closed the
  connection of a request, stopped it at the next call of
  `ngx_epoll_process_events()`, with no event and no timer left
  (`timer=-1`), and delivered SIGTERM there. nginx logged `signal 15
  (SIGTERM) received from ..., exiting` and then `epoll timer: -1`, and
  still ran 10 seconds later. A second SIGTERM ended it within 0.1 seconds.
  This is the state of the run of `test.sh` at `7926f72`
  ([#600](https://github.com/matsumotory/ngx_mruby/pull/600)), where nginx
  logged the SIGTERM and stayed in `epoll_wait()` for 20 minutes.

### Ports

The ports of the suite are the numbers from 12345 to 12399 and from 18080
to 18199: the `listen` directives of `test/conf/`, the addresses of
`add_listener`, the second nginx of `test/t/cases/_second_instance.rb`
(18116 and 12357), the nginx of `test/t/cases/config_hooks.rb` (18158), the
mock LLM upstream of `test/t/cases/_agent_proxy_client.rb` (12372 and
12373), the stream-only test of `test/t/ngx_mruby.rb` (12399), and the
ports that the tests, the hook scripts and the expected outputs of
`test/html/` name. `TEST_SH_PORT_OFFSET` (an integer, default 0) moves all
of them by the same amount, so that two checkouts can run `test.sh` at the
same time on one machine, each with its own offset:

```console
$ TEST_SH_PORT_OFFSET=1000 sh test.sh    # 13345 to 13399 and 19080 to 19199
```

Before it installs the configuration, `test.sh` runs
`test/t/cases/_stage.rb`, which copies `test/t`, `test/conf`, `test/html`,
`test/soak/mock_llm.rb` and `test/soak/http_client.rb` to
`build/nginx/harness/test/` (`build_dynamic/...` for
`BUILD_DYNAMIC_MODULE`). In every text file of the copy, each number of
those two ranges, written as five digits with no digit, letter or `_` next
to it, becomes the number plus the offset:

```text
stage: copied 164 files to /path/to/build/nginx/harness/test; 593 port numbers moved by 1000
```

`test.sh` then installs the configuration and the hook scripts from the copy,
waits for the ports of the copy, and runs `test/t/ngx_mruby.rb` and the case
files of the copy. The tests run the CRuby helpers of the copy through
`suite_path` (`test/t/cases/_prelude.rb`, and `test/t/ngx_mruby.rb` for its
own use), which joins a path of the suite to `TEST_SH_STAGE_DIR`, the
directory that `test.sh` sets. Without that variable, as when a case runs
outside `test.sh`, `suite_path` gives the path in the checkout. The tests
still run from the root of the checkout, because the configuration names
the hook scripts with paths relative to it (`build/nginx/html/<name>.rb`).
With an offset of 0, the copy is the same as the source.

The rule is textual, so a new test keeps to it:

- Write a port as five digits in one of the two ranges, and write a number
  in those ranges only where it is a port or a value that the test compares
  with a number of the same file set. `_stage.rb` fails, naming the file
  and the line, for such a number written with an underscore (`18_132`),
  which the rule would not see. A port built by arithmetic is moved only
  when its five-digit part is in the ranges: `18110 + 1` becomes
  `19110 + 1` with an offset of 1000, but `18000 + 110` and a port built
  from strings stay as they are, so write the number out.
- One number in the ranges is not a port: `test/conf/conf.d/20-filter-connection.conf`
  outputs `f.output 12345`, and `test/t/cases/filter_connection.rb` compares
  the body with `'12345'` and its length with `'5'`. Both files are moved
  alike, so the case still checks that `Filter#output` converts an Integer
  with `to_s` into five bytes.
- The offset must keep every port between 10000 and 65535, so that every
  number stays five digits long (an offset from -2345 to 47336); `_stage.rb`
  fails otherwise. It must also keep the ports apart from those of other
  runs: the soak test (12360 to 12362, `SOAK_PORT_BASE`), the performance
  comparison (12370 to 12372, `PERF_PORT_BASE`) and nginx-tests (8000 to
  8999). With offset 0, `test.sh` and the performance comparison both use
  12372.

Two runs need two checkouts as well as two offsets: one build directory
holds one test nginx, its logs and its copy of the suite. The two offsets
must keep the ranges of the two runs apart. The range from 18080 to 18199
has 120 numbers, so the offsets differ by 120 or more. The range from 12345
to 12399 of one run lands on the range from 18080 to 18199 of the other
when the difference of the offsets is from 5681 (18080 - 12399) to 5854
(18199 - 12345), with either sign, so the difference is not in that
interval. With an offset above 14568 (32767 - 18199), the ports of 18080 to
18199 reach the default ephemeral range of Linux (32768 to 60999), where a
client socket can take a port before nginx binds it. The offsets 0 and 1000
of the example meet all three conditions.

### valgrind in CI

The `build` matrix of `.github/workflows/test.yml` runs `test.sh` in each
cell. Which cells run nginx under valgrind depends on the run:

- On pull requests and pushes whose run starts the `build` matrix ([Which
  jobs a run starts](#which-jobs-a-run-starts)), one cell runs nginx under valgrind: nginx
  1.31.8, static module, without `--with-openssl-src`, the job
  `build (1.31.8)` (the matrix gives it `VALGRIND_ON_EVERY_RUN`). The other cells without a sanitizer run nginx
  directly (`NGINX_RUNNER=exec`), and the sanitizer cell runs nginx built
  with AddressSanitizer and UndefinedBehaviorSanitizer (see the next
  section).
- A manual run of `test.yml` with the input `valgrind` runs every cell
  except the sanitizer cell under valgrind:

  ```console
  $ gh workflow run test.yml --ref next -f valgrind=true
  ```

- The nightly run: `.github/workflows/valgrind-nightly.yml` starts such a
  run of `test.yml` every day at 18:23 UTC for each branch of its matrix
  (`next`), waits for it, and fails when it fails. GitHub runs a schedule
  only from the workflow file on the default branch, `master`, so the
  schedule takes effect once the file is on `master`. Until then, the file
  on `next` runs on pull requests that change it, `test.yml` or
  `test/valgrind.supp`: there it starts the run under valgrind on the head
  branch of the pull request. Neither run is a status check that `ci-ok`
  needs.

valgrind adds little time to a cell. The part of `test.sh` from the start
of nginx to `test.sh ... successful` took 67 to 94 seconds in the 16 cells
under valgrind of the run with the input `valgrind`
[40824932917](https://github.com/matsumotory/ngx_mruby/actions/runs/40824932917),
and 57 to 75 seconds in the 15 cells that ran nginx directly in the run of
the same commit for its pull request
[40824899601](https://github.com/matsumotory/ngx_mruby/actions/runs/40824899601)
(2026-10-29). A cell takes 4 to 13 minutes in all, most of it for the
builds of OpenSSL, mruby and nginx.

A cell under valgrind runs nginx with these options:

```text
valgrind --error-exitcode=99 --leak-check=full --show-leak-kinds=definite,indirect,possible --errors-for-leak-kinds=definite,indirect --suppressions=test/valgrind.supp --log-file=$RUNNER_TEMP/valgrind/valgrind.%p.log
```

valgrind counts an error for each memory error that occurs (an invalid
read or write, a conditional jump or a system call on an uninitialised
value, an invalid or mismatched free) and for each loss record of the
kinds `definite` and `indirect` that `test/valgrind.supp` does not
suppress, and prints the count, with the number of distinct stacks
(contexts), in its `ERROR SUMMARY` line when nginx exits: an invalid read
in a handler that 20 requests ran gives `20 errors from 1 contexts`. With
`--error-exitcode=99`, valgrind also exits with 99 when the count is not 0.
`test.sh` prints the exit status of nginx when it has stopped it
(`test.sh: nginx (pid 374) exit status 99` after valgrind counted errors;
see [Stopping nginx](#stopping-nginx)), but does not take it into its own,
so the step "Check the valgrind reports" reads the logs instead: it prints each log, and fails unless at least one
log has an `ERROR SUMMARY` and every `ERROR SUMMARY` counts 0 errors. A
cell without any `ERROR SUMMARY` fails as well: valgrind did not finish its
report.

Possibly lost blocks are printed with their stacks, but are not errors. At
the exit of the test nginx (`master_process off`), nginx has destroyed the
pool of the cycle, and the arrays of connections and events that
`ngx_event_process_init()` allocated, the table of `ngx_crc32_table_init()`
and the pools of the connections that are still open are left. valgrind
finds only interior pointers to them and reports them as possibly lost.
Their number depends on the connections that are open when nginx exits: in
the CI runs
[40819115837](https://github.com/matsumotory/ngx_mruby/actions/runs/40819115837),
[40820233191](https://github.com/matsumotory/ngx_mruby/actions/runs/40820233191)
and
[40821209339](https://github.com/matsumotory/ngx_mruby/actions/runs/40821209339)
of 2026-10-29, each of the 16 cells under valgrind reported from 5 blocks
(85,440 bytes) to 8 blocks (86,208 bytes), and the cell of nginx 1.31.6
with the static module gave 5, 7 and 7 blocks in these three runs. A leak
of ngx_mruby, mruby or a gem that drops the last pointer to a block is
definitely lost, and fails the cell. A request or connection that ngx_mruby
never finalizes keeps its pools until nginx exits, and valgrind reports
them as possibly lost, so it does not fail the cell. In the run
40824899601, the pool of an upstream connection that was still open at exit
is possibly lost, with `ngx_mrb_post_fiber` in the stack of its allocation.
The `soak` job, which compares the connections, timers and file descriptors
of the worker between samples ([Soak test for
memory](#soak-test-for-memory)), is the check for such leaks.

`test/valgrind.supp` suppresses only allocations of nginx itself, each with
its stack and the reason in a comment: today the environment array of
`ngx_set_environment()` (8 bytes, definitely lost in every cell), which
nginx leaves allocated at exit on purpose (`ngx_cleanup_environment()` in
`nginx.c`). An entry is added only with the stack of the report and the
reason why the block is not ngx_mruby's; a leak with a frame of ngx_mruby,
mruby or a gem is not suppressed.

## Running the tests under AddressSanitizer and UndefinedBehaviorSanitizer

CI builds one matrix cell with `-fsanitize=address,undefined`. To run the
same build locally (Linux, gcc or clang):

```console
$ sudo sysctl -w vm.mmap_rnd_bits=28     # ASan and the kernel's high-entropy ASLR do not mix
$ export NGINX_EXTRA_CC_OPT="-fsanitize=address,undefined -fno-omit-frame-pointer"
$ export NGINX_EXTRA_LD_OPT="-fsanitize=address,undefined"
$ export NGX_MRUBY_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
$ export NGX_MRUBY_LDFLAGS="-fsanitize=address,undefined"
$ export ASAN_OPTIONS="detect_leaks=1"
$ export LSAN_OPTIONS="suppressions=$PWD/test/lsan.supp"
$ export UBSAN_OPTIONS="print_stacktrace=1:suppressions=$PWD/test/ubsan.supp"
$ NGINX_RUNNER=exec sh test.sh
$ grep -HnE 'ERROR: (AddressSanitizer|LeakSanitizer)|runtime error:|SUMMARY: (AddressSanitizer|UndefinedBehaviorSanitizer)' $(find build/nginx/logs $(ls -d build/nginx/second_instance 2>/dev/null) -type f -name '*.log')
```

The last line reads the files that the "Check for sanitizer reports" step
of the CI cell reads, with the same pattern; the step fails when a line
matches. A report goes to the stderr of the process that wrote it, and that
is one of these files:

| File | Whose stderr |
|---|---|
| `build/nginx/logs/error.log` | the test nginx, once it has opened its log (its leak report at exit included) |
| `build/nginx/logs/stderr.log` | the test client (`test/t/ngx_mruby.rb` and the case files; `test.sh` redirects it), and so the processes that the tests start without redirecting it: `nginx -t`, the `nginx -s quit` of the stream-only test, an nginx before it has opened its log |
| the other `build/nginx/logs/*.log` | the nginx processes that the tests start with a log of their own, after they have opened it (`stream_only.error.log` of the stream-only test, which runs nginx with `daemon on`) |
| `build/nginx/second_instance/<mode>/*.log` | the second nginx of `test/t/cases/_second_instance.rb` (`error.log`, `stderr.log`, `stdout.log`) |

`build/nginx/second_instance/` is missing when `test.sh` stopped before the
case files; the step then reads the other files and says so. The step does
not read the `*.log.bak` files, in which `test.sh` keeps the
logs of an earlier run in the same directory. A report of the test nginx
from before it opened `error.log` goes to the terminal (in CI, the output of
the `script` step), as the next paragraph says.

`NGINX_EXTRA_CC_OPT` and `NGINX_EXTRA_LD_OPT` are appended to nginx's
`--with-cc-opt` and `--with-ld-opt`; `NGX_MRUBY_CFLAGS` and `NGX_MRUBY_LDFLAGS`
reach the mruby build. Do not combine the sanitizers with valgrind. nginx
sends its stderr to `error.log` once the configuration is loaded, so reports
from code that runs while nginx parses the configuration (directive handlers,
script compilation, `mruby_init_code`) appear on the terminal instead; read
both. `test/ubsan.supp` lists the reports that come from nginx itself, each
with the reason. `test/lsan.supp` does the same for LeakSanitizer: nginx
never frees `cycle->connections` and the two event arrays it allocates in
`ngx_event_process_init`, and whether LeakSanitizer reports them at exit
depends on whether anything outside them still points at them, so without
the suppression a run can fail on nginx's own allocations. With the gcc 11
runtime that CI uses, a suppressed block hides nothing else; the LLVM
runtime and gcc 12 and later also treat a suppressed block as a root, so
there a block reachable only from those arrays is not reported either.

## nginx's own test suite (nginx-tests)

`sh test/nginx-tests/run.sh` runs nginx's own test suite,
[nginx-tests](https://github.com/nginx/nginx-tests), with `prove` on two
builds of the nginx version in `nginx_version`, and compares the results:

- nginx with ngx_mruby, built by `test.sh` with `TEST_SH_SKIP_TESTS=1`:
  the static module, the configure options of `test.sh` (see
  [Testing](#testing)) and `-DMRB_GC_STRESS`, installed to `build/nginx`.
  With `TEST_SH_SKIP_TESTS=1`, `test.sh` stops after the install: it writes
  no test configuration, kills no nginx and starts none. `run.sh` unsets
  `BUILD_DYNAMIC_MODULE`, which would build into `build_dynamic/` instead.
- nginx without ngx_mruby: a copy of the same nginx source in
  `build_nginxtests/plain/src`, configured with the options that `test.sh`
  gave nginx (`NGX_CONFIG_OPT` of the generated `Makefile`) without the two
  `--add-module` options that the `Makefile` adds, for ngx_mruby and for
  ngx_devel_kit. The `configure arguments` lines of `nginx -V` in the
  summary show both.

The test files write their own nginx configurations, and none has an mruby
directive. In the build with ngx_mruby, each start and reload of nginx
creates an `mrb_state` of ngx_mruby for each `http {}` and each `stream {}`
block while nginx reads the configuration (`mrb_open`, under
`MRB_GC_STRESS`), and `mrb_open` runs the Ruby code of mruby's core and
of the bundled gems. Each HTTP request passes the handlers that ngx_mruby
adds to the post-read, server rewrite, rewrite, access and log phases, in
the phases that the request reaches (a `return` or a `rewrite` can end it
before the later ones), and the one of the content phase unless the
location has a content handler of its own (`proxy_pass` and the like),
which nginx runs instead of the handlers of that phase. These handlers decline when no
code is configured. Each stream session passes ngx_mruby's handler of the
access phase. The header and body filters of ngx_mruby are added only when
a directive asks for them, and no handler, filter or init code of a
configuration runs. A test file that fails with ngx_mruby and passes
without it therefore shows that the module changes nginx's behavior
although nothing is configured for it.

### The pinned commit of nginx-tests

nginx-tests has no releases or tags. `run.sh` fetches the commit in
`NGINX_TESTS_COMMIT`, `ec44bc80c4bf` (the head of `master` on 2026-10-19,
committed on 2026-10-16), so that a test added upstream does not change the
results without a change in this repository. A pull request of its own moves
the pin, and quotes the summaries before and after; a change of
`nginx_version` is a reason to move it, because new test files of
nginx-tests test the features of new nginx versions and skip themselves on
older ones.

### Running nginx-tests

`run.sh` needs Linux, a user other than root (the test files write their
configurations to directories that only that user can read, and nginx
started by root runs its workers as `nobody`), and what `test.sh` needs.
The test files that need a perl module or a program that is missing are
skipped, not failed. On Ubuntu 22.04, the job installs:

```console
$ sudo apt-get install rake bison git gperf zlib1g-dev libpcre3-dev libssl-dev ruby \
    libio-socket-ssl-perl libnet-ssleay-perl libfcgi-perl libscgi-perl \
    libcache-memcached-perl libcache-memcached-fast-perl libprotocol-websocket-perl memcached
$ sh test/nginx-tests/self-test.sh
$ sh test/nginx-tests/run.sh
```

On macOS, run it in a Linux container on a copy of the tree, mounted at the
same path:

```sh
D=$HOME/ngx_mruby-nginx-tests   # any directory outside the checkout
rm -rf "$D" && mkdir -p "$D" && git archive HEAD | tar -x -C "$D"
docker run --rm -v "$D:$D" -w "$D" ubuntu:22.04 sh -c 'apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y build-essential perl rake ruby bison git gperf wget ca-certificates openssl zlib1g-dev libpcre3-dev libssl-dev libio-socket-ssl-perl libnet-ssleay-perl libfcgi-perl libscgi-perl libcache-memcached-perl libcache-memcached-fast-perl libprotocol-websocket-perl memcached >/dev/null && useradd -m nt && chown -R nt "$PWD" && su nt -c "NGX_MRUBY_COMMIT='"$(git rev-parse HEAD)"' sh test/nginx-tests/run.sh"'
```

The test files start nginx on ports from 8000 to 8999 that they lock, so
they run in parallel (`NGINX_TESTS_JOBS`, by default the number of CPUs).
They do not use the ports of `test.sh`, and `test.sh` stops only the nginx
that it started ("Stopping nginx" above).

Environment variables: `NGINX_TESTS_OUT` (the output directory, by default
`build_nginxtests`), `NGINX_TESTS_SRC` (a checkout of nginx-tests at the
pinned commit, used instead of the fetch, for example when github.com is
unreachable), `NGINX_TESTS_JOBS`, `NGINX_TESTS_FILES` (test files to run
instead of all, for example `NGINX_TESTS_FILES='access.t proxy.t'`) and
`NGX_MRUBY_COMMIT` (the ngx_mruby commit that the summary names; by
default `GITHUB_SHA` in GitHub Actions, else `HEAD` of the checkout). Extra
arguments of `run.sh` go to `test.sh`, and so to `./configure`. The
variables of nginx-tests itself work as well: to read the error log of a
failed file, run it again alone with `TEST_NGINX_LEAVE=1` (keeps its
temporary directory) or `TEST_NGINX_CATLOG=1` (prints the log).

The output, in `build_nginxtests/`:

| File | Content |
|---|---|
| `summary.md` | The counts of both builds, the failed files by build, the reasons of the skips, the configure arguments of both builds |
| `only-mruby.txt`, `both.txt`, `only-plain.txt` | The test files that failed with ngx_mruby only, on both builds, and without ngx_mruby only |
| `mruby/`, `plain/` | For each build: `prove.log` (the output of `prove`), `results.tsv` (a line for each test file: the file, `passed`, `failed` or `skipped`, and the reason of a skip or the failed subtests), `nginx-V.txt` |

`test/nginx-tests/results.pl` reads `prove.log`: a file fails when its
entry in prove's "Test Summary Report" has failed subtests, a wait status
other than 0 or parse errors (a missing or wrong plan), and a file whose
entry has only TODO subtests that passed has passed. It stops when the log
is not a complete run of prove. `test/nginx-tests/compare.pl` writes the
lists and the summary. `sh test/nginx-tests/self-test.sh` checks both on
the output of `prove` for the small test files in
`test/nginx-tests/self-test/`, which pass, fail, skip or break their plan
on purpose, differently for the two builds (the table at the top of
`self-test.sh`).

`run.sh` exits with 0 when both builds were tested and their results read,
also when test files failed. It exits with another status when a build,
the fetch or `prove` itself failed, or when a log is not a complete run.

### nginx-tests in CI

`.github/workflows/nginx-tests.yml` runs the self-test and `run.sh` on
`ubuntu-22.04`, on pull requests to `next` that change an input of the
nginx binary (the inputs that "[In CI](#in-ci)" of the performance
comparison lists), `test.sh`, `test/nginx-tests/` or the workflow, on every
push to `next` (each push gets a run of its own, also when the next push
comes before it finished) and on "Run workflow". The job summary is `summary.md`, each
file that fails with ngx_mruby only is a warning annotation, and the
artifact `nginx-tests` has the output above without the copy of the nginx
source.

The job records; it does not gate. It fails only when the self-test, a
build, the fetch or `prove` itself fails, or `summary.md` is missing, not
on the result of a test file, and `ci-ok` does not need it (see
[Required status check](#required-status-check)). Pillar E of
`docs/proposals/v3-plan.md` makes it required once its results are stable.

### Results of nginx-tests

Measured on 2026-10-19, with nginx-tests at `ec44bc80c4bf`, nginx 1.31.6,
gcc 11.4.0, OpenSSL 3.0.2 and perl 5.34 on both machines:

- CI: the `nginx-tests` job of
  [run 39241352263](https://github.com/matsumotory/ngx_mruby/actions/runs/39241352263)
  on `ubuntu-22.04` (x86_64, 4 parallel test files), on the merge commit
  `401cf56` of #602 (`093e47d`) into `next` at `7b5a0c4`.
- A Docker container of `ubuntu:22.04` on macOS (aarch64, 11 parallel test
  files), with the command of [Running nginx-tests](#running-nginx-tests),
  on `093e47d`.

| Machine | Build | Test files | Passed | Failed | Skipped | Subtests run |
|---|---|---|---|---|---|---|
| CI (x86_64) | nginx with ngx_mruby | 511 | 302 | 0 | 209 | 3994 |
| CI (x86_64) | nginx without ngx_mruby | 511 | 302 | 0 | 209 | 3994 |
| Container (aarch64) | nginx with ngx_mruby | 511 | 301 | 0 | 210 | 3991 |
| Container (aarch64) | nginx without ngx_mruby | 511 | 301 | 0 | 210 | 3991 |

- Test files that fail because ngx_mruby is in nginx (they fail with
  ngx_mruby and pass without it): none, on both machines.
- Test files that fail on nginx without ngx_mruby too: none, on both
  machines.

The two machines differ in one file, `ssl_ktls.t`: it passes on the runner
and skips in the container ("no Linux KTLS"), whose kernel has no kTLS. On
each machine, the same files were skipped on both builds, for the same
reasons. Of the 209 on the runner, 189 skip because nginx lacks a module
that `test.sh` does not build: `http_v2` (59 files), `stream_ssl` (25),
`http_v3` (23), `mail` (16), `realip` (11), `sub` (9), and 18 other modules
with 1 to 6 files each. The other 20 skip for conditions of the machine or
of nginx-tests: a program or perl module that is not installed (`uwsgi` for
4 files, `GD`, `Win32API::File`, a newer `IO::Socket::SSL`), OpenSSL 3.5,
root (3 files), a wildcard address (2), Windows (1), and 6 files that
nginx-tests runs only with `TEST_NGINX_UNSAFE` or not at all (an orphaned
process group, a long test, keys of an OpenSSL engine or provider). The
summary of each run lists every reason with its count. On the runner, the
job took about 8 minutes: 2 minutes 37 seconds for the two builds and 2
minutes 37 seconds for `prove` on each build.

These results cover nginx with ngx_mruby present and nothing configured for
it. Two kinds of runs would cover more and are not in place: a build with
the modules that the skipped files need (`--with-http_v2_module`,
`--with-http_v3_module`, `--with-stream_ssl_module`, `--with-mail` and the
others above), and runs in which ngx_mruby's handlers or filters run Ruby
code on the requests of the suite (`TEST_NGINX_GLOBALS_HTTP`, as Pillar E
of `docs/proposals/v3-plan.md` names). `docs/HANDOFF.md` lists both in its
queue.

## Mock LLM upstream

`test/soak/mock_llm.rb` (CRuby 3.0 or later) is an HTTP/1.1 server that
answers `POST /v1/messages` the way the Anthropic Messages API does and
`POST /v1/responses` the way the OpenAI Responses API does. It stands for
the upstream of an agent proxy (nginx with ngx_mruby in front of an LLM
API) in three places:

- the soak test (`agent_*` scenarios) and the performance comparison
  (`proxy_*`, `responses_stream_plain_*`, `auth`, `route_json_*`), which
  start it as a process of its own on the port base + 2 (12362 and 12372)
  for each scenario, with the options of the scenario (`mock` in
  `test/soak/scenarios.rb`);
- the case `test/t/cases/agent_proxy.rb`, whose helper
  `test/t/cases/_agent_proxy_client.rb` runs it in the helper's process on
  12372 and 12373 while it sends its requests. The case checks recipes of
  an agent proxy that work with the current build, on the server of
  `test/conf/conf.d/60-agent-proxy.conf` (port 18132): a server rewrite
  handler that rejects an unknown client key with 401 and a JSON body from a
  server-level `error_page` (and the request does not reach the upstream);
  an access handler that picks one of two upstream blocks by the `model` of
  the JSON body and replaces the client's credential; `limit_conn` per client
  key, whose rejection becomes a JSON 429 with `retry-after` through
  `limit_conn_status 460` and `error_page`, and whose slot is free again
  after the client closed its stream; an upstream 529 passed to the client
  unchanged; and a log handler that reads `$upstream_status`. The same
  recipes run on `location = /v1/responses` with Responses requests, where
  the proxy's own 401 and 429 bodies use the error format of the Responses
  API and the upstream errors are a 503 and a 429. The case also checks
  that a stream of 50 deltas arrives byte for byte: one Messages stream,
  and one Responses stream for each terminal event.

```console
$ ruby test/soak/mock_llm.rb --port 12362 --events 50 --hold-after 10
```

| Option | Default | Meaning |
|---|---|---|
| `--port PORT` | (required) | listen on `127.0.0.1:PORT`; repeat it for more ports, which answer the same way |
| `--events N` | 50 | text delta events in a stream: `content_block_delta` (Messages), `response.output_text.delta` (Responses) |
| `--delta-text TEXT` | `hello ` | the text of each text delta event |
| `--hold-after K` | off | write the first K events of a stream, then nothing more until the other side closes the connection |
| `--reset-after K` | off | write the first K events of a stream, then reset the connection (RST) |
| `--status CODE` | off | answer every request with this status and an error body of its API, before any event: on `/v1/messages` an Anthropic error (`overloaded_error` for 529, `api_error` for 503), on `/v1/responses` an OpenAI error (`rate_limit_error` for 429, `service_unavailable_error` for 503, `invalid_request_error` for the other 4xx, `server_error` for the other 5xx) |
| `--delay-ms MS` | 0 | wait MS milliseconds between two events |
| `--one-write` | off | write the head and the whole stream with one write |
| `--terminal NAME` | `completed` | the event that ends a Responses stream: `completed`, `incomplete` or `failed` |

A request can override the options for itself with the headers
`x-mock-events`, `x-mock-hold-after`, `x-mock-reset-after`, `x-mock-status`
and `x-mock-delay-ms`, each a number of 0 or more, and `x-mock-terminal`,
one of `completed`, `incomplete` and `failed`. `x-mock-hold-after`,
`x-mock-reset-after` and `x-mock-status` also take `off`, which turns the
hold, the reset or the error status off; `x-mock-events` and
`x-mock-delay-ms` do not. Any other value gets a 400 answer
(`invalid_request_error`) that names the header. nginx forwards the headers
unless the configuration drops them. `ruby test/soak/mock_llm_test.rb` checks
these rules and the answers below against the mock in its own process (no
nginx, about a second); `test/soak/run.sh` runs it before the soak.

What it answers on `POST /v1/messages`:

- A JSON body with `"stream": true`: 200, `text/event-stream`, chunked. The
  events are `message_start` (with `usage`), `content_block_start`, N
  `content_block_delta` events with the text, `content_block_stop`,
  `message_delta` (with `usage`) and `message_stop`: N + 5 events.
- Any other JSON object: 200 with a message as JSON (`Content-Length`).

On `POST /v1/responses`, with the event types and fields of `openapi.yaml`
in [openai/openai-openapi](https://github.com/openai/openai-openapi) (read
at commit `33248a6`, 2026-10-19):

- A JSON body with `"stream": true`: 200, `text/event-stream`, chunked. Each
  event has an `event:` line with its type and a `data:` line whose JSON
  has the same `type` and a `sequence_number` that counts from 0. The
  events are `response.created` and `response.in_progress` (the `Response`
  object in status `in_progress`, `usage` null),
  `response.output_item.added`, `response.content_part.added` and N
  `response.output_text.delta` events with the text. For the terminal
  event `completed` or `incomplete` follow `response.output_text.done`,
  `response.content_part.done`, `response.output_item.done` and
  `response.completed` or `response.incomplete`, which carries the whole
  `Response` object with the output text and `usage` (`input_tokens`,
  `input_tokens_details`, `output_tokens`, `output_tokens_details`,
  `total_tokens`): N + 8 events. For `failed`, `response.failed` follows
  the deltas, with status `failed`, an `error` and `usage` null: N + 5
  events.
- Any other JSON object: 200 with a `Response` object as JSON (status
  `completed`, `Content-Length`).

On both paths, without `--one-write`, each event is one chunk written with
one write; the response head goes with the first event and the last chunk
with the last event. A body that is not a JSON object gets a 400 with an
`invalid_request_error` in the error format of the API. Another path gets
a 404 (Anthropic format), and `GET /_mock/stats` its counters as JSON
(below).

The answer depends only on the request and the options: the model is the
request's `model`, `input_tokens` is the request body's size in bytes / 4
(rounded up), `output_tokens` is N (6 for an answer without a stream), the
ids and times of a `Response` are fixed, and there are no sleeps but
`--delay-ms`. The drivers and the case compute the expected response with
the same code (`MockLLM.stream_body`, `MockLLM.answer_body`)
and compare it byte for byte. Responses also carry `x-mock-port` (the port
that answered) and, when the request had them, `x-mock-authorization` and
`x-mock-x-api-key` with the values that arrived, so that a test can see
which credential the proxy sent.

The mock never closes an idle keep-alive connection. It closes one only when
the request has `Connection: close` (the answer then has it too), when the
other side closes it, and for `--hold-after` and `--reset-after`. The
counters of `GET /_mock/stats`:

| Counter | Meaning |
|---|---|
| `connections_open` | connections open now, without the one asking |
| `connections` | connections accepted |
| `requests` | `POST /v1/messages` and `POST /v1/responses` requests read |
| `completed` | answers written in full (error statuses included) |
| `held` | streams waiting in `--hold-after` now |
| `held_closed` | streams in `--hold-after` that the other side closed |
| `reset` | connections reset by `--reset-after` |
| `write_failed` | answers cut short because the other side had closed the connection |

## Soak test for memory

An nginx worker serves requests for days. Anything that a finished request
leaves behind in the worker (a GC root, a live mruby object, a timer, a file
descriptor, a connection, heap memory) adds up over the life of the worker.
The soak test sends many requests to one location per scenario and checks
that none of these grows. CI runs it in the `soak` job.

### What it measures

`test/soak/soak.rb` starts nginx (`master_process on`, one worker) for each
scenario, checks one response, sends `SOAK_WARMUP` requests, and then sends
`SOAK_N` requests in three windows of `SOAK_N / 3`. It takes a sample after
the warmup and after each window, four samples in all. Before each sample it
closes all of its connections and waits (up to 5 seconds) until `stub_status`
shows that the only open connection is the one asking for it. A sample is:

| Column | Source | Pass condition |
|---|---|---|
| `gc_live` | `Nginx::Debug.stats` (below), read after `Nginx::Debug.gc` | same in all samples |
| `gc_root` | same | same in all samples |
| `fibers` | `gc_root_fibers` of the same | same in all samples |
| `arena` | `gc_arena_idx` of the same | same in all samples |
| `timers` | `timers` of the same | 0 in all samples |
| `fd` | entries in `/proc/<worker>/fd` | `fd` minus `up` the same in all samples |
| `up` | `connections_open` of the mock LLM (0 in a scenario without one) | at most `SOAK_CONCURRENCY`; 0 in the `abort` and `cut` scenarios |
| `active` | `Active connections` of `stub_status` | 1 in all samples |
| `rss_kb` | `VmRSS` in `/proc/<worker>/status` | last sample minus the one before it at most `SOAK_RSS_STEP_KB`; last sample minus the first at most `SOAK_RSS_TOTAL_KB` |

The worker is in the same state at every sample: every request sent before it
has finished, and the only request running is `/debug/stats` itself. The
counters therefore do not depend on how many requests ran before:

- `gc_live` is the number of live mruby objects. `Nginx::Debug.gc` runs a
  full GC first, so the objects of finished requests are already freed.
- `gc_root` is the number of objects that ngx_mruby has registered with
  `mrb_gc_register()` and not yet unregistered, and `fibers` counts the
  fibers among them. A handler registers its fiber when it starts and
  unregisters it when it ends, so only the fiber of `/debug/stats` is left.
  ngx_mruby counts its own calls (see "The soak build and `Nginx::Debug`"
  below), so the check does not depend on how mruby stores the GC roots.
- `arena` is the depth of the mruby GC arena while `/debug/stats` runs. Each
  code path that saves the arena restores it.
- `timers` counts the `Nginx::Async.sleep` timers that have neither fired nor
  been deleted. No request is waiting, so there are none.
- `fd` is read after the `/debug/stats` connection closed, so it counts the
  listening sockets, the log files and nginx's own descriptors. `active` comes
  from the `/status` request, the only open connection at that time. A socket
  or file that a request leaves open adds one to them.
- `up` is the number of connections open at the mock LLM, which nginx's
  upstream keeps for the next requests. Their number is the number of
  upstream connections that were in use at the same time at the busiest
  moment so far: it can grow by one in a later window that happens to be
  busier, and each of them is also in `fd`. The soak therefore compares `fd`
  minus `up` between samples, and bounds `up` by the number of client
  connections. In the `abort` and `cut` scenarios no response ends normally,
  so nginx keeps no upstream connection: the soak waits (up to 5 seconds)
  until `up` is 0 and fails the sample otherwise.

`VmRSS` is not exact, so it is bounded instead of compared. The soak build
calls `malloc_trim(0)` in the full GC before each sample (see below), which
returns the free pages of the C heap; without it, VmRSS moved by up to about
1 MB in both directions between samples of a correct build, depending on
where the allocator happened to leave free memory.

A scenario of `test/soak/nginx.conf` also checks `Nginx::Debug` itself, once,
after its first response and before the warmup. It requests `/debug/check`,
whose code runs `Nginx::Debug.gc`, reads `Nginx::Debug.stats`, makes two
Strings that nothing references in each of the 1000 rounds of a loop, and reads
`gc_live` again before and after a second `Nginx::Debug.gc`. The scenario
fails unless `Nginx::Debug.stats` has the keys listed in "The soak build and
`Nginx::Debug`" below (with `gc_root_mruby` and `gc_root_fibers_mruby`
either both present or both absent) and only Integer values,
`Nginx::Debug.gc` returns `nil`, `gc_live` grew by 1000 or more with the
Strings, and the second full GC brought it down by 1000 or more, to at most
10 above the first read. The code makes the Strings between `GC.disable`
and `GC.enable`: with about 1000 live objects after a full GC, mruby's
incremental GC would otherwise start within the loop and free most of the
Strings before the second read. Without
this check, a `Nginx::Debug.stats` that left out a key, or a
`Nginx::Debug.gc` that freed nothing, would make every sample the same and
the soak would pass.

A scenario also fails when a response is not the expected one, when nginx does
not exit within 30 seconds of `SIGQUIT`, or when its `error.log` or stderr
contains `open socket`, `[error]`, `[alert]`, `[crit]`, `[emerg]`,
`runtime error:` or `Sanitizer`. ngx_mruby logs an exception raised in a
handler at the `error` level, and the `disconnect` client reads only its first
response, so the log is where an exception in its later requests shows. A
scenario can list lines that nginx logs at the `error` level on purpose
(`allowed_log` in `test/soak/scenarios.rb`); they are left out before the
check. The exit status is 1 when any scenario fails.

The default scenarios, each one location in `test/soak/nginx.conf`:

| Scenario | Handler | Client |
|---|---|---|
| `hello` | `Nginx.rputs` | keep-alive |
| `headers` | reads 3 request headers, sets 2 response headers | keep-alive |
| `var` | reads 2 variables with `Nginx::Var`, sets 1 | keep-alive |
| `filter` | `mruby_output_body_filter_code` rewrites a `return 200` body | keep-alive |
| `sleep` | `Nginx::Async.sleep 1`, then the body | keep-alive |
| `sub_request` | `Nginx::Async::HTTP.sub_request` to a location that proxies to the static location of a second server (port base + 1) | keep-alive |
| `file` | `mruby_content_handler` with a file and `cache` | keep-alive |
| `disconnect` | `Nginx::Async.sleep 50`, then the body | one request per connection, closed without reading the response |

and four agent proxy scenarios, each in `/v1/route` or
`/v1/responses/route` of `test/soak/nginx.agent.conf` (see "Agent proxy
scenarios" below) in front of the mock LLM:

| Scenario | Mock | Client |
|---|---|---|
| `agent_stream` | streams of 50 `content_block_delta` events (55 events) | keep-alive; every stream is compared byte for byte |
| `agent_client_abort` | writes 10 events, then holds the stream until nginx closes the connection | one request per connection: reads the head and the first 3 events, checks them, closes |
| `agent_upstream_reset` | writes 10 events, then resets the connection | one request per connection: reads to EOF and checks that the body is exactly the 10 events, without the end of the chunked body |
| `agent_responses_stream` | Responses streams of 50 `response.output_text.delta` events and `response.completed` (58 events), through `/v1/responses/route` | keep-alive; every stream is compared byte for byte |

Keep-alive clients are `SOAK_CONCURRENCY` connections, each sending its next
request after reading the response; every response is checked. The
`disconnect` client sends bursts of 16 requests per thread every 100 ms, which
keeps the number of requests open at once the same in every window. The
`agent_client_abort` (mode `:abort`) and `agent_upstream_reset` (mode
`:cut`) clients are `SOAK_CONCURRENCY` threads, each sending one request per
connection and checking what arrives.

### Agent proxy scenarios

`test/soak/nginx.agent.conf` is a configuration of its own, for the soak
test and the performance comparison. It has no mruby filter directive: one
body filter directive anywhere in an `http {}` block installs ngx_mruby's
body filter for every response of that block (as the `filter` scenario does
in `test/soak/nginx.conf`), and each chunked response, such as a stream,
would then pass it and log a notice. Its `error_log` is at `warn`. The
proxy settings are those of an agent proxy: `proxy_buffering off`,
`proxy_buffer_size 4k`, `proxy_http_version 1.1`, the client's
`Authorization` replaced by the credential that a handler picked, and an
`upstream` block with `keepalive 32`, `keepalive_requests 1000000` and
`keepalive_timeout 1h`, so that nginx does not close idle connections to
the mock during a scenario either. The handlers are in `test/soak/handlers/`:

- `agent_init.rb` (`mruby_init_worker`): the client key, credential and
  model tables;
- `agent_auth.rb` (server rewrite handler of the server `auth.agent.test`):
  looks up the client key from `Authorization` or `x-api-key` (two Hash
  lookups) and sets three variables;
- `agent_route.rb` (access handler of `/v1/route` and
  `/v1/responses/route`, with `mruby_enable_read_request_body on`):
  `JSON.parse(r.body)["model"]`, one Hash lookup, and `$agent_backend` for
  `proxy_pass http://$agent_backend`.

`/v1/plain` and `/v1/route` proxy to the mock's `/v1/messages`, and
`/v1/responses/plain` and `/v1/responses/route` to its `/v1/responses`.
The request bodies are Messages requests of exactly 2 KB or 64 KB, and
Responses requests of exactly 2 KB for the `responses_*` and
`agent_responses_*` scenarios (`MockLLM.request_body`, with `api:
:responses`); `"model"` is the first key of each, and the bodies of the
streams have `"stream": true`. The abort and reset scenarios have no
Responses counterpart: nginx relays the bytes of either API the same way.
In each `agent_*` scenario the soak starts the mock (port base + 2) before
nginx, and after the last sample checks its counters: it read exactly the
requests that the soak sent (1 + `SOAK_WARMUP` + `SOAK_N`), and every one of
them ended as the scenario makes it end: written in full (`agent_stream`),
held until nginx closed the connection or found closed while the mock was
still writing (`agent_client_abort`), or reset (`agent_upstream_reset`).
The mock's output goes to `logs/mock.<scenario>.log`.

`agent_upstream_reset` allows two lines at the `error` level, both about the
upstream connection of `/v1/messages` at the mock: `recv() failed (104:
Connection reset by peer)` (nginx logs errors of upstream connections at the
`error` level, and those of client connections at `info`), and `upstream
prematurely closed connection`, which nginx logs for an upstream that closes
in the middle of a response in unbuffered mode. In the runs so far only the
first appeared, with "while reading upstream" or "while sending to client"
as the action. `agent_client_abort` logs nothing at `warn` or above.

### The soak build and `Nginx::Debug`

`test/soak/run.sh` builds with `test/build_release.sh` in `build_soak/` (see
"Release builds" below): nginx and ngx_mruby with `-O2 -g`, without
`MRB_GC_STRESS` and without `--with-debug`, and with the gems of
`build_config.rb` at the commits of `build_config.rb.lock`. It adds two
defines. ngx_mruby is compiled with
`-DNGX_MRUBY_DEBUG_STATS`, and mruby with `-DMRB_USE_MALLOC_TRIM`, so
`mrb_full_gc()` also calls `malloc_trim(0)`. mruby runs a full GC only when
it is asked to (`GC.start`, `Nginx::Debug.gc`) or in rare cases (an
incremental GC that finds too many objects, a failed allocation), so the
worker behaves as without it between samples.

`-DNGX_MRUBY_DEBUG_STATS` adds the class `Nginx::Debug`. The default builds
of `build.sh` and `test.sh` do not have it.

- `Nginx::Debug.gc` runs a full GC (`mrb_full_gc`) and returns `nil`.
- `Nginx::Debug.stats` returns a Hash with these Symbol keys:
  - `gc_live`: `mrb->gc.live`.
  - `gc_root`: the objects that ngx_mruby has registered with
    `mrb_gc_register()` and not yet unregistered with `mrb_gc_unregister()`,
    one per call, in the whole nginx process: the registrations of the http
    module and those of the stream module are counted together. Immediate
    values are not counted, because mruby does not register them. The value
    is negative when ngx_mruby unregistered more than it registered.
  - `gc_root_fibers`: the fibers among the objects counted in `gc_root`.
  - `gc_arena_idx`: `mrb->gc.arena_idx`.
  - `timers`: the `Nginx::Async.sleep` timers that have neither fired nor
    been deleted.
  - `gc_root_mruby` and `gc_root_fibers_mruby`: the length of mruby's own
    `_gc_root_` array in the mrb_state of the http module, and the fibers in
    it. mruby 3.x and 4.0 create that array at the first `mrb_gc_register()`
    of the mrb_state; mruby 4.1 keeps the GC roots in `mrb->gc.root`
    instead, and the two keys are then left out. Unlike `gc_root`, they
    include the objects that mruby and the gems register, and they do not
    include the registrations of the stream module. The soak test does not
    check them: they are there to compare with `gc_root` on the mruby
    versions that have the array. The two can differ on mruby 4.0: its
    `mrb_gc_unregister` removes every entry of the object from the array,
    while mruby 3.x removes one entry, and none when the object is not in
    the array. The counter subtracts one per call on every version, so on
    mruby 4.0 `gc_root_mruby` is lower than `gc_root` once an object that
    was registered more than once has been unregistered once.

`gc_root` and `gc_root_fibers` do not read the GC roots from mruby, because
mruby 4.1 no longer keeps them in the `_gc_root_` array: a count read from
the array would be 0 in every sample, and the soak would pass without
checking anything. With `-DNGX_MRUBY_DEBUG_STATS`,
`src/http/ngx_http_mruby_debug.h` defines `mrb_gc_register` and
`mrb_gc_unregister` as macros that call the mruby function and then count
the call, so every call in a source file that includes the header is
counted, including a call added later. A `.c` file in `src/http/` or
`src/stream/` that calls either function must therefore include
`ngx_http_mruby_debug.h`; `test/soak/run.sh` checks this before it builds
and stops otherwise. Without the define, the header defines no macro and the
calls go to mruby directly.

### Running it

The driver reads `/proc` and needs Linux and CRuby 3.0 or later. On other
systems, run it in a container, for example:

```console
$ docker run --rm -v "$PWD":/work -w /work ubuntu:22.04 sh -c 'apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y build-essential rake ruby bison git gperf wget ca-certificates zlib1g-dev libpcre3-dev libssl-dev >/dev/null && sh test/soak/run.sh'
```

On Linux:

```console
$ sh test/soak/run.sh                                  # build, then run the default scenarios
$ ONLY_RUN=1 sh test/soak/run.sh                       # run without building
$ ONLY_RUN=1 SOAK_SCENARIOS=sleep,disconnect SOAK_N=100000 sh test/soak/run.sh
```

The first run takes a few minutes (it clones the gems and builds mruby and
nginx); the scenarios themselves take about a minute (the `agent_*` ones
about 18 seconds of it, on the aarch64 container). The table has one row
per scenario; when a value differs between samples, all four values are shown,
separated by `/`, and the reasons are listed below the table. The logs are in
`build_soak/nginx/soak/logs/`: `error.<scenario>.log`,
`stderr.<scenario>.log`, `mock.<scenario>.log` (the mock LLM's output, for
the `agent_*` scenarios) and `soak.log` (the output of the driver).

`test.sh` stops only the nginx that it started ("Stopping nginx" above),
and its ports are not those of the soak.

| Variable | Default | Meaning |
|---|---|---|
| `ONLY_RUN` | unset | set to skip the build |
| `NUM_THREADS_ENV` | half of the CPUs | build parallelism (passed to `build.sh`) |
| `SOAK_SCENARIOS` | the default set | comma-separated scenario names |
| `SOAK_N` | 20000 | requests per scenario after the warmup |
| `SOAK_WARMUP` | 2000 | requests before the first sample |
| `SOAK_CONCURRENCY` | 8 | connections (threads, for `disconnect`) |
| `SOAK_PORT_BASE` | 12360 | port of the scenarios; the backend of `sub_request` uses the next one, the mock LLM the one after |
| `SOAK_RSS_STEP_KB` | 512 | VmRSS limit for the last window, in kB |
| `SOAK_RSS_TOTAL_KB` | 1024 | VmRSS limit from the first to the last sample, in kB |

### Thresholds and calibration

The two VmRSS limits were set from runs of the default scenarios on
2026-10-03 with nginx 1.31.6 on Ubuntu 22.04 (gcc 11, glibc 2.35): in a
container on aarch64, and in the CI `soak` job on x86_64. The values are the
largest over all scenarios and runs of a row:

| Runs | Growth in the last window | Growth from the first sample |
|---|---|---|
| aarch64, 3 runs, `SOAK_N=20000`, without `MRB_USE_MALLOC_TRIM` | +144 kB | +212 kB (drops down to -1076 kB) |
| aarch64, 1 run, `SOAK_N=100000`, without `MRB_USE_MALLOC_TRIM` | +288 kB | +3396 kB (`disconnect`) |
| aarch64, 10 runs, `SOAK_N=20000` | +112 kB (`sub_request`) | +204 kB (`sleep`) |
| aarch64, 1 run, `SOAK_N=100000` | +68 kB (`file`) | +160 kB (`file`) |
| x86_64 (CI), 4 runs, `SOAK_N=20000` | +144 kB (`filter`) | +236 kB (`sleep`) |
| aarch64, 3 runs, `SOAK_N=20000`, the `agent_*` scenarios (2026-10-04) | +28 kB (`agent_stream`) | +32 kB (`agent_upstream_reset`) |
| x86_64 (CI), runs 37152930938 and 37156005549, `SOAK_N=20000`, the `agent_*` scenarios (2026-10-04) | +16 kB (`agent_stream`, `agent_client_abort`) | +84 kB (`agent_stream`, `agent_client_abort`) |

Without `malloc_trim(0)`, the `disconnect` scenario at `SOAK_N=300000` moved
by +2832, -788 and +1088 kB from window to window, which is over a 512 kB
limit for the last window, although its counters stayed the same and it grew
less in all than at `SOAK_N=100000`. With it, the largest growth is 144 kB in
the last window and 236 kB in all. The default limits, 512 kB for the last
window and 1024 kB in all, are about 3.5 and 4.3 times these. The limit for
the last window is the looser one because one window of a shared CI runner
grew by 144 kB; the limit in all is the one that finds small leaks: a leak
below about 50 bytes per request stays under 1024 kB over the 20000 requests
of the default `SOAK_N`, so raise `SOAK_N` to look for smaller ones. For
comparison, a build that leaks 4 kB per request grows by about 26 MB per
window.

### Adding a scenario

1. Add a location to `test/soak/nginx.conf` (and a handler file to
   `test/soak/handlers/` if it uses one). Use `__SOAK_HANDLERS__` for the path
   of that directory and `__SOAK_BACKEND_PORT__` for the second server. A
   scenario behind the mock LLM goes to `test/soak/nginx.agent.conf`
   instead, with `__SOAK_MOCK_PORT__` for the mock.
2. Add a `Scenario` to `SCENARIOS` in `test/soak/scenarios.rb` with the
   path, the request headers, the expected body and response headers, and
   the mode (`:keepalive`, `:disconnect`, `:abort` or `:cut`). A scenario of
   the agent template also sets `conf: 'nginx.agent.conf'`, the request
   method and body, and `mock:` with the options of the mock (`[]` for the
   defaults); the comment at the top of that file lists the fields.
3. Add its name to `DEFAULT_SCENARIOS` in `test/soak/soak.rb`, run the soak
   three times, and check that all counters stay the same and that VmRSS
   stays within the limits. If a counter keeps growing, the scenario has
   found a problem: do not raise a limit or drop the comparison to make it
   pass. Report it as described in `SECURITY.md` when it may be a
   vulnerability.
4. A `:keepalive` scenario can also be measured by the performance
   comparison (below): add its name to `DEFAULT_SCENARIOS` in
   `test/perf/perf.rb` and run the null comparison of "Thresholds and
   calibration" there.

## Release builds

`sh test/build_release.sh SOURCE_DIR BUILD_DIR` builds nginx with ngx_mruby
as a static module with release-like options: nginx and ngx_mruby with
`-O2 -g`, mruby with the flags of its gcc toolchain (`-O3 -g`), without
`MRB_GC_STRESS` (which `test.sh` adds) and without `--with-debug`, and with
the gems of `build_config.rb` at the commits of a gem lock (below). The soak
test and the performance comparison
build with it, each in directories of their own, so that their options do
not mix:

| Build | Directory | Options added |
|---|---|---|
| soak (`test/soak/run.sh`) | `build_soak/` | `-DNGX_MRUBY_DEBUG_STATS` for ngx_mruby (`RELEASE_CC_OPT`), `-DMRB_USE_MALLOC_TRIM` for mruby (`NGX_MRUBY_CFLAGS`) |
| perf (`test/perf/run.sh`, `test/perf/compare.sh`) | `build_perf/head/`, `build_perf/base/` | none: both defines add code to the process under measurement |

`SOURCE_DIR` is the checkout to build, and its own build files are used
(`build.sh`, `configure`, `build_config.rb`, ...), so the base of a pull
request is built the way it builds itself. The script copies the sources to
`BUILD_DIR/tree`, runs `build.sh` there and installs nginx to
`BUILD_DIR/nginx`, so the `build/` directory, `mruby/build` and the generated
`Makefile`, `config` and `mrbgems_config` of `test.sh` are not touched. The
build is always a static module built from its own nginx source with the
system OpenSSL, so the script ignores `BUILD_DYNAMIC_MODULE`, `NGINX_SRC_ENV`
and `OPENSSL_SRC_VERSION`. The nginx source is downloaded to
`BUILD_DIR/tree/build/`; when nginx.org is unreachable, put it there as
described in `AGENTS.md`.

The third-party gems are built at the commits of the `build_config.rb.lock`
committed in `SOURCE_DIR` (see "Gem commits" in `docs/install/README.md`), or
of the lock that `RELEASE_GEM_LOCK` names when it is set and not empty.
`test/soak/run.sh` and `test/perf/run.sh` pass `RELEASE_GEM_LOCK` on from
the environment, so `RELEASE_GEM_LOCK=/path/to/other.lock sh
test/soak/run.sh` builds other commits without a change to the checkout. A
checkout that has no lock (one from before the lock was committed) gets the
head of each gem's branch on its first build. rake writes the commits it
built to `BUILD_DIR/tree/build_config.rb.lock`.

Later runs update the copy and rebuild only what changed:

- A file is written to the copy only when its content differs, and it gets
  the time of the copy, not that of `SOURCE_DIR`. A checkout made with
  `git archive` has the time of the commit, which can be older than the
  objects of the last build, and make would not rebuild it.
- Files that no longer exist in `SOURCE_DIR` are removed from the copy.
- make does not track the headers in `src/` and `dependence/`, so when one
  of them changed, the `.c` files there are touched.
- Files are overwritten in place, not removed and created again. With the
  sources on a case-insensitive file system shared with a container (Docker
  Desktop on macOS), rake loads mruby's `Rakefile` as `rakefile`, and after
  the file had been removed and created again, a second run in the same
  container failed with `LoadError: cannot load such file -- .../rakefile`.

make and rake do not notice every change, though: the objects of a removed
source or a dropped gem stay in `libmruby.a`, and nginx's configure does not
run again. The script therefore records these inputs in
`BUILD_DIR/build_stamp`: the mruby tree (its git tree id when `SOURCE_DIR` is
the top of a git work tree, else a checksum of its files without
`mruby/build` and `mruby/bin`, the output of the `test.sh` build), the file
names under `mrbgems/`, checksums of `build_config.rb`, `config.in`,
`configure`, `Makefile.in`, `build.sh` and `nginx_version`,
`NGX_MRUBY_CFLAGS` (passed to mruby, as with `test.sh`), the
nginx configure options and the gem lock of the build. When the stamp
differs from that of the last build, mruby and nginx are built from scratch,
with new clones of the gems; the downloaded nginx source is kept. The new
clones matter when only the lock changed: rake checks an existing clone out
at the commit of the lock without fetching, and an older clone may not have
that commit. After a change that the stamp
does not cover, for example an uncommitted change under `mruby/` (the git
tree id is that of the commit), reset the build by hand with
`rm -rf build_soak` (or `build_perf`).

## Performance comparison with callgrind

A change to the request path can make every request do more work without
failing any test. The performance comparison counts the instructions that
nginx executes per request (callgrind's `Ir`) in the base and the head of a
pull request, both release builds, and reports the change per scenario.
Instruction counts do not depend on the speed or the load of the machine, so
the comparison works on shared CI runners, whose throughput varies by more
than 30% (section 3.7 of `docs/proposals/v3-plan.md`). They do not show cache misses, branch mispredictions
or the time spent in the kernel: they measure how much work the user-space
code of nginx, ngx_mruby, mruby and the C library does for a request.

### What it measures

The scenarios are those of the soak test that use keep-alive clients:
`hello`, `headers`, `var`, `filter`, `sleep`, `sub_request` and `file` (see
the table in "Soak test for memory"), and the agent proxy scenarios of "Agent
proxy scenarios" below; `disconnect` is not measured. For each scenario, and
for the base and the head in turn, `test/perf/perf.rb`:

1. starts the mock LLM when the scenario has one, and nginx with
   `test/soak/nginx.conf` (or the scenario's template), changed to
   `master_process off`, under `valgrind --tool=callgrind --instr-atstart=no`,
   so that the startup runs without instrumentation;
2. checks one response and sends `PERF_WARMUP` requests;
3. waits until `stub_status` shows no open connection of the warmup, and
   switches the instrumentation on with `callgrind_control --instr=on`;
4. sends `PERF_N` requests over keep-alive and checks every response. nginx
   closes a connection after 1000 requests (`keepalive_requests`), and the
   client then opens the next one;
5. writes the profile with `callgrind_control --dump`, and stops nginx.

The profile of step 5 holds the cost of the requests of step 4: not the
startup, the configuration, the warmup or the exit. **Ir per request** is
its total Ir divided by `PERF_N`. The alternative, the difference of two runs
with N and 2N requests divided by N, needs three times as many requests and
adds the variation of two runs; the window of one run has nothing but the
requests in it.

callgrind_control reaches the process through valgrind's gdbserver (`vgdb`),
which does not serve a process that valgrind forked, such as an nginx
worker. With `master_process off`, the one nginx process runs the event loop
and the handlers as a worker does. When vgdb may not use ptrace to interrupt
a process that waits in `epoll_wait`, a command runs the next time the
process runs code, so `perf.rb` sends a request to `/status` (`stub_status`)
every 0.2 seconds until the command has run. Parts of these requests (two
per window in the runs so far) fall into the window.

**Ir per request without GC** leaves out the cost of mruby's garbage
collector: the inclusive cost of the calls into `mrb_incremental_gc` and
`mrb_full_gc` made from outside the collector (from `mrb_obj_alloc`, the
malloc wrappers, `GC.start`). It is the inclusive cost that
`callgrind_annotate --inclusive=yes` prints for `mrb_incremental_gc` and
`mrb_full_gc` without a recursion suffix (`'2`), without counting twice a
full GC that `mrb_incremental_gc` runs; `perf.rb` reads it from the call
records of the profile (see the comment of `parse_profile`). The GC runs in
bursts: `mrb_obj_alloc` calls the collector when the number of live objects
passes a threshold, and one cycle (root scan and marking, then sweeping) is a
few calls. In `hello`, 20000 requests make 21 calls, about one cycle per
2000 requests, and the GC is about 6% of the total. A change that allocates a
few objects more or less per request moves the cycles against the window,
and the total moves by a share of one cycle. The number without GC does not
have that step, so the thresholds apply to it; the total is reported as
well.

The GC also changes the cost of the rest: after a sweep has freed many
blocks, the next `malloc` calls of the request code take longer. The window
therefore has to span many GC cycles. With `PERF_N=20000`, `hello` measured
11039 Ir per request without GC, and 11049 (+0.1%) with the window moved by
5000 requests (`PERF_WARMUP=7000`); with `PERF_N=1000` and
`PERF_WARMUP=200`, a window shorter than one cycle, it measured 10726 and
10732 in two runs (-2.8%). That is why `PERF_N` is 20000.

### Agent proxy scenarios in the comparison

These scenarios measure what an agent proxy costs per request: nginx in
front of the mock LLM (see "Mock LLM upstream"), with `test/soak/nginx.agent.conf`
(see "Agent proxy scenarios" in the soak section). The scenarios without
Ruby are the baselines of the scenarios of the same shape, so that the
difference between the two is what the Ruby adds. The last row of the table
is the seven scenarios of `test/soak/nginx.conf`, for their request
function.

| Scenario | Request and answer | Ruby per request | Request function (calls per request) |
|---|---|---|---|
| `proxy_plain_2k`, `proxy_plain_64k` | POST of a Messages body of exactly 2 KB or 64 KB to `/v1/plain` (`proxy_pass` to the mock); a JSON message | none | `ngx_http_log_request` (1) |
| `proxy_stream_plain_50`, `proxy_stream_plain_1000` | the 2 KB body with `"stream": true` to `/v1/plain`; a stream of 50 or 1000 deltas (55 or 1005 events) | none | `ngx_http_log_request` (1) |
| `responses_stream_plain_50`, `responses_stream_plain_1000` | a 2 KB Responses body with `"stream": true` to `/v1/responses/plain` (`proxy_pass` to the mock's `/v1/responses`); a Responses stream of 50 or 1000 deltas and `response.completed` (58 or 1008 events) | none | `ngx_http_log_request` (1) |
| `auth` | `proxy_plain_2k` to the server `auth.agent.test`, whose server rewrite handler `agent_auth.rb` looks up the client key and sets the upstream credential | 1 handler | `ngx_http_log_request` (1) |
| `route_json_2k`, `route_json_64k` | `proxy_plain_*` to `/v1/route`, whose access handler `agent_route.rb` parses the body with `JSON.parse` and sets the upstream block for `proxy_pass http://$agent_backend` | 1 handler | `ngx_http_log_request` (1) |
| `ruby_call_1`, `ruby_call_10` | GET of a location with 1 or 10 `mruby_set_code` variables and `return 200`; no upstream | 1 or 10 calls | `ngx_http_mruby_set_inline_handler` (1 or 10) |
| `hello`, `headers`, `var`, `filter`, `sleep`, `sub_request`, `file` | GET of the locations of `test/soak/nginx.conf` (see "Soak test for memory"); no mock | 1 handler or filter | `ngx_mrb_start_fiber` (1) |

The seven scenarios of `test/soak/nginx.conf` count `ngx_mrb_start_fiber`:
`ngx_mrb_run`, which runs the Ruby code of a handler or filter, starts one
fiber for each run, and nothing else calls `ngx_mrb_start_fiber`. They do
not count `ngx_mrb_run`, because callgrind does not record its calls the
same way in every build. In the aarch64 build of `next` at `45c9e52`
(2026-10-04), it recorded a second call of `ngx_mrb_run` per request: in
`filter` as a call from `ngx_mrb_run` to `ngx_mrb_run'2`, which counts
once, and in the other six scenarios as a call from
`ngx_mrb_http_get_module_ctx.part.0` to `ngx_mrb_run'2`, although
`ngx_mrb_http_get_module_ctx` does not call `ngx_mrb_run`, so their
windows held two calls per request and failed the check. It recorded one
call of `ngx_mrb_start_fiber` per request in all seven, as in the x86_64
builds of the CI runner.

The scenarios with an upstream count `ngx_http_log_request`, which nginx
calls once for each request it ends, with or without Ruby (for a
subrequest only with `log_subrequest on`): the scenarios without Ruby have
no call of `ngx_mrb_start_fiber` to count, and all the scenarios with an
upstream count the same function. The `/status` requests that wake nginx for
`callgrind_control` also end in the window when they come after the
instrumentation was switched on, so the window may hold up to that many
calls more (2 per window in the runs so far). `mruby_set_code` reaches
`ngx_mrb_run` through a tail call of its handler, which callgrind does not
always record as a call of `ngx_mrb_run`: in an aarch64 build, one of the
ten calls per request of `ruby_call_10` showed as a call from the handler to
`ngx_mrb_start_fiber`, and `ruby_call_1` showed none. The `ruby_call_*`
scenarios therefore count the handler, which nginx calls through a pointer.

Two counts per request are printed after the table and kept in
`report.json`, but not checked: `ruby_calls`, the calls of
`ngx_mrb_start_fiber` (`ngx_mrb_run` starts one fiber per run of Ruby code,
and nothing else calls it; in the seven scenarios of `test/soak/nginx.conf`
the window check counts the same calls), and `non_buffered_calls`, the
calls of `ngx_http_upstream_process_non_buffered_request`, which relays an
unbuffered response. nginx calls it when the upstream connection becomes
readable and when the client connection becomes writable. One call reads
from the upstream until `recv()` would block, at most `proxy_buffer_size`
(4k) at a time, and writes what it read to the client, so the count is not
a count of 4k reads: how many calls a response takes depends on how much of
it had arrived at each call. It also differs between builds and machines:
2.00 per request for `proxy_plain_*`, `auth` and `route_json_*` in the
aarch64 container, 1.00 on the CI runner (x86_64).

Each call costs Ir. On aarch64, `proxy_stream_plain_50` (`PERF_N=2000`)
with the mock writing the stream in one write, one write per event, and one
write per event 1 ms apart made 3.00, 4.96 and 109.99 calls per request and
cost 52270, 54255 and 142740 Ir per request: about 1010 Ir per call from the
first to the second, and 850 from the first to the third. With two builds,
the line of a scenario whose calls differ gives the Ir that the difference
alone makes at 1000 Ir per call (`NON_BUFFERED_CALL_IR`), as a share of the
base without GC, and from half of `PERF_WARN_PERCENT` on it says that the
change of the scenario may come from when the response arrived. For
`proxy_stream_plain_50`, about 2 more calls per request reach `WARN` and
about 3 reach `FAIL`; between the base and the head of one run, its calls
differed by 0.01 to 0.25 per request in the null changes of "Thresholds and
calibration".

First measurement, 2026-10-04: one run of `test/perf/perf.rb` on the head
build of this checkout (`next` at `f62880c` plus the harness), nginx 1.31.6,
Ubuntu 22.04 (gcc 11, valgrind 3.18.1), container on aarch64,
`PERF_N=20000`. H is `hello` in the same run, 11856 Ir per request (11158
without GC):

| Scenario | Ir/req (w/o GC) | H | `non_buffered_calls`/req |
|---|---|---|---|
| `proxy_plain_2k` | 21952 (21952) | 1.85 | 2.00 |
| `proxy_plain_64k` | 22264 (22264) | 1.88 | 2.00 |
| `proxy_stream_plain_50` | 54294 (54294) | 4.58 | 4.97 |
| `proxy_stream_plain_1000` | 432228 (432228) | 36.5 | 38.43 |
| `auth` | 49132 (46977) | 4.14 | 2.00 |
| `route_json_2k` | 109396 (106246) | 9.23 | 2.00 |
| `route_json_64k` | 1603842 (1600216) | 135.3 | 2.00 |
| `ruby_call_1` | 11404 (10737) | 0.96 | 0 |
| `ruby_call_10` | 41541 (35237) | 3.50 | 0 |

The differences between scenarios of the same shape, from that run:

- `auth` minus `proxy_plain_2k`: 27180 Ir per request (25025 without GC),
  2.3 H, for one server rewrite handler with two Hash lookups and three
  variable assignments.
- `route_json_2k` minus `proxy_plain_2k`: 87444 (84294), 7.4 H, for one
  access handler that parses a 2 KB body, plus the `proxy_pass` with a
  variable, which looks the upstream block up by name.
- `route_json_64k` minus `proxy_plain_64k`: 1581578 (1577952), 133 H. The
  62 KB more of body cost about 24100 Ir per KB without GC.
- One more Ruby call, `(ruby_call_10 - ruby_call_1) / 9`: 3349 Ir (2722
  without GC), 0.28 H.
- One more stream event without Ruby,
  `(proxy_stream_plain_1000 - proxy_stream_plain_50) / 950`: 398 Ir, with
  the `non_buffered_calls` of that run (4.97 and 38.43 per request).

The Responses streams, 2026-10-19: one run of `test/perf/compare.sh` with
the release builds of `next` at `a466688` (base) and of the head that
added the scenarios (the same binary), nginx 1.31.6, Ubuntu 22.04 (gcc 11,
valgrind 3.18.1) in a container on aarch64, `PERF_N=20000`. The base
build measured `hello` at 11618 Ir per request (11260 without GC), and:

| Scenario | Ir/req (w/o GC) | H | `non_buffered_calls`/req |
|---|---|---|---|
| `proxy_stream_plain_50` | 53674 (53674) | 4.62 | 4.27 |
| `responses_stream_plain_50` | 55710 (55710) | 4.80 | 5.65 |
| `proxy_stream_plain_1000` | 433190 (433190) | 37.3 | 37.20 |
| `responses_stream_plain_1000` | 478098 (478098) | 41.2 | 59.46 |

One more relayed Responses event,
`(responses_stream_plain_1000 - responses_stream_plain_50) / 950`, cost
445 Ir against 399 Ir for a Messages event in the same run. A delta event
of the Responses stream is 186 to 189 bytes (its `sequence_number` grows),
one of the Messages stream 121 bytes; the body of the 1000-delta stream is
215046 bytes against 121619, and it took 59.46 relay calls per request
against 37.20.

`proxy_stream_plain_1000` and `route_json_64k` took 83 and 129 seconds per
build in that run, while all the scenarios of the default set together take
about 140 seconds, so they are not in `DEFAULT_SCENARIOS`, nor is
`responses_stream_plain_1000`; name them in `PERF_SCENARIOS`. The other
agent proxy scenarios are in the default set and add about one minute per
build.

### Thresholds and calibration

A scenario is `WARN` when its Ir per request without GC is 3% or more above
the base (`PERF_WARN_PERCENT`), and `FAIL` from 5% (`PERF_FAIL_PERCENT`).
The exit status is 1 when a scenario is `FAIL`, when a measurement fails
(`ERROR`: an unexpected response, a line at the `error` level or above in
`error.log`, a timeout, a missing dump, or a window that does not hold the
requests, see "In CI"), or when no scenario was compared. The one exception
is a base that answers with an unexpected response while the head passes,
which is what a scenario that needs a feature of the head gets: it is shown
as `n/a` and does not fail the run. That holds only when nothing else went
wrong in the base measurement. Its `error.log` may have the lines that
ngx_mruby logs when the Ruby code of a request raises (`mrb_run failed:
return 500 HTTP status code to client: error: ...`), which is what a base
that lacks a Ruby method or class of the head logs (`NoMethodError`,
`NameError`). Any other line at the `error` level or above makes the
scenario `ERROR`, for example the `connect()` or `recv()` error that nginx
logs when the mock LLM failed and nginx answered 502. So do a problem of
the mock, and more than five lines at those levels in one log: the report
shows five lines per log and does not read the rest. A directive that only
the head has stops the base at startup, which is `ERROR` as well.

The thresholds were checked with a null change on 2026-10-03: three runs of
`compare.sh` on two checkouts with the same build inputs (`next` at
`f713d4e`, and a branch that changes only `test/` and the documentation),
with nginx 1.31.6 on Ubuntu 22.04 (gcc 11, valgrind 3.18.1) in a container
on aarch64. The first run built both trees; the other two measured the same
builds again (`ONLY_RUN=1`). Change of head against base, total / without
GC:

| Scenario | Base Ir/req (w/o GC) | Run 1 | Run 2 | Run 3 |
|---|---|---|---|---|
| `hello` | 11736 (11039) | +0.002% / +0.003% | -0.000% / -0.000% | +0.008% / +0.008% |
| `headers` | 36002 (34025) | +0.002% / +0.002% | -0.002% / -0.002% | +0.000% / +0.000% |
| `var` | 21199 (19700) | -0.000% / -0.000% | +0.000% / +0.000% | +0.000% / +0.000% |
| `filter` | 14010 (13089) | -0.002% / -0.002% | -0.002% / -0.002% | +0.002% / +0.002% |
| `sleep` | 15427 (14654) | -0.006% / -0.007% | -0.002% / -0.002% | +0.000% / +0.000% |
| `sub_request` | 48710 (47538) | -0.003% / -0.004% | -0.001% / -0.001% | -0.001% / -0.001% |
| `file` | 14009 (13075) | +0.002% / +0.002% | +0.000% / +0.000% | -0.002% / -0.002% |

The largest change is 0.008%, about 1 instruction per request, more than
300 times below the 3% of `WARN`; `N` does not need to be raised. A later
run on 2026-10-04, on new builds of the same two checkouts, measured
`sub_request` at +0.076%
(47501 and 47537 Ir per request without GC) and every other scenario
within 0.011%: `sub_request`, which proxies to a second server, varies the
most, on the CI runner as well (below). A request
to `/status` that wakes `callgrind_control` costs about 12500 instructions
(the connection included), and parts of two of them are in each window, at
most about 0.01% of the smallest window (`hello`, 235 million
instructions).

The agent proxy scenarios were checked with null changes on 2026-10-04:
two in the same kind of container on aarch64, with all nine of them (the
two left out of the default set included), and the `perf` job of the pull
request that added them on the CI runner (x86_64, run 37152930938: base
`next` at `f62880c`, head the merge commit, no build input changed), with
the seven of the default set. Change of head against base, total / without
GC:

| Scenario | aarch64, same build twice (`next` at `4f29b06`) | aarch64, `compare.sh`, `next` at `f62880c` and the pull request | x86_64, CI run 37152930938 |
|---|---|---|---|
| `proxy_plain_2k` | +0.000% / +0.000% | +0.005% / +0.005% | +0.000% / +0.000% |
| `proxy_plain_64k` | +0.005% / +0.005% | +0.009% / +0.009% | -0.110% / -0.110% |
| `proxy_stream_plain_50` | +0.042% / +0.042% | +0.023% / +0.023% | -0.063% / -0.063% |
| `proxy_stream_plain_1000` | +0.004% / +0.004% | +0.007% / +0.007% | not run |
| `auth` | +0.000% / +0.000% | +0.000% / +0.000% | +0.000% / +0.000% |
| `route_json_2k` | +0.000% / +0.000% | +0.000% / +0.000% | -0.000% / -0.000% |
| `route_json_64k` | +0.000% / +0.000% | +0.000% / +0.000% | not run |
| `ruby_call_1` | +0.000% / +0.000% | +0.000% / +0.000% | +0.000% / +0.000% |
| `ruby_call_10` | +0.003% / +0.004% | +0.000% / +0.000% | +0.000% / +0.000% |

The scenarios with an upstream vary the most, and the `non_buffered_calls`
do not explain all of it. On aarch64, `proxy_stream_plain_50` moved by up
to 0.042% with its calls at 5.01 and 5.02 per request in base and head. On
the CI runner, `proxy_plain_64k` moved by -0.110% (22530 and 22506 Ir per
request) with its calls at 1.00 in both builds, and `proxy_stream_plain_50`
by -0.063% while its calls went from 4.86 to 4.94, which alone would add
about 0.14%. A second run of that job (37156005549, on the commit that
applied the review of that pull request, again with no build input
changed) measured `proxy_plain_64k` at +0.30% (22564 and 22630 Ir per
request, calls 1.00 in both builds) and `proxy_stream_plain_50` at +0.39%
while its calls went from 4.92 to 5.17, which the comparison estimated at
+0.43%; every other scenario stayed within 0.02%. Other work whose amount
depends on timing, such as how many reads the 64 KB request body takes, is
not counted. Between runs of the same build on aarch64, `auth` measured
46797 and 46977 Ir per request without GC (0.38%) and `route_json_2k`
106066 and 106246 (0.17%). The largest change between the base and the
head of one run, which the thresholds compare, is 0.39% in these runs,
about 8 times below the 3% of `WARN`. Later runs on the runner can move the
scenarios with an upstream by a few tenths of a percent as well; a change
of these scenarios near `WARN` needs a second run, and the
`non_buffered_calls` note, before it is taken as a regression.

In the `compare.sh` run, the seven scenarios of `test/soak/nginx.conf`
failed their window check in both builds on aarch64: they counted
`ngx_mrb_run` then, and callgrind recorded two calls of it per request (see
"Agent proxy scenarios in the comparison"). They count
`ngx_mrb_start_fiber` now. A null change on 2026-10-04 in the same kind of
container (`compare.sh` with `next` at `45c9e52` as the base and a branch
that changes only `test/perf/` and the documentation as the head) found
exactly 20000 calls of it in each window of the seven, in both builds, and
measured every scenario of the default set within 0.017%
(`proxy_stream_plain_50`), the seven within 0.009%.

To check that the thresholds fire, the head was a copy of the base with an
empty loop of 100 iterations (`volatile` counter) at the start of
`ngx_mrb_run`, which each of the seven scenarios of that time runs once per
request (the agent proxy scenarios came later; the `proxy_*` ones run no
Ruby, and `ruby_call_10` runs it ten times). The self cost of
`ngx_mrb_run` grew by 604 instructions per request in every scenario, and
the report showed `hello` +5.47% (`FAIL`), `filter` and `file` +4.62%,
`sleep` +4.10%, `var` +3.07% (`WARN`), `headers` +1.79% and `sub_request`
+1.26% (`ok`), the 604 instructions over the Ir per request without GC of
each scenario, and `compare.sh` exited with 1. In instructions, 3% is
about 330 per request in `hello` and 1430 in `sub_request`.

On the CI runner (ubuntu-22.04, x86_64, the same versions), the `perf` job
of the pull request that added it is the same null change: the base was
`next` at `f713d4e`, the head the merge commit. Four runs of that job, each
building both trees: runs 1 to 3 on the first commit of that pull request
(the run and two re-runs of the job), run 4 on its second commit, which
changed only the documentation:

| Scenario | Base Ir/req (w/o GC) | Run 1 | Run 2 | Run 3 | Run 4 |
|---|---|---|---|---|---|
| `hello` | 11669 (11006) | -0.003% / -0.004% | -0.003% / -0.003% | +0.000% / +0.000% | +0.000% / +0.000% |
| `headers` | 39424 (37267) | -0.002% / -0.002% | +0.000% / +0.000% | +0.000% / +0.000% | +0.000% / +0.000% |
| `var` | 22383 (20706) | +0.000% / +0.000% | +0.000% / +0.000% | +0.000% / +0.000% | +0.000% / +0.000% |
| `filter` | 14569 (13636) | +0.000% / +0.001% | +0.003% / +0.004% | +0.000% / +0.000% | +0.003% / +0.002% |
| `sleep` | 15833 (15068) | +0.006% / +0.006% | +0.000% / +0.000% | +0.001% / +0.001% | +0.002% / +0.002% |
| `sub_request` | 49996 (48854) | +0.001% / +0.001% | +0.016% / +0.016% | -0.001% / -0.001% | +0.020% / +0.021% |
| `file` | 14309 (13360) | +0.002% / +0.002% | +0.000% / +0.000% | -0.002% / -0.003% | +0.000% / +0.001% |

Two more runs of the job, on the commits that applied the reviews of that
pull request (still with no change to a build input), gave every scenario
within 0.007% except `sub_request`, at +0.005% and -0.047% (48706 and 48683
Ir per request without GC). Over the six runs up to 2026-10-04:

- Between base and head of one run, the largest change was about 0.05%
  (`sub_request`, about 23 instructions); every other scenario stayed
  within 0.007%.
- Between runs, `sub_request` measured from 48683 to 48857 Ir per request
  without GC (0.36%); every other scenario stayed within 0.015%.

`sub_request`, which proxies to a second server, is the scenario that
varies; even its largest change within a run is about 60 times below the 3%
of `WARN`. Base and head are measured in the same job, one after the other,
so it is the change within a run that the thresholds see. The numbers differ from those of
aarch64 because the instruction set differs; on x86_64, callgrind shows no
recursion suffix on the GC entry points, and the number without GC again
equals the inclusive cost of `mrb_incremental_gc` that `callgrind_annotate`
prints. The job is advisory (not needed by `ci-ok`) until it has also run on
pull requests that change the code; see "In CI" below.

### Running it

The driver needs CRuby 3.0 or later and valgrind with `callgrind_control`
and its helper `vgdb`, which work on Linux; `perf.rb` stops at once
without them. On macOS, run it in a Linux container. To compare this
checkout with `origin/next` in a container, in one command:

```console
$ rm -rf build_perf/base-src && git archive --prefix=build_perf/base-src/ origin/next | tar -x && docker run --rm -v "$PWD":/work -w /work ubuntu:22.04 sh -c 'apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y build-essential rake ruby bison git gperf wget ca-certificates zlib1g-dev libpcre3-dev libssl-dev valgrind >/dev/null && sh test/perf/compare.sh build_perf/base-src'
```

On Linux:

```console
$ sh test/perf/compare.sh build_perf/base-src          # build both, then compare
$ ONLY_RUN=1 sh test/perf/compare.sh build_perf/base-src
$ ONLY_RUN=1 PERF_SCENARIOS=hello,var sh test/perf/compare.sh build_perf/base-src
$ sh test/perf/run.sh                                  # measure this checkout only
```

`compare.sh BASE_DIR [HEAD_DIR]` builds `BASE_DIR` into `build_perf/base` and
`HEAD_DIR` (default: this checkout) into `build_perf/head`, each with the
third-party gems at the commits of the `build_config.rb.lock` committed in
it. The gems therefore differ only where the head changes the lock, and a
pull request that moves a gem to another commit is measured with that
commit, as it would be merged. A checkout that has no lock (one from before
the lock was committed) takes the lock of the other side: the base the
head's, the head the one that the base build wrote. The report says how many
gems are at different commits and lists them. The measurement (`test/perf/`, the scenarios in `test/soak/`) comes
from this checkout for both builds. The first run builds two trees (a few
minutes each); the measurement of the default scenarios takes about 140
seconds per build (139 seconds on the CI runner, 28 of them in `sleep`), and
`proxy_stream_plain_1000` and `route_json_64k` add about 80 and 130 seconds
when `PERF_SCENARIOS` names them. The report goes to `build_perf/report.txt` and
`build_perf/report.json`. `test.sh` starts its mock LLM upstream on 12372
too, so do not run it at the same time.

| Variable | Default | Meaning |
|---|---|---|
| `ONLY_RUN` | unset | set to skip the builds |
| `NUM_THREADS_ENV` | half of the CPUs | build parallelism (passed to `build.sh`) |
| `PERF_SCENARIOS` | `DEFAULT_SCENARIOS` of `test/perf/perf.rb` | comma-separated scenario names |
| `PERF_N` | 20000 | requests in the measured window |
| `PERF_WARMUP` | 2000 | requests before the window |
| `PERF_WARN_PERCENT` | 3 | WARN from this change of Ir per request without GC |
| `PERF_FAIL_PERCENT` | 5 | FAIL from this change |
| `PERF_PORT_BASE` | 12370 | port of the scenarios; the backend of `sub_request` uses the next one, the mock LLM the one after |
| `PERF_REPORT_DIR` | `build_perf` | where `report.txt` and `report.json` go |
| `PERF_REQUEST_FUNCTIONS` | `ngx_mrb_start_fiber` | names of the function counted once per request in the seven scenarios of `test/soak/nginx.conf` (see "In CI") |

### In CI

The `perf` job of `.github/workflows/test.yml` runs on pull requests that
change an input of the measured binary, the measurement or the workflow, or
that have the label `perf` (read when the job runs, so adding the label and
re-running the job is enough), and only when the `changes` job starts the
build jobs ([Which jobs a run starts](#which-jobs-a-run-starts)): a pull
request whose files are all outside the inputs of the binary and the tests
skips it, with the label too. The inputs of the binary are what
`test/build_release.sh` copies: `src/`, `mrbgems/`, `mruby/`, `dependence/`
(ngx_devel_kit, which `Makefile.in` adds to nginx), the top-level build
files `build_config.rb`, `configure`, `config.in`, `Makefile.in`,
`build.sh` and `nginx_version`, and the gem lock `build_config.rb.lock`. The
measurement is `test/perf/`,
`test/build_release.sh` and the scenario files in `test/soak/`
(`nginx.conf`, `nginx.agent.conf`, `scenarios.rb`, `http_client.rb`,
`mock_llm.rb`, `handlers/`). The job of `master` is the same, with two
differences: `master` commits no gem lock, so the lock is not an input
there, and `master` has no soak job, so its `perf` job first runs the check
of the mock LLM (`ruby test/soak/mock_llm_test.rb`) that `test/soak/run.sh`
runs on `next`; on `master` the whole of `test/soak/` is the measurement.

A change of `nginx_version` builds the head with another nginx, so its
`WARN` or `FAIL` measures nginx's own cost as well as ngx_mruby's; read the
functions of the profiles (below) before taking it as a regression of
ngx_mruby.

The checkout of a pull request is the merge commit (`refs/pull/N/merge`);
the job compares its first parent, the base branch, with the merge commit,
so the difference is the change of the pull request as it would be merged.
The table is in the job summary, with the reasons of the failed
measurements below it; `WARN`, `FAIL`, `ERROR` and `n/a` rows and a run
that compared no scenario are annotations; the job fails on `FAIL` and
`ERROR`. A measurement fails (`ERROR`) when nginx does not start or answer,
`callgrind_control` fails or times out, the dump is missing, `error.log` has
a line at the `error` level or above, or the window does not hold the
requests: 0 Ir, or not the expected calls of the scenario's request
function: exactly one call of `ngx_mrb_start_fiber` per request in the
seven scenarios of `test/soak/nginx.conf`, and in the agent proxy scenarios
the functions and counts of the table in "Agent proxy scenarios in the
comparison" (`callgrind_control` prints "OK." even when vgdb did not reach
the process, so an empty window is caught here). Only a base that answers a
scenario with an unexpected response and has no other problem than
ngx_mruby's `mrb_run failed` lines (a scenario that needs a feature of the
head; see [Thresholds and calibration](#thresholds-and-calibration-1) of
the performance comparison) gives `n/a`, and a run in which no scenario was
compared fails.

The calls of the request function are counted by name. A copy that GCC
makes of a function at `-O2` (`ngx_mrb_start_fiber.part.0`, `.isra.0`,
`.constprop.0`, `.cold`) counts as the function, and a call from one copy to
another counts once, so a change that makes GCC split or clone it does not
fail the window. A pull request that renames `ngx_mrb_start_fiber`, or
moves the start of the fiber of a Ruby run to another function, has to add
the new name to `REQUEST_FUNCTIONS` in `test/perf/perf.rb` and keep the old
one: the `perf.rb` of the head measures the base too, and a call between
two listed names counts once. GCC cannot inline `ngx_mrb_start_fiber` now,
because it is defined in `ngx_http_mruby_async.c` and called from
`ngx_http_mruby_module.c`. A change that lets the compiler inline it (for
example making it `static` in the file of its single caller, or a build
with LTO) would leave no call of it in the profile, and every window of the
seven scenarios would hold 0 calls, so such a change has to list a function
that keeps a real call.
`PERF_REQUEST_FUNCTIONS` (comma-separated) overrides the list for a local
run, `REQUEST_FUNCTION_CALLS` sets another number of calls per request
for a scenario, and `SCENARIO_REQUEST_FUNCTIONS` another function. `ruby test/perf/perf.rb --self-test` checks the name rules
and the reading of a profile on a made-up profile, without a build or
valgrind; `compare.sh` and `run.sh` run it first.

The job is advisory for now: `ci-ok` does not need it, so a `FAIL` does not
block a merge. Instruction counts do not vary with the runner's speed
(calibration above), so the plan (Pillar E of
`docs/proposals/v3-plan.md`) is to gate on them: once the job has also run
on pull requests that change `src/` or `mrbgems/` without false alarms, it
is to be added to the `needs` of `ci-ok`.

The artifact `perf-callgrind` has the report, and for `base` and `head` the
profiles of the windows (`callgrind/callgrind.out.<scenario>`), the output
of `callgrind_control` and valgrind, and the nginx logs. To see where a
change comes from, print the functions of the same scenario in both builds
and compare them:

```console
$ callgrind_annotate --inclusive=yes build_perf/head/callgrind/callgrind.out.var | head -40
$ callgrind_annotate build_perf/base/callgrind/callgrind.out.var > base.txt
$ callgrind_annotate build_perf/head/callgrind/callgrind.out.var > head.txt
$ diff base.txt head.txt
```

The counts are for the whole window; divide by `PERF_N` for one request.
KCachegrind and QCachegrind open the profiles as well.

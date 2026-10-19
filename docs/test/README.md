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

## Add a test as a fragment and a case file

Instead of editing `test/conf/nginx.conf` and `test/t/ngx_mruby.rb`, a test
can live in files of its own:

- `test/conf/conf.d/<name>.conf`: a fragment included at the end of the
  `http {}` block. It holds its own `server {}` on a port of its own (18110
  and up; 18116 is taken by the second nginx that
  `test/t/cases/_second_instance.rb` starts). Fragments for `stream {}` go
  to `test/conf/conf.d/stream/` (ports 12353 and up; 12357 is taken by the
  second nginx).
- `test/t/cases/<name>.rb`: a test file run after `test/t/ngx_mruby.rb`,
  with `test/t/cases/_prelude.rb` prepended. The prelude defines `base`,
  `base_ssl`, `http_host`, `html_path`, `nginx_t` (runs `nginx -t` on a
  generated configuration), `tcp_client` and `second_instance`. It starts
  with `SimpleTest.new` and ends with `t.report`. Files whose name starts
  with `_` are helpers and are not run as cases; `_tcp_client.rb`,
  `_filter_connection_client.rb`, `_request_body_client.rb` and
  `_second_instance.rb` are CRuby scripts that the prelude helpers and the
  cases run with `ruby`, and `_wait_for_listen.rb` is the CRuby script that
  test.sh runs to wait for nginx (see "Waiting for nginx to listen" below).
- Hook scripts go to `test/html/` as before; the fragment refers to them as
  `build/nginx/html/<name>.rb`.

`test.sh` copies the fragments into the built nginx's `conf/conf.d/` with the
same substitutions as `nginx.conf`, and runs every case file in turn. A
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
every job that it lists in `needs` succeeded. These are every job of the
`build` matrix and the `files` job, and on `next` also the `soak` job.

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
`build_dynamic/`, `build_soak/`, `build_perf/`) or `mruby/build/`, a file
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
and `test/conf/conf.d/*.conf`, the `http {}` servers (33 ports as of
2026-10). nginx opens all its listening sockets in one loop
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
$ grep -E 'AddressSanitizer|UndefinedBehaviorSanitizer|runtime error|LeakSanitizer' build/nginx/logs/error.log
```

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

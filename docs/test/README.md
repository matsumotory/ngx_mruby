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
`build` matrix and the `files` job, and on `next` also the `soak` job. The
`perf` job (see "In CI" under "Performance comparison with callgrind") is
not among them yet.

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

## Mock LLM upstream

`test/soak/mock_llm.rb` (CRuby 3.0 or later) is an HTTP/1.1 server that
answers `POST /v1/messages` the way the Anthropic Messages API does. On
`master`, it is the upstream of the agent proxy scenarios of the
performance comparison (`proxy_*`, `auth`, `route_json_*`; see
"Performance comparison with callgrind"), which `test/perf/perf.rb` starts
as a process of its own on the port base + 2 (12372) for each scenario, with
the options of the scenario (`mock` in `test/soak/scenarios.rb`). On `next`,
the memory soak test and a functional case use it as well.

```console
$ ruby test/soak/mock_llm.rb --port 12372 --events 50
```

| Option | Default | Meaning |
|---|---|---|
| `--port PORT` | (required) | listen on `127.0.0.1:PORT`; repeat it for more ports, which answer the same way |
| `--events N` | 50 | `content_block_delta` events in a stream |
| `--delta-text TEXT` | `hello ` | the text of each `content_block_delta` |
| `--hold-after K` | off | write the first K events of a stream, then nothing more until the other side closes the connection |
| `--reset-after K` | off | write the first K events of a stream, then reset the connection (RST) |
| `--status CODE` | off | answer every request with this status and an Anthropic error body (`overloaded_error` for 529, `api_error` for 503), before any event |
| `--delay-ms MS` | 0 | wait MS milliseconds between two events |
| `--one-write` | off | write the head and the whole stream with one write |

A request can override the options for itself with the headers
`x-mock-events`, `x-mock-hold-after`, `x-mock-reset-after`, `x-mock-status`
and `x-mock-delay-ms`, each a number of 0 or more. `x-mock-hold-after`,
`x-mock-reset-after` and `x-mock-status` also take `off`, which turns the
hold, the reset or the error status off; `x-mock-events` and
`x-mock-delay-ms` do not. Any other value gets a 400 answer
(`invalid_request_error`) that names the header. nginx forwards the headers
unless the configuration drops them. `ruby test/soak/mock_llm_test.rb` checks
these rules and the answers below against the mock in its own process (no
nginx, about a second); the `perf` job runs it before the comparison.

What it answers:

- A JSON body with `"stream": true`: 200, `text/event-stream`, chunked. The
  events are `message_start` (with `usage`), `content_block_start`, N
  `content_block_delta` events with the text, `content_block_stop`,
  `message_delta` (with `usage`) and `message_stop`: N + 5 events. Without
  `--one-write`, each event is one chunk written with one write; the response
  head goes with the first event and the last chunk with `message_stop`.
- Any other JSON object: 200 with a message as JSON (`Content-Length`).
- A body that is not a JSON object: 400; another path: 404.
- `GET /_mock/stats`: its counters as JSON (below).

The answer depends only on the request and the options: the model is the
request's `model`, `input_tokens` is the request body's size in bytes / 4
(rounded up), `output_tokens` is N (6 for a message), and there are no
sleeps but `--delay-ms`. `perf.rb` computes the expected response with the
same code (`MockLLM.stream_body`, `MockLLM.message_body`) and compares it
byte for byte. Responses also carry `x-mock-port` (the port that answered)
and, when the request had them, `x-mock-authorization` and
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
| `requests` | `POST /v1/messages` requests read |
| `completed` | answers written in full (error statuses included) |
| `held` | streams waiting in `--hold-after` now |
| `held_closed` | streams in `--hold-after` that the other side closed |
| `reset` | connections reset by `--reset-after` |
| `write_failed` | answers cut short because the other side had closed the connection |

## Release builds

`sh test/build_release.sh SOURCE_DIR BUILD_DIR` builds nginx with ngx_mruby
as a static module with release-like options: nginx and ngx_mruby with
`-O2 -g`, mruby with the flags of its gcc toolchain (`-O3 -g`), without
`MRB_GC_STRESS` (which `test.sh` adds) and without `--with-debug`. The script
is the one of `next`, so its header comment also names the soak build of
`next` (`test/soak/run.sh`, `-DNGX_MRUBY_DEBUG_STATS`) and
`NGX_MRUBY_AUTO_SSL`, which on `next` adds the auto-ssl mrbgem; on `master`,
`build_config.rb` always builds that gem, and the variable changes only the
build stamp. The performance comparison builds with it (`test/perf/run.sh`,
`test/perf/compare.sh`), in `build_perf/head/` and `build_perf/base/`, with
no option added: the defines of the soak build of `next`
(`-DNGX_MRUBY_DEBUG_STATS`, `-DMRB_USE_MALLOC_TRIM`) would add code to the
process under measurement.

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

The third-party gems are built at the commits of a gem lock: the one that
`RELEASE_GEM_LOCK` names when it is set and not empty, else the
`build_config.rb.lock` in `SOURCE_DIR`. `master` commits no lock (its
`.gitignore` lists the file), so a fresh checkout of `master` has none and
gets the head of each gem's branch on its first build; a checkout in which
`sh test.sh` has run has the lock that rake wrote there, with the commits of
that build. rake writes the commits it built to
`BUILD_DIR/tree/build_config.rb.lock`.

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
`NGX_MRUBY_CFLAGS` (passed to mruby, as with `test.sh`),
`NGX_MRUBY_AUTO_SSL` (see above), the nginx configure options and the gem lock of the build. When the stamp
differs from that of the last build, mruby and nginx are built from scratch,
with new clones of the gems; the downloaded nginx source is kept. The new
clones matter when only the lock changed: rake checks an existing clone out
at the commit of the lock without fetching, and an older clone may not have
that commit. After a change that the stamp does not cover, for example an
uncommitted change under `mruby/` (the git tree id is that of the commit),
reset the build by hand with `rm -rf build_perf`.

## Performance comparison with callgrind

A change to the request path can make every request do more work without
failing any test. The performance comparison counts the instructions that
nginx executes per request (callgrind's `Ir`) in the base and the head of a
pull request, both release builds, and reports the change per scenario.
Instruction counts do not depend on the speed or the load of the machine, so
the comparison works on shared CI runners, whose throughput varies by more
than 30% (section 3.7 of `docs/proposals/v3-plan.md` on `next`). They do not
show cache misses, branch mispredictions or the time spent in the kernel:
they measure how much work the user-space code of nginx, ngx_mruby, mruby
and the C library does for a request.

The comparison is the one of `next`. `master` has its files (`test/perf/`,
`test/build_release.sh`, and in `test/soak/` the configurations, scenarios,
HTTP client, handlers and mock LLM that it reads), but not the memory soak
test of `next` (`test/soak/soak.rb`, `test/soak/run.sh`) and not
`Nginx::Debug`, the Ruby class of the soak build that the soak reads: the
copies of `test/soak/nginx.conf` and `test/soak/nginx.agent.conf` on
`master` have no `/debug/stats` location, which only the soak requests. The
comparison reads none of the soak's counters, so it measures the same on
both branches.

### What it measures

The scenarios are the locations of `test/soak/nginx.conf`, each with a
keep-alive client:

| Scenario | Handler |
|---|---|
| `hello` | `Nginx.rputs` |
| `headers` | reads 3 request headers, sets 2 response headers |
| `var` | reads 2 variables with `Nginx::Var`, sets 1 |
| `filter` | `mruby_output_body_filter_code` rewrites a `return 200` body |
| `sleep` | `Nginx::Async.sleep 1`, then the body |
| `sub_request` | `Nginx::Async::HTTP.sub_request` to a location that proxies to the static location of a second server (port base + 1) |
| `file` | `mruby_content_handler` with a file and `cache` |

and the agent proxy scenarios of "Agent proxy scenarios in the comparison"
below. (`test/soak/scenarios.rb` also lists the scenarios that only the soak
of `next` runs: `disconnect` and `agent_*`, which are not keep-alive and
are not measured.) For each scenario, and for the base and the head in
turn, `test/perf/perf.rb`:

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
few calls. A change that allocates a few objects more or less per request
moves the cycles against the window, and the total moves by a share of one
cycle. The number without GC does not have that step, so the thresholds
apply to it; the total is reported as well. The GC also changes the cost of
the rest (after a sweep has freed many blocks, the next `malloc` calls take
longer), so the window has to span many GC cycles, which is why `PERF_N` is
20000 (the runs that showed it are in "Performance comparison with
callgrind" of `docs/test/README.md` on `next`).

### Agent proxy scenarios in the comparison

These scenarios measure what an agent proxy costs per request: nginx in
front of the mock LLM (see "Mock LLM upstream"), with
`test/soak/nginx.agent.conf`. That configuration has no mruby filter
directive: one body filter directive anywhere in an `http {}` block
installs ngx_mruby's body filter for every response of that block (as the
`filter` scenario does in `test/soak/nginx.conf`), and each chunked
response, such as a stream, would then pass it and log a notice. Its
`error_log` is at `warn`. The proxy settings are those of an agent proxy:
`proxy_buffering off`, `proxy_buffer_size 4k`, `proxy_http_version 1.1`,
the client's `Authorization` replaced by the credential that a handler
picked, and an `upstream` block with `keepalive 32`,
`keepalive_requests 1000000` and `keepalive_timeout 1h`. The handlers are in
`test/soak/handlers/`:

- `agent_init.rb` (`mruby_init_worker`): the client key, credential and
  model tables;
- `agent_auth.rb` (server rewrite handler of the server `auth.agent.test`):
  looks up the client key from `Authorization` or `x-api-key` (two Hash
  lookups) and sets three variables;
- `agent_route.rb` (access handler of `/v1/route`, with
  `mruby_enable_read_request_body on`): `JSON.parse(r.body)["model"]`, one
  Hash lookup, and `$agent_backend` for `proxy_pass http://$agent_backend`.

The request bodies are Messages requests of exactly 2 KB or 64 KB
(`MockLLM.request_body`). The scenarios without Ruby are the baselines of
the scenarios of the same shape, so that the difference between the two is
what the Ruby adds. The last row of the table is the seven scenarios of
`test/soak/nginx.conf`, for their request function.

| Scenario | Request and answer | Ruby per request | Request function (calls per request) |
|---|---|---|---|
| `proxy_plain_2k`, `proxy_plain_64k` | POST of a Messages body of exactly 2 KB or 64 KB to `/v1/plain` (`proxy_pass` to the mock); a JSON message | none | `ngx_http_log_request` (1) |
| `proxy_stream_plain_50`, `proxy_stream_plain_1000` | the 2 KB body with `"stream": true` to `/v1/plain`; a stream of 50 or 1000 deltas (55 or 1005 events) | none | `ngx_http_log_request` (1) |
| `auth` | `proxy_plain_2k` to the server `auth.agent.test`, whose server rewrite handler `agent_auth.rb` looks up the client key and sets the upstream credential | 1 handler | `ngx_http_log_request` (1) |
| `route_json_2k`, `route_json_64k` | `proxy_plain_*` to `/v1/route`, whose access handler `agent_route.rb` parses the body with `JSON.parse` and sets the upstream block for `proxy_pass http://$agent_backend` | 1 handler | `ngx_http_log_request` (1) |
| `ruby_call_1`, `ruby_call_10` | GET of a location with 1 or 10 `mruby_set_code` variables and `return 200`; no upstream | 1 or 10 calls | `ngx_http_mruby_set_inline_handler` (1 or 10) |
| `hello`, `headers`, `var`, `filter`, `sleep`, `sub_request`, `file` | GET of the locations of `test/soak/nginx.conf`; no mock | 1 handler or filter | `ngx_mrb_start_fiber` (1) |

The seven scenarios of `test/soak/nginx.conf` count `ngx_mrb_start_fiber`:
`ngx_mrb_run`, which runs the Ruby code of a handler or filter, starts one
fiber for each run, and nothing else calls `ngx_mrb_start_fiber`. They do
not count `ngx_mrb_run`, because callgrind does not record its calls the
same way in every build: in an aarch64 build of `next` (2026-10-04), it
recorded a second call of `ngx_mrb_run` per request in six of the seven,
and one call of `ngx_mrb_start_fiber` per request in all seven, as in the
x86_64 builds of the CI runner.

The scenarios with an upstream count `ngx_http_log_request`, which nginx
calls once for each request it ends, with or without Ruby (for a
subrequest only with `log_subrequest on`): the scenarios without Ruby have
no call of `ngx_mrb_start_fiber` to count, and all the scenarios with an
upstream count the same function. The `/status` requests that wake nginx for
`callgrind_control` also end in the window when they come after the
instrumentation was switched on, so the window may hold up to that many
calls more (2 per window in the runs so far). `mruby_set_code` reaches
`ngx_mrb_run` through a tail call of its handler, which callgrind does not
always record as a call of `ngx_mrb_run`, so the `ruby_call_*` scenarios
count the handler, which nginx calls through a pointer.

Two counts per request are printed after the table and kept in
`report.json`, but not checked: `ruby_calls`, the calls of
`ngx_mrb_start_fiber`, and `non_buffered_calls`, the calls of
`ngx_http_upstream_process_non_buffered_request`, which relays an
unbuffered response. nginx calls it when the upstream connection becomes
readable and when the client connection becomes writable. One call reads
from the upstream until `recv()` would block, at most `proxy_buffer_size`
(4k) at a time, and writes what it read to the client, so how many calls a
response takes depends on how much of it had arrived at each call. It also
differs between builds and machines (2.00 per request for `proxy_plain_*`,
`auth` and `route_json_*` in an aarch64 container, 1.00 on the x86_64 CI
runner, in the runs of `next`).

Each call costs Ir: about 1000 per call in the runs of `next`
(`NON_BUFFERED_CALL_IR` in `perf.rb`). With two builds, the line of a
scenario whose calls differ gives the Ir that the difference alone makes, as
a share of the base without GC, and from half of `PERF_WARN_PERCENT` on it
says that the change of the scenario may come from when the response
arrived. For `proxy_stream_plain_50`, about 2 more calls per request reach
`WARN` and about 3 reach `FAIL`.

`proxy_stream_plain_1000` and `route_json_64k` take more than a minute per
build each, so they are not in `DEFAULT_SCENARIOS`; name them in
`PERF_SCENARIOS`.

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

The thresholds were calibrated on `next` in October 2026, with null changes
(base and head with the same build inputs) and with a planted cost (an
empty loop of 100 iterations in `ngx_mrb_run`, which the report showed as
`WARN` and `FAIL` rows); the runs and their numbers are in "Thresholds and
calibration" under "Performance comparison with callgrind" in
`docs/test/README.md` on `next`. In those null changes, the scenarios of
`test/soak/nginx.conf` moved by at most about 0.08% between base and head
(`sub_request`, which proxies to a second server, the most), and the
scenarios with an upstream by at most 0.39% on the CI runner, more than 7
times below the 3% of `WARN`.

On `master`, two null changes on 2026-10-19 (the base `master`, the head
the pull request that added the comparison to `master`, which changed no
build input) measured:

| Scenario | aarch64: base Ir/req (w/o GC) | aarch64 container, `compare.sh` | x86_64, CI run 39240312315 |
|---|---|---|---|
| `hello` | 11853 (11173) | -0.003% | +0.000% |
| `headers` | 36364 (34388) | +0.000% | -0.001% |
| `var` | 21342 (19973) | +0.000% | +0.002% |
| `filter` | 14203 (13364) | +0.002% | +0.000% |
| `sleep` | 15661 (14888) | +0.004% | +0.000% |
| `sub_request` | 48731 (47568) | +0.002% | +0.002% |
| `file` | 14069 (13231) | +0.000% | +0.000% |
| `proxy_plain_2k` | 22102 (22102) | -0.004% | +0.001% |
| `proxy_plain_64k` | 22426 (22426) | -0.001% | -0.229% |
| `proxy_stream_plain_50` | 53135 (53135) | -0.018% | -0.119% |
| `auth` | 48206 (46038) | +0.003% | -0.001% |
| `route_json_2k` | 109332 (106191) | -0.005% | +0.000% |
| `ruby_call_1` | 11360 (10677) | +0.009% | +0.000% |
| `ruby_call_10` | 41988 (35598) | +0.001% | +0.000% |

The last two columns are the change of head against base without GC. The
first run was `compare.sh` with nginx 1.31.6 on Ubuntu 22.04 (gcc 11.4,
valgrind 3.18.1) in a container on aarch64, `PERF_N=20000`, base `master` at
`a6c32a4`; the `.text` sections of the two nginx binaries were byte for byte
the same. The second is the `perf` job of that pull request on the CI runner
(ubuntu-22.04, x86_64), base `master` at `a500846`. Both builds of each run
had the same 21 third-party gems at the same commits. The scenarios of
`test/soak/nginx.conf` and those without an upstream moved by at most
0.009%. The scenarios with an upstream moved the most: on the CI runner
`proxy_plain_64k` by -0.229% (22777 and 22725 Ir per request, its
`non_buffered_calls` 1.00 in both builds) and `proxy_stream_plain_50` by
-0.119% (its `non_buffered_calls` 4.62 and 4.54, which the report estimated
at -0.15%). The largest, 0.229%, is about 13 times below the 3% of `WARN`.
In the aarch64 container, the measurement of the default scenarios took
about 4 minutes per build, `sleep` 45 seconds of it; the `perf` job took
13 minutes, both builds included.

On `master` the absolute numbers of a scenario can differ between runs on
different days: `master` commits no gem lock, so each run builds the gems
at the heads of their branches at that time (both builds of one run at the
same commits). The change between base and head of one run is what the
thresholds compare.

### Running it

The driver needs CRuby 3.0 or later and valgrind with `callgrind_control`
and its helper `vgdb`, which work on Linux; `perf.rb` stops at once
without them. On macOS, run it in a Linux container. To compare this
checkout with `origin/master` in a container, in one command:

```console
$ rm -rf build_perf/base-src && git archive --prefix=build_perf/base-src/ origin/master | tar -x && docker run --rm -v "$PWD":/work -w /work ubuntu:22.04 sh -c 'apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y build-essential rake ruby bison git gperf wget ca-certificates zlib1g-dev libpcre3-dev libssl-dev valgrind >/dev/null && sh test/perf/compare.sh build_perf/base-src'
```

On Linux:

```console
$ sh test/perf/compare.sh build_perf/base-src          # build both, then compare
$ ONLY_RUN=1 sh test/perf/compare.sh build_perf/base-src
$ ONLY_RUN=1 PERF_SCENARIOS=hello,var sh test/perf/compare.sh build_perf/base-src
$ sh test/perf/run.sh                                  # measure this checkout only
```

`compare.sh BASE_DIR [HEAD_DIR]` builds `BASE_DIR` into `build_perf/base` and
`HEAD_DIR` (default: this checkout) into `build_perf/head`. Both builds take
the third-party gems at the same commits: a checkout without a gem lock
takes the lock of the other side (the base the head's, the head the one
that the base build wrote). On `master`, which commits no lock, the base
(made with `git archive`) has none, so it takes the lock that `sh test.sh`
left in this checkout, and when this checkout has none either (a fresh
clone, as in CI), the base is built at the head of each gem's branch and
the head takes the lock that the base build wrote. The report says how many
gems are at different commits and lists them. The measurement (`test/perf/`,
the scenarios in `test/soak/`) comes from this checkout for both builds, so
a base from before the comparison was added (a tag, for example) is
measured as well. The first run builds two trees (a few minutes each); the
measurement of the default scenarios takes about 4 minutes per build. The
report goes to `build_perf/report.txt` and `build_perf/report.json`.
`test.sh` kills every nginx on the machine, so do not run it at the same
time.

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
re-running the job is enough). The inputs of the binary are what
`test/build_release.sh` copies: `src/`, `mrbgems/`, `mruby/`, `dependence/`
(ngx_devel_kit, which `Makefile.in` adds to nginx), and the top-level build
files `build_config.rb`, `configure`, `config.in`, `Makefile.in`,
`build.sh` and `nginx_version`; `master` commits no gem lock, so on
`master` the lock is not an input (on `next`, `build_config.rb.lock` is).
The measurement is `test/perf/`, `test/build_release.sh` and `test/soak/`,
which on `master` holds only the files of the comparison. The job first
runs `ruby test/soak/mock_llm_test.rb`, the check of the mock LLM.

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
head; see "Thresholds and calibration" above) gives `n/a`, and a run in
which no scenario was compared fails.

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
that keeps a real call. `PERF_REQUEST_FUNCTIONS` (comma-separated) overrides
the list for a local run, `REQUEST_FUNCTION_CALLS` sets another number of
calls per request for a scenario, and `SCENARIO_REQUEST_FUNCTIONS` another
function. `ruby test/perf/perf.rb --self-test` checks the name rules and the
reading of a profile on a made-up profile, without a build or valgrind;
`compare.sh` and `run.sh` run it first.

`ci-ok` does not need the job yet, so a `FAIL` does not fail `ci-ok`.
"Design principles" in `AGENTS.md` still holds the merge of a pull request
whose latest `perf` run reports `FAIL` or `ERROR` (unless the owner
accepted the `FAIL` on the pull request), and a `WARN` until the owner
accepts it. The plan (Pillar E of `docs/proposals/v3-plan.md` on `next`) is
to add the job to the `needs` of `ci-ok` once it has run on pull requests
that change `src/` or `mrbgems/` without false alarms.

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

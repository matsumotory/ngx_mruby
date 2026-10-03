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
  with `_` are helpers and are not run by test.sh; `_tcp_client.rb`,
  `_filter_connection_client.rb` and `_second_instance.rb` are CRuby
  scripts that the prelude helpers run with `ruby`.
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
allocation of nginx itself would be reported; `second_instance` returns the
first sanitizer line of the second nginx's `error.log` as `sanitizer`, and
the cases print that log when the line is set.

## Testing
##### build nginx into ``./build/nginx`` and test on ``./build/nginx``
```
sh test.sh
```

If you want to run with valgrind, set the environment variables `NGINX_RUNNER` and `NGINX_HEATTIME`.

```console
$ NGINX_RUNNER=valgrind NGINX_HEATTIME=10 sh test.sh
```

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
| `fd` | entries in `/proc/<worker>/fd` | same in all samples |
| `active` | `Active connections` of `stub_status` | 1 in all samples |
| `rss_kb` | `VmRSS` in `/proc/<worker>/status` | last sample minus the one before it at most `SOAK_RSS_STEP_KB`; last sample minus the first at most `SOAK_RSS_TOTAL_KB` |

The worker is in the same state at every sample: every request sent before it
has finished, and the only request running is `/debug/stats` itself. The
counters therefore do not depend on how many requests ran before:

- `gc_live` is the number of live mruby objects. `Nginx::Debug.gc` runs a
  full GC first, so the objects of finished requests are already freed.
- `gc_root` is the length of the array that `mrb_gc_register()` appends to,
  and `fibers` counts the fibers in it. A handler registers its fiber when it
  starts and unregisters it when it ends, so only the fiber of `/debug/stats`
  is left.
- `arena` is the depth of the mruby GC arena while `/debug/stats` runs. Each
  code path that saves the arena restores it.
- `timers` counts the `Nginx::Async.sleep` timers that have neither fired nor
  been deleted. No request is waiting, so there are none.
- `fd` is read after the `/debug/stats` connection closed, so it counts the
  listening sockets, the log files and nginx's own descriptors. `active` comes
  from the `/status` request, the only open connection at that time. A socket
  or file that a request leaves open adds one to them.

`VmRSS` is not exact, so it is bounded instead of compared. The soak build
calls `malloc_trim(0)` in the full GC before each sample (see below), which
returns the free pages of the C heap; without it, VmRSS moved by up to about
1 MB in both directions between samples of a correct build, depending on
where the allocator happened to leave free memory.

A scenario also fails when a response is not the expected one, when nginx does
not exit within 30 seconds of `SIGQUIT`, or when its `error.log` or stderr
contains `open socket`, `[error]`, `[alert]`, `[crit]`, `[emerg]`,
`runtime error:` or `Sanitizer`. ngx_mruby logs an exception raised in a
handler at the `error` level, and the `disconnect` client reads only its first
response, so the log is where an exception in its later requests shows. The
exit status is 1 when any scenario fails.

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

Keep-alive clients are `SOAK_CONCURRENCY` connections, each sending its next
request after reading the response; every response is checked. The
`disconnect` client sends bursts of 16 requests per thread every 100 ms, which
keeps the number of requests open at once the same in every window.

### The soak build and `Nginx::Debug`

`test/soak/run.sh` builds with `test/build_release.sh` in `build_soak/` (see
"Release builds" below): nginx and ngx_mruby with `-O2 -g`, without
`MRB_GC_STRESS` and without `--with-debug`, and with the gems of
`build_config.rb`. It adds two defines. ngx_mruby is compiled with
`-DNGX_MRUBY_DEBUG_STATS`, and mruby with `-DMRB_USE_MALLOC_TRIM`, so
`mrb_full_gc()` also calls `malloc_trim(0)`. mruby runs a full GC only when
it is asked to (`GC.start`, `Nginx::Debug.gc`) or in rare cases (an
incremental GC that finds too many objects, a failed allocation), so the
worker behaves as without it between samples.

`-DNGX_MRUBY_DEBUG_STATS` adds the class `Nginx::Debug`. The default builds
of `build.sh` and `test.sh` do not have it.

- `Nginx::Debug.gc` runs a full GC (`mrb_full_gc`) and returns `nil`.
- `Nginx::Debug.stats` returns a Hash with the Symbol keys `gc_live`
  (`mrb->gc.live`), `gc_root` (the length of mruby's `_gc_root_` array, 0 when
  it does not exist), `gc_root_fibers` (the fibers in that array),
  `gc_arena_idx` (`mrb->gc.arena_idx`) and `timers` (the `Nginx::Async.sleep`
  timers that have neither fired nor been deleted).

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
nginx); the scenarios themselves take about 30 seconds. The table has one row
per scenario; when a value differs between samples, all four values are shown,
separated by `/`, and the reasons are listed below the table. The logs are in
`build_soak/nginx/soak/logs/`: `error.<scenario>.log`,
`stderr.<scenario>.log` and `soak.log` (the output of the driver).

`test.sh` kills every nginx on the machine, including the soak's, so do not
run both at the same time on one machine.

| Variable | Default | Meaning |
|---|---|---|
| `ONLY_RUN` | unset | set to skip the build |
| `NUM_THREADS_ENV` | half of the CPUs | build parallelism (passed to `build.sh`) |
| `SOAK_SCENARIOS` | the default set | comma-separated scenario names |
| `SOAK_N` | 20000 | requests per scenario after the warmup |
| `SOAK_WARMUP` | 2000 | requests before the first sample |
| `SOAK_CONCURRENCY` | 8 | connections (threads, for `disconnect`) |
| `SOAK_PORT_BASE` | 12360 | port of the scenarios; the backend of `sub_request` uses the next one |
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
   of that directory and `__SOAK_BACKEND_PORT__` for the second server.
2. Add a `Scenario` to `SCENARIOS` in `test/soak/scenarios.rb` with the
   path, the request headers, the expected body and response headers, and
   the mode (`:keepalive` or `:disconnect`).
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
the gems of `build_config.rb`. The soak test and the performance comparison
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
described in `AGENTS.md`. `RELEASE_GEM_LOCK` names a `build_config.rb.lock`
whose gem commits the build uses; without it, rake clones the default branch
of each gem on the first build and writes the commits to
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
`NGX_MRUBY_CFLAGS` (passed to mruby, as with `test.sh`), the nginx configure
options and the gem lock of `RELEASE_GEM_LOCK`. When the stamp differs from
that of the last build, mruby and nginx are built from scratch; the
downloaded nginx source is kept. After a change that the stamp does not
cover, for example an uncommitted change under `mruby/` (the git tree id is
that of the commit), reset the build by hand with `rm -rf build_soak` (or
`build_perf`).

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
the table in "Soak test for memory"); `disconnect` is not measured. For each
scenario, and for the base and the head in turn, `test/perf/perf.rb`:

1. starts nginx with `test/soak/nginx.conf`, changed to `master_process off`,
   under `valgrind --tool=callgrind --instr-atstart=no`, so that the startup
   runs without instrumentation;
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

### Thresholds and calibration

A scenario is `WARN` when its Ir per request without GC is 3% or more above
the base (`PERF_WARN_PERCENT`), and `FAIL` from 5% (`PERF_FAIL_PERCENT`).
The exit status is 1 when a scenario is `FAIL`, when a measurement fails
(`ERROR`: an unexpected response, a line at the `error` level or above in
`error.log`, a timeout, a missing dump, or a window that does not hold the
requests, see "In CI"), or when no scenario was compared. The one exception
is a base that answers with an unexpected response while the head passes,
which is what a scenario that needs a feature of the head gets: it is shown
as `n/a` and does not fail the run.

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

To check that the thresholds fire, the head was a copy of the base with an
empty loop of 100 iterations (`volatile` counter) at the start of
`ngx_mrb_run`, which every scenario runs once per request. The self cost of
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

Between base and head of one run, the largest change is about 0.02%
(`sub_request` in run 4: 48810 and 48820 Ir per request without GC, about
10 instructions). Between runs, the same build moves by up to about 0.1%:
the base of `sub_request` measured from 48810 to 48856 without GC over the
four runs (0.095%); every other scenario stayed within 0.011%. Base and
head are measured in the same job, one after the other, so it is the change
within a run that the thresholds see. The numbers differ from those of
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
`HEAD_DIR` (default: this checkout) into `build_perf/head`, the head with the
gem lock of the base build, so that both have the same third-party gems; the
report says how many gems are at different commits (0 when the lock
worked). The measurement (`test/perf/`, the scenarios in `test/soak/`) comes
from this checkout for both builds. The first run builds two trees (a few
minutes each); the measurement takes about one and a half minutes per build,
most of it in `sleep`. The report goes to `build_perf/report.txt` and
`build_perf/report.json`. `test.sh` kills every nginx on the machine, so do
not run it at the same time.

| Variable | Default | Meaning |
|---|---|---|
| `ONLY_RUN` | unset | set to skip the builds |
| `NUM_THREADS_ENV` | half of the CPUs | build parallelism (passed to `build.sh`) |
| `PERF_SCENARIOS` | all seven | comma-separated scenario names |
| `PERF_N` | 20000 | requests in the measured window |
| `PERF_WARMUP` | 2000 | requests before the window |
| `PERF_WARN_PERCENT` | 3 | WARN from this change of Ir per request without GC |
| `PERF_FAIL_PERCENT` | 5 | FAIL from this change |
| `PERF_PORT_BASE` | 12370 | port of the scenarios; the backend of `sub_request` uses the next one |
| `PERF_REPORT_DIR` | `build_perf` | where `report.txt` and `report.json` go |
| `PERF_REQUEST_FUNCTIONS` | `ngx_mrb_run` | names of the function counted once per request (see "In CI") |

### In CI

The `perf` job of `.github/workflows/test.yml` runs on pull requests that
change an input of the measured binary, the measurement or the workflow, or
that have the label `perf` (read when the job runs, so adding the label and
re-running the job is enough). The inputs of the binary are what
`test/build_release.sh` copies: `src/`, `mrbgems/`, `mruby/`, `dependence/`
(ngx_devel_kit, which `Makefile.in` adds to nginx) and the top-level build
files `build_config.rb`, `configure`, `config.in`, `Makefile.in`,
`build.sh` and `nginx_version`. The measurement is `test/perf/`,
`test/build_release.sh` and the scenario files in `test/soak/`
(`nginx.conf`, `scenarios.rb`, `http_client.rb`, `handlers/`).

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
requests: 0 Ir, or not exactly one call of `ngx_mrb_run` per request
(`callgrind_control` prints "OK." even when vgdb did not reach the process,
so an empty window is caught here). Only a base that answers a scenario with
an unexpected response (a scenario that needs a feature of the head) gives
`n/a`, and a run in which no scenario was compared fails.

The calls of `ngx_mrb_run` are counted by name. A copy that GCC makes of the
function at `-O2` (`ngx_mrb_run.part.0`, `.isra.0`, `.constprop.0`, `.cold`)
counts as the function, and a call from one copy to another counts once,
so a change that makes GCC split or clone it does not fail the window. A
pull request that renames `ngx_mrb_run`, or moves the running of the Ruby
code to another function, has to add the new name to `REQUEST_FUNCTIONS` in
`test/perf/perf.rb` and keep the old one: the `perf.rb` of the head
measures the base too, and a call between two listed names counts once.
`PERF_REQUEST_FUNCTIONS` (comma-separated) overrides the list for a local
run, and `REQUEST_FUNCTION_CALLS` sets another number of calls per request
for a scenario. `ruby test/perf/perf.rb --self-test` checks the name rules
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

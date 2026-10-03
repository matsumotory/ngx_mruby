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
with the reason.

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
contains `open socket`, `[alert]`, `[crit]`, `[emerg]`, `runtime error:` or
`Sanitizer`. The exit status is 1 when any scenario fails.

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

`test/soak/run.sh` builds nginx and ngx_mruby with `-O2 -g` and
`-DNGX_MRUBY_DEBUG_STATS`, without `MRB_GC_STRESS` and without `--with-debug`,
and with the gems of `build_config.rb`. mruby is built with
`-DMRB_USE_MALLOC_TRIM`, so `mrb_full_gc()` also calls `malloc_trim(0)`.
mruby runs a full GC only when it is asked to (`GC.start`,
`Nginx::Debug.gc`) or in rare cases (an incremental GC that finds too many
objects, a failed allocation), so the worker behaves as without it between
samples. `run.sh` runs `build.sh` in a copy of the
sources in `build_soak/tree` and installs nginx to `build_soak/nginx`, so the
`build/` directory, `mruby/build` and the generated `Makefile`, `config` and
`mrbgems_config` of `test.sh` are not touched. Later runs copy the sources
again and rebuild only what changed; the mruby build is rebuilt from scratch
when `NGX_MRUBY_CFLAGS` (passed to mruby, as with `test.sh`) changes. The soak
build is always a static module built from its own nginx source with the
system OpenSSL, so `run.sh` ignores `BUILD_DYNAMIC_MODULE`, `NGINX_SRC_ENV`
and `OPENSSL_SRC_VERSION`. The nginx source is downloaded to
`build_soak/tree/build/`; when nginx.org is unreachable, put it there as
described in `AGENTS.md`.

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
| aarch64, 6 runs, `SOAK_N=20000` | +100 kB (`sub_request`) | +188 kB (`sleep`) |
| aarch64, 1 run, `SOAK_N=100000` | +68 kB (`file`) | +160 kB (`file`) |
| x86_64 (CI), 2 runs, `SOAK_N=20000` | +144 kB (`filter`) | +216 kB (`sleep`) |

Without `malloc_trim(0)`, the `disconnect` scenario at `SOAK_N=300000` moved
by +2832, -788 and +1088 kB from window to window, which is over a 512 kB
limit for the last window, although its counters stayed the same and it grew
less in all than at `SOAK_N=100000`. With it, the largest growth is 144 kB in
the last window and 216 kB in all. The default limits, 512 kB for the last
window and 1024 kB in all, are about 3.5 and 4.7 times these. The limit for
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
2. Add a `Scenario` to `SCENARIOS` in `test/soak/soak.rb` with the path, the
   request headers, the expected body and response headers, and the mode
   (`:keepalive` or `:disconnect`).
3. Add its name to `DEFAULT_SCENARIOS`, run the soak three times, and check
   that all counters stay the same and that VmRSS stays within the limits.
   If a counter keeps growing, the scenario has found a problem: do not
   raise a limit or drop the comparison to make it pass. Report it as
   described in `SECURITY.md` when it may be a vulnerability.

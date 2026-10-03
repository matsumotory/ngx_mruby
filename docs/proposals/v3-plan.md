# ngx_mruby v3 plan

Status: in effect. The owner accepted the eleven recommendations in section 7
on 2026-10-03, in the review of this proposal, and set the priority recorded
in section 6 at the same time. Written 2026-10-03
from a read of the code at `master` (78e2f89, four commits after v2.7.0) and
a survey of primary sources dated up to 2026-10-03. Facts cite a file and line or a URL
with its date. Statements marked "unverified" come from reading code only and
still need a build and a test.

Security-relevant details found during the code read are deliberately not in
this document. They are tracked in the repository's private security advisory
(see `SECURITY.md`, added by #531).

## 1. Purpose

ngx_mruby 2.x embeds mruby 3.3.0 into nginx and has not had a release since
v2.7.0 (2024-11-07). Its build, tests, documentation, examples and default
dependencies date from 2014 to 2019. The owner decided on 2026-10-03:

- **v3** (branch `next`) is the base for the next generation of ngx_mruby.
  It is aligned with the 2026 technology background: mruby 4.x, nginx
  1.30/1.31, OpenSSL 3.5 LTS and 4.0, container-first distribution, generated
  and bilingual documentation, examples that run, a modern site, videos,
  memory and performance tests, and a development process that agents and
  humans can follow.
- **v2** (branch `master`, mirrored to `v2.x` until v3 is promoted) keeps
  compatibility for existing users and receives only security fixes, nginx
  version tracking and build fixes.

This document records the facts the plan rests on, the candidate changes for
v3 grouped by pillar, the v2 policy, the order of work, and the decisions
the owner made.

## 2. Where ngx_mruby stands (2026-10-03)

### 2.1 Code

- `src/` is about 6,900 lines of C: `src/http/` 5,409 (largest file
  `ngx_http_mruby_module.c`, 2,150 lines) and `src/stream/` 1,533. HTTP and
  stream are separate code paths with copied functions.
- One `mrb_state` per `http {}` block, created in the master process when the
  configuration is parsed (`ngx_http_mruby_module.c:323-355, 977-990`). All
  servers, locations, SSL handshake handlers and `mruby_init*` code share it;
  workers inherit a `fork` copy. Global variables, constants and `Userdata`
  therefore persist across requests inside a worker (`README.md:91` says the
  per-request global table is freed; it is not: only `mrb->exc` is cleared,
  `ngx_http_mruby_module.c:711-714`). stream has its own `mrb_state` per
  `stream {}` block.
- Twelve phase handlers (6 phases x file/inline) are registered whether or not
  a location uses mruby (`ngx_http_mruby_module.c:622-705`). Inline `*_code`
  is compiled once; file handlers are recompiled on every request unless
  `cache` or `mruby_cache on` is set (`:827-838, 911-934`).
- The Ruby APIs do not take their request or connection from one
  per-request or per-connection context type; the documentation is the only
  guard on which phase an API may be used in. v3 introduces such a type
  (Pillar B).
- `ngx_mrb_finalize_rputs` (`ngx_http_mruby_core.c:84-111`) applies one rule
  for every phase and is the common cause of five long-standing issues: an
  exception after `Nginx.rputs` returns 200 with a partial body, `Nginx.return
  200` without a body becomes 500 (#200, #225), a body with a non-200 status
  is discarded (#484), the async resume path overwrites 500
  (`ngx_http_mruby_async.c:116-132`), and the recursion inside a header filter
  (#206).
- Async is Fiber-based. The registration of fibers with the GC, the cleanup
  when a request or session ends, and the clearing of the interpreter's error
  state are handled differently on each path (HTTP sleep, HTTP subrequest,
  stream sleep), so v3 unifies them (Pillar B). Objects reachable from GC
  roots are not reported by valgrind. The compiled handler `RProc` is mutated
  per request through `mruby/internal.h` (`ngx_http_mruby_async.c:48-50`).
- HTTP and stream keep separate copies of code loading, fiber run and
  resume, sleep, upstream switching, error logging and the
  duplicate-directive check. v3 moves them into one common layer so each
  change is made once (Pillar B).
- v3 gives each filter handler pointer the type of the handlers assigned to
  it (Pillar B).
- Output filter handler pointers are not merged from `server {}` to
  `location {}` (`ngx_http_mruby_module.c:532-561`), so a filter written at
  server level does not run inside a location (unverified at runtime).
- Supported nginx versions are inconsistent: stream `add_listener` uses the
  1.25.5+ API unconditionally since 9a0f82b (2024-11), `docs/install` says
  1.11.5+, the code still has nginx 1.2/1.3 branches
  (`ngx_http_mruby_module.c:810`), and CI tests 1.26.2 to 1.31.5.

### 2.2 Dependencies and build

- Bundled mruby is 3.3.0 (`mruby/include/mruby/version.h`), last synced
  2024-03-11. Upstream is 4.0.0 (2026-04-20) with 4.1.0-rc2 (2026-09-11).
- Bundled `ngx_devel_kit` is 0.2.15 (2018-06); upstream is v0.3.4
  (2025-02-19).
- `build_config.rb` fetches 12 third-party mrbgems from GitHub branch heads
  with no commit pin and no committed lock file; `hiredis` and `vedis` are
  cloned unpinned inside `mrbgem.rake` files. `mruby-redis` was removed from
  the default build on 2026-09-02 (7256106, unreleased) because `hiredis`
  changed; docs and the auto-ssl example still assume `Redis`.
- `auto-ssl` depends on `pyama86/mruby-acme-client`, an ACMEv1 client
  (`new-reg`, `new-authz`); Let's Encrypt turned ACMEv1 off in 2021-06. It
  also pulls GPL-licensed `mruby-polarssl` into the default `libmruby`.
- `Dockerfile` is `ubuntu:18.04`; `.travis.yml` is unused; `configure.in`
  does not look in `/opt/homebrew` for OpenSSL.

### 2.3 Tests and CI

- Tests are integration tests only: `test.sh` builds nginx, starts it with
  `master_process off` and one worker, and runs `test/t/ngx_mruby.rb` (98
  assert blocks, 210 `assert_*` calls) over HTTP/1.0.
- valgrind runs with no options and its result is not part of the exit status
  (`test.sh:138-147`); CI on `master` passes with `definitely lost: 8 bytes`,
  `possibly lost: 86,208 bytes`.
- CI (`.github/workflows/test.yml`) runs on push only, on `ubuntu-22.04`, 16
  cells (4 nginx x static/dynamic x OpenSSL from source), OpenSSL 1.1.1w
  only. No sanitizer, fuzzing, load, soak, RSS, reload or multi-worker test.
- 15 directives and about 20 Ruby methods have no test; `mrbgems/*/test` are
  empty. `test.sh` runs `killall nginx` and uses fixed ports, so only one run
  per machine is possible.

### 2.4 Documentation

- Directive contexts in `docs/directives/README.md` differ from the
  implementation (implementation also allows `http` and `if in location`);
  eight directives have no section; `docs/use_case` still shows
  `mruby_output_filter`, removed in v1.17.2; several Ruby examples do not
  parse; `LOG_ALERT` and `LOG_EMERG` descriptions are swapped; example output
  shows nginx 1.4.4 and module version 0.0.1.

### 2.5 Users (public evidence)

- 998 stars, 114 forks. Seven releases in 2023-2024, none since. No commits
  in 2025. Contributors since 2023: pyama86, dearblue, buty4649, sawanoboly.
- GitHub code search (default branches only): `mruby_content_handler` 103,
  `mruby_access_handler` 36, `mruby_set_code` 31, `mruby_rewrite_handler` 30,
  `mruby_ssl_handshake_handler` 22, `mruby_output_body_filter` 11,
  `mruby_stream` 9.
- Production use with evidence: GMO Pepabo (dynamic certificates, rate limit,
  waiting room using `Nginx::Async::HTTP.sub_request`; tech.pepabo.com
  2021-03-22, PHPerKaigi 2024), TMDB (#505, Redis), a user whose production
  build broke when the v2.7.0 tag was renamed (#527).
- No distribution packages (Debian, Alpine, Homebrew, FreeBSD ports). Docker
  Hub images are stale (2019-2022). Most issues since 2023 are build
  failures (#519, #521, #524, #526).

## 3. The 2026 technology background

All claims below were checked against the cited page on 2026-10-03.

### 3.1 nginx

- Mainline 1.31.6, stable 1.30.5 (both 2026-09-15); legacy 1.28.3, 1.26.3
  (nginx.org/en/download.html). A new stable branch appears every April;
  fixes after 1.30.0 went only to 1.30.x and 1.31.x. 2026 had seven
  security releases.
- 1.30 brought Early Hints, HTTP/2 to upstreams, Encrypted Client Hello,
  upstream sticky, MPTCP, and `proxy_http_version 1.1` with keepalive by
  default. 1.31 brought a forward proxy module, `least_time`, PROXY protocol
  v2 for stream, a control API, predicate locations and `ngx_http_json_module`
  (nginx.org/en/CHANGES).
- A dynamic module loads only if `nginx_version` matches to the patch level
  and `NGX_MODULE_SIGNATURE` matches (`src/core/ngx_module.c:170-177`).
  1.31.3 broke binary compatibility for modules using script codes; 1.31.4
  restored it. ngx_mruby does not use those APIs.
- Official packages ship njs, otel and acme as separate dynamic-module
  packages built per nginx version; the official Docker image builds
  third-party modules through `nginx/docker-nginx/modules` (`source`,
  `build-deps`, `prebuild`). ngx_mruby is not in `pkg-oss`.
- njs 1.0.0 (2026-06-23) deprecated its own engine in favour of QuickJS
  (ES2023) and reuses contexts across requests; without reuse its benchmark
  drops 94.3% (blog.nginx.org 2025-07-10). njs has `js_access`,
  `js_set`, filters, `js_periodic`, shared dicts and `ngx.fetch`, but no
  SSL handshake hook.
- nginx-acme (Rust, `ngx-rust`) v0.4.1 (2026-05-01) supports http-01 and
  tls-alpn-01, ARI and profiles; no dns-01, no wildcard or regex
  `server_name`, no on-demand issuance at handshake. Certificates are passed
  through `$acme_certificate`.
- `ssl_certificate` accepts variables since 1.15.9, `data:` since 1.15.10,
  and `ssl_certificate_cache` since 1.27.4. nginx sets `SSL_CTX_set_cert_cb`
  when `ssl_certificate` has a variable (`ngx_http_ssl_module.c:818`);
  ngx_mruby sets the same callback on the same `SSL_CTX`
  (`ngx_http_mruby_module.c:427`), so the two cannot be combined on one
  server. nginx has no handling of `SSL_ERROR_WANT_X509_LOOKUP`, so an
  asynchronous certificate callback needs its own design.

### 3.2 Where nginx runs

- W3Techs 2026-10-03: Cloudflare Server 31.2%, Nginx 30.8%, Apache 21.9%
  (counted from the `Server` header, so origins behind Cloudflare are not
  counted). `.jp` domains: Nginx 53.6%. Netcraft July 2026: nginx runs
  43.9% of web-facing computers; OpenResty grew by 39.5 million sites that
  month.
- Kubernetes `ingress-nginx` retired in March 2026 (archived 2026-03-23)
  with one or two maintainers and the snippet annotations named as a security
  reason; the recommended replacement is the Gateway API. Users moved to
  Cilium, Traefik, Istio and Envoy Gateway (CNCF 2026-04-02).
  Cloudflare replaced its nginx/OpenResty edge with Rust (Pingora 2022,
  FL2 2025). Istio ambient uses Envoy and ztunnel. NGINX Unit was archived
  on 2025-10-08.
- Conclusion for v3: the primary deployment targets are the official nginx
  container images (Debian and Alpine, 1B+ pulls) and nginx as the origin or
  reverse proxy on VMs and PaaS. Being an ingress controller data plane,
  a CDN edge or a service-mesh sidecar is out of scope.

### 3.3 mruby

- 4.0.0 (2026-04-20) and 4.1.0-rc2 (2026-09-11); no maintenance releases on
  3.x. 4.0 C API: `mrb_alloca` to `mrb_temp_alloc`, `mruby/ext/io.h` to
  `mruby/io.h`, `MRB_NO_PRESYM` removed, `mrb_open()` returns a state with
  `exc` set on failure (`MRB_OPEN_FAILURE()`), ROM method tables, 19 listed
  memory-safety fixes. 3.4: `MRB_FROZEN_P` to `mrb_frozen_p`, `private` and
  `protected` implemented, `initialize` always private.
- 4.1 (NEWS.md): Prism compiler replaces `parse.y`; `mrb_gc_register` counts
  registrations; `mruby-regexp`, `mruby-env`, `mruby-process`,
  `mruby-signal` join core; `mrbc_context` becomes `mrb_ccontext` with
  compatibility aliases. The fiber, GC arena and load APIs ngx_mruby uses
  are still declared in 4.1.0-rc2.
- CVE-2025-7207, CVE-2025-13120 and CVE-2026-1979 cover mruby up to 3.4.0;
  CVE-2025-12875 is recorded against 3.4.0 only. All require processing
  attacker-supplied Ruby source. CVE-2026-79590 affects the Prism compiler on
  master after 4.0.0, not the 4.0.0 tag (issue #7032).
- Third-party gems: `iij/mruby-env`, `mruby-dir`, `mruby-process` last
  pushed 2018-2019 and a 2025 compatibility PR was closed unmerged;
  `mattn/mruby-json` and `mruby-onig-regexp` are active;
  `mruby-secure-random` (2020) has an open CSPRNG issue; `mruby-mutex` 2017,
  `mruby-uname` 2014.
- mruby had 3,526 commits and 796 merged PRs in the last 12 months; Groonga
  tracks mruby master in production. h2o's bundled mruby stopped at 3.1
  (2022).

### 3.4 TLS

- OpenSSL support ends: 3.4 on 2026-10-22, 3.6 on 2026-11-01, 4.0 on
  2027-05-14; 3.5 is LTS until 2030-04-08; 3.0 and 1.1.1 are unsupported
  (openssl-library.org release strategy). 3.5 defaults to X25519MLKEM768;
  Chrome 131, Firefox 132 and iOS 26 send it by default. 4.0 removed ENGINE
  and adds ECH (RFC 9849); nginx `ssl_ech_file` needs OpenSSL 4.0.
- nginx QUIC needs OpenSSL 3.5.1+ for 0-RTT; CVE-2026-90439 affected HTTP/3
  with OpenSSL 3.5.0 or older.
- Certificate lifetimes: 200 days from 2026-03-15, 100 from 2027-03-15, 47
  from 2029-03-15 (CA/B Forum BR 2.3.0, section 6.3.2). Let's Encrypt moves
  to 45 days (2026-05-13 for the `tlsserver` profile), offers 6-day and IP
  certificates, stopped OCSP on 2025-08-06, and recommends ARI (RFC 9773).
- Consequence: `auto-ssl` cannot work against Let's Encrypt today, and any
  certificate-lookup design must refresh without a reload.

### 3.5 Scripting in proxies

- OpenResty 1.31.1.1 (2026-06-05) tracks nginx 1.31 and OpenSSL 3.5 and added
  `proxy_ssl_verify_by_lua` and stream certificate hooks. Its strength is
  cosockets (non-blocking sockets on the nginx event loop) and the
  `lua-resty-*` ecosystem.
- Envoy has stable Lua filters and dynamic modules (Rust/Go/C++ SDKs) with an
  ABI stability policy. Proxy-Wasm on nginx is weak: Kong's
  `ngx_wasm_module` has no commits since 2025-04 and Kong removed its Wasm
  support in 3.11. HAProxy 3.4 ships Lua 5.5, native OpenTelemetry and ACME.
- Cloudflare's stated reasons for leaving Lua (untyped, large dynamic code
  base hard to reason about) apply to any embedded scripting layer. The
  position for ngx_mruby v3 is therefore the small decisions that nginx
  configuration cannot express: authentication, routing, rate limiting,
  observability attributes, and certificate selection from external stores.
  Not an application platform.

### 3.6 Documentation, examples, video

- Starlight 0.42 (Astro 7) has built-in i18n and CJK spacing; Docusaurus
  3.10 is the last 3.x before v4; Material for MkDocs is maintenance-only
  (successor Zensical 0.1.0 planned 2026-11-05); VitePress 2 is still alpha.
- Diátaxis (tutorials, how-to, reference, explanation) is used by nginx.org,
  Caddy and Envoy in the same order: Getting Started, how-to, reference.
- mruby generates its Ruby API reference with YARD + yard-mruby and its C
  reference with Doxygen.
- `docker/awesome-compose` pairs each example with a `compose.yaml` and a
  README stating the expected output.
- Remotion has official agent skills (`remotion-dev/skills`) and is free for
  individuals and companies of up to three employees; larger companies need a
  Company License. HyperFrames (Apache 2.0) is the alternative.

### 3.7 Development process for C nginx modules

- nginx's own CI runs an ASan cell with `-O1 -g -fsanitize=address
  -fno-omit-frame-pointer -DNGX_DEBUG_PALLOC -DNGX_DEBUG_MALLOC`,
  `ASAN_OPTIONS=detect_odr_violation=0:report_globals=0:detect_leaks=0` and
  `sysctl vm.mmap_rnd_bits=28`; PRs run `nginx-tests` with `prove`.
- `nginx-tests` can run against a binary with `TEST_NGINX_BINARY`,
  `TEST_NGINX_MODULES` and `TEST_NGINX_GLOBALS_*`.
- mruby is in OSS-Fuzz (ASan, MSan, UBSan). ClusterFuzzLite runs fuzzing in
  GitHub Actions for projects not accepted by OSS-Fuzz.
- GitHub supports SHA-pinning policies for actions, artifact attestations
  (SLSA Build L2/L3), Immutable Releases (GA 2025-10-29) and Dependabot for
  actions. mruby's `MRuby::Lockfile` records gem commits in
  `build_config.rb.lock`. Debian Policy forbids network access during build.
- `wrk` and `wrk2` are unmaintained; `oha` 1.16 (HTTP/1.1, 2, 3) and
  `h2load` are current. Shared CI runners vary by more than 30% in
  throughput, so throughput benchmarks are recorded, not gated. Instruction
  counts measured with callgrind do not depend on the runner's speed: two
  builds of the same code, measured one after the other on the runner,
  differed by at most about 0.05% per scenario in six runs
  (`docs/test/README.md`, "Performance comparison with callgrind"), so they
  can be gated against thresholds of a few percent. `/proc/<pid>/smaps_rollup` gives `Pss`
  for soak-test leak detection.

## 4. v3 candidates by pillar

Compatibility impact uses four values: **none** (internal), **additive**
(new API or directive, old ones unchanged), **behavior** (same API, different
result; needs a migration note), **breaking** (removal or new requirement).

### Pillar A: runtime and dependencies

| Candidate | Impact | Evidence |
|---|---|---|
| Bundle mruby 4.1.0 (rc2 until released; a commit after the #7032 fix). Rewrite `build_config.rb` to select gems explicitly instead of `full-core`; replace `iij/mruby-env`, `-process`, `-dir` with core gems; choose between core `mruby-regexp` and `mruby-onig-regexp`. | breaking (Ruby-level: `private`/`protected`, `initialize` private, regex engine) | 3.3, 2.2 |
| Pin every third-party gem by commit and commit `build_config.rb.lock`; move toward a source tarball that builds without network. | behavior (same tag now builds the same binary) | 3.7, 2.2 |
| Update `ngx_devel_kit` to v0.3.4 via `update-devkit-subtree`. | none | 2.2 |
| Require nginx 1.30 stable and 1.31 mainline; remove `nginx_version` branches older than 1.25.5; raise the floor each April. | breaking (older nginx) | 3.1, 2.1 |
| Require OpenSSL 3.5 LTS; test 4.0; drop 1.1.1 and 3.0. Check ngx_mruby and bundled gems for ENGINE or removed APIs. | breaking (older OpenSSL) | 3.4 |
| Replace `mruby-secure-random` with a small gem over `RAND_bytes`/`getrandom`; reimplement `mruby-digest` over OpenSSL 3 EVP or find a maintained one; drop `mruby-vedis` and `mruby-localmemcache` from the default list. | breaking (default gem set) | 3.3 |

### Pillar B: core design

| Candidate | Impact | Evidence |
|---|---|---|
| Introduce one execution-context type per request (HTTP) and per connection (stream, SSL handshake) and derive every Ruby API from it. Calling an API outside the phase it is designed for raises a Ruby exception. | behavior (code that "worked by accident" in the wrong phase now raises) | 2.1 |
| Redesign response finalization per phase: allow `Nginx.return 200` with an empty body, allow a body with any status, return 500 when an exception follows `rputs`, make `Nginx.return` type-independent of `headers_out.status`, fix the header-filter recursion. | behavior (fixes #200 #225 #484 #206) | 2.1 |
| One fiber lifecycle for HTTP and stream: register once at start, unregister once in the pool cleanup; `sub_request` returns the response directly (`last_response` kept); clear `mrb->exc` on every exit path of `ngx_mrb_run` and `post_fiber`; raise when async APIs are used outside supported phases; replace the `RProc` mutation with public mruby API. | behavior (async errors become 500; fewer leaks) | 2.1 |
| Common layer for HTTP and stream (code loading, fiber run/resume, sleep, upstream switching, error logging, duplicate directive check) so a fix lands once. | none | 2.1 |
| Headers: `delete` matches the full name and removes all matches; builtin headers (`Content-Type`, `Content-Length`, `Location`, `Date`) are kept in sync with `headers_out`; setters accept non-String via `to_s` or raise `TypeError`. | behavior | 2.1 |
| `Nginx::Var`: one setter implementation shared by `set` and assignment through `method_missing`, built on the execution-context type. | behavior (minor) | 2.1 |
| Give filter handler pointers the type of their handlers; merge filter handler pointers so server-level filters apply in locations; register phase handlers only where a directive exists; mark cached procs with `mrb_gc_register`. | behavior (server-level filters start applying) | 2.1 |
| Table-driven directive definitions (file/inline pairs) so adding a field touches one place. | none | 2.1 |
| Request/response naming: add `Nginx::Request#response_content_type` style accessors; keep old names as aliases (#410, #411). | additive | 2.5 |

### Pillar C: capabilities for 2026

| Candidate | Impact | Evidence |
|---|---|---|
| Non-blocking socket API on the nginx event loop with a per-worker connection pool (Redis, HTTP APIs, certificate stores). Evaluate mruby 4.0 `mruby-task` with an nginx HAL versus extending the Fiber design. This is the prerequisite for Redis (#505, #428), external auth and certificate lookup. | additive | 3.5, 2.5 |
| Shared dictionary over nginx slab shared memory (like `lua_shared_dict` and `js_shared_dict_zone`) for rate limiting and caches. | additive | 3.5 |
| `Nginx::SSL`: keep for lookups nginx variables cannot express (external stores, tenant logic, ECH outer SNI); chain with nginx's own `cert_cb` or reject the combination at config time; add an in-process certificate cache with TTL; verify behaviour under HTTP/3 and ECH. Replace `auto-ssl` with examples that combine nginx-acme (fixed names) and an external ACME client with store lookup (on-demand). | breaking (`auto-ssl` removed from default) | 3.1, 3.4 |
| Redis: restore as an optional, pinned gem built on the new socket API. | additive | 2.5 |
| Read-only TLS facts for Ruby (`$ssl_curve`, ECH status, protocol). | additive | 3.4 |
| stream: `preread` and `content` phase handlers, variables, SNI-based routing; stream APIs share their implementation with HTTP through the common layer (Pillar B). | additive / behavior | 2.1 |

### Pillar D: distribution

| Candidate | Impact | Evidence |
|---|---|---|
| Dynamic module as the default artifact: `--with-compat`, one `.so` per nginx version (stable and mainline, x86_64 and aarch64), built in CI for Debian and Alpine (musl). Static build remains documented. | none | 3.1, 3.7 |
| OCI images on GHCR based on the official nginx images (`load_module`), with provenance and SBOM; a `nginx/docker-nginx/modules` definition so users can add `ngx_mruby` with `ENABLED_MODULES`. | none | 3.1, 2.5 |
| Releases: tag `vX.Y.Z`, draft release with source tarball (gems vendored), `.so` artifacts, attestations and SBOM, then publish; Immutable Releases; never rename a tag (#527). | none | 3.7, 2.5 |
| deb/rpm through `pkg-oss` `build_module.sh`; Alpine `_add_module` compatibility by keeping the tarball layout stable. Homebrew out of scope. | none | 3.7 |

### Pillar E: tests and CI

| Candidate | Impact | Evidence |
|---|---|---|
| Test harness rewrite: no `killall`, pid-managed nginx, configurable ports, readiness check instead of fixed `sleep`, requests sent from CRuby (or Go) rather than from a test-built mruby, HTTP/1.1, HTTP/2 and HTTP/3 clients, `master_process on`, multi-worker and reload cases. | none | 2.3 |
| Required gate: ASan+UBSan build (nginx settings from 3.7) running the whole suite. valgrind moved to nightly with `--error-exitcode`. | none | 3.7 |
| Memory accounting tests: a test-only method exposing the GC root count and arena index; soak test with `oha`/`h2load` recording worker `Pss` and `Private_Dirty` over time with a slope threshold set after measuring. | none | 3.7, 2.1 |
| nginx-tests run against nginx with ngx_mruby loaded (`TEST_NGINX_MODULES`, `TEST_NGINX_GLOBALS_HTTP`), recorded first, required once stable. | none | 3.7 |
| Coverage: tests for the 15 untested directives and ~20 untested methods before touching the core, so v3 refactors are checked against v2 behaviour. | none | 2.3 |
| ClusterFuzzLite with a fuzzer that drives request headers, variables and SNI through mruby handlers. | none | 3.7 |
| Matrix: nginx 1.30.x and 1.31.x current patch, OpenSSL 3.5 and 4.0, gcc and clang, Ubuntu 24.04, Debian, Alpine, FreeBSD; nightly build against mruby master. Throughput benchmarks recorded with Bencher or github-action-benchmark, not gated. | none | 3.1, 3.7 |
| Instructions per request (callgrind `Ir`) of the base and the head of each PR that changes the code: release builds, the keep-alive soak scenarios, WARN from 3% and FAIL from 5% more instructions without the GC (`test/perf/`, `docs/test/README.md`). Advisory first; gated through `ci-ok` once it has run on PRs that change the code without false alarms. | none | 3.7 |

### Pillar F: documentation, site, examples, video

| Candidate | Impact | Evidence |
|---|---|---|
| Site built with Starlight (version pinned), structured by Diátaxis: Getting Started (runs in Docker in minutes), how-to for the five standard uses (auth, routing, rate limit, observability with `ngx_otel_module`, certificate lookup), reference, explanation (lifetimes, phases, what nginx can do without Ruby). English primary, Japanese under `src/content/docs/ja/`. GitHub Pages. | none | 3.6 |
| Generated reference: directives extracted from `ngx_command_t` tables and checked against prose in CI; Ruby API from YARD + yard-mruby; C API from Doxygen. | none | 3.6, 2.4 |
| `examples/<use>/` with `compose.yaml` and README with expected output, each started in CI. Drop the external `hsbt/nginx-tech-talk` reference and the fixtures that reference removed directives or unreachable hosts. | none | 3.6, 2.4 |
| Introduction video with Remotion (license depends on who produces it) or HyperFrames; form (length, sound, aspect) decided with the owner before production. | none | 3.6 |
| v2 docs frozen at a stable URL (`/v2/` or the GitHub `docs/`), no live version switcher. | none | 3.6 |

### Pillar G: process

| Candidate | Impact | Evidence |
|---|---|---|
| Adopt `AGENTS.md`, `CLAUDE.md`, `SECURITY.md` and the PR template from PR #531; CI on pull requests with `ci-ok` from #530; mirror from #532. | none | existing PRs |
| semver, pre-release tags, migration guide listing every "behavior" and "breaking" row above, deprecation warnings one release before removal. | none | 3.1 (njs precedent) |
| Supply chain: SHA-pinned actions, Dependabot, Renovate or a scheduled job for `build_config.rb` gems, `zizmor`, OpenSSF Scorecard recorded, Best Practices badge target. | none | 3.7 |
| Trust boundary stated in docs: ngx_mruby executes code written by the operator; multi-tenant code injection is out of scope (the ingress-nginx snippet lesson). | none | 3.2 |

## 5. v2 policy

- Scope: security fixes from the advisory, nginx version tracking in CI and
  `nginx_version`, build fixes (#519, #526, `/opt/homebrew`), test.sh
  version-gating fix (#529), CI on PRs (#530), mirror (#532). No API or
  directive changes. mruby stays 3.3.0; evaluate backporting the mruby CVE
  fixes after checking each commit against 3.3.0.
- `mruby-redis`: v2.7.0 users have `Redis` in the default build. Recommended:
  restore it in 2.7.1 with `hiredis` pinned to a release tag, or state the
  removal in the release notes as a breaking change. Decided: see section 7,
  item 5.
- `auto-ssl`: document that the ACMEv1 path no longer works; keep the
  dehydrated hook path.
- Support period: recommended until twelve months after v3.0.0, revisited
  when Debian trixie's nginx 1.26 leaves support. Decided: see section 7,
  item 11.
- Next release: 2.7.1 (security fix, nginx 1.31.6/1.30.5, redis decision).

## 6. Order of work (decided 2026-10-03)

Priority: stability, performance and current dependencies come before new
capabilities. The evidence in 2.5 shows that users are blocked by builds
breaking on new nginx and OS releases, by builds that are not reproducible,
and by behaviour under long-running load, not by missing features. New
capabilities (Pillar C) are taken up only where users ask for them; the
Redis connection pool (#428, #505) is the one item with a demonstrated
demand.

1. **Finish the infrastructure PRs** (#529 to #532) and the 2.7.1 security
   release through the private fork.
2. **Safety net first** (Pillar E, parts of G): harness rewrite, ASan+UBSan
   gate, valgrind exit code, GC root test hooks, tests for untested
   directives and methods, pinned gems, nginx-tests recorded. Nothing in the
   core is refactored before this exists; otherwise v3 cannot show it keeps
   v2 behaviour.
3. **Runtime** (Pillar A): mruby 4.1, NDK, OpenSSL 3.5/4.0, nginx floor,
   `build_config.rb` rewrite, build each bundled gem on mruby 4.
4. **Core stability** (Pillar B): execution context, finalization, fiber
   lifecycle, common layer, headers and variables. Tag `v3.0.0-alpha.1`
   when the v2 suite passes under the new core with sanitizers clean.
5. **Distribution** (Pillar D): `.so` per nginx version, images, releases
   with attestations.
6. **Docs, site, examples, video** (Pillar F) in parallel from step 4.
   Tag `v3.0.0-beta.1` when the migration guide and examples exist.
7. **Capabilities on demand** (Pillar C): Redis pool first; socket API,
   shared dict, SSL repositioning and stream phases only when asked.
   `v3.0.0-rc.1` when the site and examples are complete.

## 7. Decisions (made by the owner on 2026-10-03)

The owner accepted every recommendation below on 2026-10-03. The list is
kept as the record of what was decided and why.

1. mruby target for v3: **4.1.0** (rc2 or a post-#7032 commit until
   released), not 4.0.0, because 4.1 fixes GC registration counting that the
   async design depends on and adds core regexp/env/process.
2. nginx floor for v3: **1.30 stable and 1.31 mainline**, raised every
   April. Distro users on 1.26/1.24 stay on v2.
3. OpenSSL: **3.5 LTS baseline, 4.0 tested**, 1.1.1 and 3.0 dropped.
4. Default artifact: **dynamic module**; static build documented, not
   released as a binary.
5. `mruby-redis` in 2.7.1: **restore with pinned `hiredis`**.
6. `auto-ssl`: **remove from the default build in v3**; replace with
   nginx-acme plus store-lookup examples; document breakage in v2.
7. `mruby_stream`: **keep in v3** and ask users in a GitHub Discussion
   before investing in new stream features.
8. Behavior changes in v3 (exceptions outside phase, 500 after `rputs`
   exception, `Headers#delete` exact match, empty 200 allowed, body with any
   status): **accept all**, each listed in the migration guide.
9. Documentation language: **English primary, Japanese translation**.
10. Video tooling: **Remotion** if produced as an individual OSS activity;
    confirm whether a Company License applies before production.
11. v2 support period: **twelve months after v3.0.0**.

## 8. Verification before implementation

- Read nginx 1.31.x source for: phase handler return value semantics
  (`NGX_OK` vs `NGX_DECLINED` in rewrite/access), the type of
  `headers_out.status`, `ngx_list_push` capacity rules, `ngx_parse_url`
  allocation, stream phase return values, `ngx_http_core_run_phases` after
  async resume.
- Build each bundled and third-party gem on mruby 4.0.0 and 4.1.0-rc2.
- Confirm HTTP/3 and ECH paths call the SSL handshake handler; confirm the
  `cert_cb` conflict with variable `ssl_certificate`.
- Measure worker RSS and config-load time on mruby 3.3.0 versus 4.1.
- Run the v2 suite under ASan and UBSan before and after each Pillar B
  change, and record the result in the PR.

## 9. Sources

- nginx: https://nginx.org/en/download.html, https://nginx.org/en/CHANGES,
  https://nginx.org/en/docs/quic.html,
  https://nginx.org/en/docs/http/ngx_http_ssl_module.html,
  https://nginx.org/en/docs/http/ngx_http_acme_module.html,
  https://nginx.org/en/docs/njs/engine.html,
  https://github.com/nginx/nginx/blob/master/src/core/ngx_module.c,
  https://github.com/nginx/nginx-acme, https://github.com/nginx/docker-nginx,
  https://github.com/nginx/nginx-tests, https://github.com/nginx/ci-self-hosted,
  https://blog.nginx.org/blog/quickjs-engine-support-for-njs
- Usage: https://w3techs.com/technologies/overview/web_server,
  https://w3techs.com/technologies/segmentation/tld-jp-/web_server,
  https://www.netcraft.com/blog/july-2026-web-server-survey,
  https://kubernetes.io/blog/2025/11/11/ingress-nginx-retirement/,
  https://www.kubernetes.io/blog/2026/01/29/ingress-nginx-statement/,
  https://www.cncf.io/blog/2026/04/02/ingress-nginx-retirement-experience-from-end-users/,
  https://blog.cloudflare.com/20-percent-internet-upgrade/
- mruby: https://mruby.org/downloads/, https://github.com/mruby/mruby/tags,
  https://github.com/mruby/mruby/blob/master/NEWS.md,
  https://github.com/mruby/mruby/blob/master/doc/mruby4.0.md,
  https://github.com/mruby/mruby/blob/master/doc/mruby3.4.md,
  https://github.com/mruby/mruby/issues/7032
- TLS: https://openssl-library.org/policies/releasestrat/index.html,
  https://openssl-library.org/news/openssl-3.5-notes/index.html,
  https://github.com/cabforum/servercert/blob/main/docs/BR.md,
  https://letsencrypt.org/2025/12/02/from-90-to-45,
  https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability
- Scripting: https://blog.openresty.com/en/openresty-ann-1.31.1.1/,
  https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/dynamic_modules,
  https://developer.konghq.com/gateway/breaking-changes/,
  https://www.haproxy.com/blog/announcing-haproxy-3-4
- Docs and video: https://starlight.astro.build/guides/i18n/,
  https://docusaurus.io/blog/releases/3.10, https://diataxis.fr/,
  https://mruby.org/docs/api/, https://github.com/docker/awesome-compose,
  https://www.remotion.dev/docs/ai/skills, https://www.remotion.pro/license
- Process: https://github.com/google/oss-fuzz/tree/master/projects/mruby,
  https://google.github.io/clusterfuzzlite/,
  https://docs.github.com/en/actions/concepts/security/artifact-attestations,
  https://github.com/orgs/community/discussions/178351,
  https://github.com/mruby/mruby/blob/master/lib/mruby/build/load_gems.rb,
  https://www.debian.org/doc/debian-policy/ch-source.html,
  https://bencher.dev/docs/explanation/thresholds/,
  https://github.com/hatoo/oha/releases

# ngx_mruby v3 plan

Status: in effect. The owner accepted the eleven recommendations in section 7
on 2026-10-03, in the review of this proposal, and set the priority recorded
in section 6 at the same time. On 2026-10-04 the owner made the agent proxy
the scheduled use case of v3.0 and set its protocol scope (section 7, items
12 and 13). Written 2026-10-03 from a read of the code at `master` (78e2f89,
four commits after v2.7.0) and a survey of primary sources dated up to
2026-10-03. Amended 2026-10-04 for the agent proxy, from measurements on
`next` and primary sources fetched that day, in these places: the
introduction of section 4 and its last subsection, "Agent proxy: the v3.0
use case"; the Pillar F and Pillar G rows; the heading, the priority
paragraph and steps 2, 4, 7 and 8 of section 6; the heading and
introduction of section 7, its items 12 and 13 and the open question after
them; and the related lines of sections 1, 3.5, 8 and 9. The agent proxy
rows of step 4, the parallel start of step 7 and the order inside it, the
release conditions that steps 7 and 8 add for `v3.0.0-rc.1` and v3.0.0,
and the targets in section 8 are proposals of that amendment, not
decisions. Facts cite a file and line or a URL with its date. Statements
marked "unverified" come from reading code only and still need a build and
a test.

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

On 2026-10-04 the owner added the use case that v3.0 is built and measured
against: an agent proxy, a proxy for LLM agents written in Ruby on ngx_mruby
with good performance (section 4, "Agent proxy: the v3.0 use case"; section
7, items 12 and 13).

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
  Not an application platform. The agent proxy that the owner made the v3.0
  use case on 2026-10-04 (section 4) is a complex proxy built from these
  decisions, for the traffic of LLM agents: Ruby decides per request and per
  listed stream event, and nginx's proxy module moves the bytes.

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

The rows that the agent proxy adds to Pillars B, C and F are listed with the
use case in "Agent proxy: the v3.0 use case" at the end of this section.

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
| Site built with Starlight (version pinned), structured by Diátaxis: Getting Started (runs in Docker in minutes), how-to for the five standard uses (auth, routing, rate limit, observability with `ngx_otel_module`, certificate lookup) and for the agent proxy (below), reference, explanation (lifetimes, phases, what nginx can do without Ruby). English primary, Japanese under `src/content/docs/ja/`. GitHub Pages. | none | 3.6 |
| Generated reference: directives extracted from `ngx_command_t` tables and checked against prose in CI; Ruby API from YARD + yard-mruby; C API from Doxygen. | none | 3.6, 2.4 |
| `examples/<use>/` with `compose.yaml` and README with expected output, each started in CI. Drop the external `hsbt/nginx-tech-talk` reference and the fixtures that reference removed directives or unreachable hosts. | none | 3.6, 2.4 |
| Introduction video with Remotion (license depends on who produces it) or HyperFrames; form (length, sound, aspect) decided with the owner before production. | none | 3.6 |
| v2 docs frozen at a stable URL (`/v2/` or the GitHub `docs/`), no live version switcher. | none | 3.6 |

### Pillar G: process

| Candidate | Impact | Evidence |
|---|---|---|
| Adopt `AGENTS.md`, `CLAUDE.md`, `SECURITY.md` and the PR template from PR #531; CI on pull requests with `ci-ok` from #530; mirror from #532. | none | existing PRs |
| semver, pre-release tags, migration guide listing every "behavior" and "breaking" row of this section, those of "Agent proxy: the v3.0 use case" below included, deprecation warnings one release before removal. | none | 3.1 (njs precedent) |
| Supply chain: SHA-pinned actions, Dependabot, Renovate or a scheduled job for `build_config.rb` gems, `zizmor`, OpenSSF Scorecard recorded, Best Practices badge target. | none | 3.7 |
| Trust boundary stated in docs: ngx_mruby executes code written by the operator; multi-tenant code injection is out of scope (the ingress-nginx snippet lesson). | none | 3.2 |

### Agent proxy: the v3.0 use case

The owner decided on 2026-10-04 (section 7, item 12) that v3.0 is built and
measured against an agent proxy: a complex proxy for LLM agents such as
Claude Code and Codex, written in Ruby on ngx_mruby with good performance.
It authenticates the client, checks the client's model
allowlist and its token and money budgets, chooses the upstream and the
provider credential before the first response byte, relays a long streamed
response as it arrives, reads the token usage from the stream, and charges
the usage to counters that all workers share when the response ends or is
cut. Ruby makes these decisions with a number of calls per request that does
not depend on the length of the stream; nginx's proxy module moves the
bytes. Good performance is stated in instructions per request against the
measured baselines below, under the relative gate of the perf lane (Pillar
E), with throughput, latency and memory per open stream recorded beside them
(section 8).

**Protocol scope** (section 7, item 13): pass-through of the Anthropic
Messages API and the OpenAI Responses API, including their streamed
responses (server-sent events, SSE). The proxy reads requests (headers and
fields of the JSON body) and the events of a stream that its configuration
lists, one complete SSE event at a time. It changes only what belongs to the
gateway: it replaces the client's credential with the provider's, sets
`Host` and the TLS server name (SNI) for the upstream it chooses, and
answers some requests itself, with its own error responses (401, 403, 429,
504) and with the model list of `GET /v1/models`, the model discovery of
Claude Code's gateway guide, which the reference proxy serves from the
client's model allowlist. It forwards the `anthropic-*` request headers, the
request body fields and every event of a stream in order unchanged. An
upstream error that the proxy passes to the client keeps its body
unchanged; on an upstream 529, the proxy may instead send the request to
the fallback location of another provider (`error_page 529 = @name`,
section 8). It does not reimplement either API and does not translate
between them. Other wire formats (Gemini, OpenAI Chat Completions) and
upstreams that need translation or request signing (Amazon Bedrock
InvokeModel, Google Cloud rawPredict, AWS SigV4) are not part of the scope.
Neither is the WebSocket transport of the Responses API: nginx relays an
upgraded connection outside the body filters
(`ngx_http_upstream_process_upgraded`, `src/http/ngx_http_upstream.c:3705`
in nginx 1.31.6), so the reference proxy refuses `Upgrade`.

Facts the rows below rest on, checked against the cited page on 2026-10-04
(URLs in section 9):

- Claude Code sends Anthropic Messages requests to a gateway named by
  `ANTHROPIC_BASE_URL`, with the gateway credential in `Authorization`,
  `x-api-key` or both. Its gateway guide ("Claude Code gateway compatibility
  guide", the `llm-gateway-protocol` page) asks a gateway to pass the
  `anthropic-*` request headers and the request body fields through
  unchanged, to inspect bodies without modifying them, to deliver each
  response's full event sequence without dropping, duplicating or
  reordering events, and to forward error response bodies unmodified. With
  model discovery turned on (it is off by default), Claude Code asks the
  gateway for its models with `GET /v1/models?limit=1000`, with a timeout of
  3 seconds by default that `CLAUDE_CODE_GATEWAY_MODEL_DISCOVERY_TIMEOUT_MS`
  changes, and treats a redirect as a failure ("Model discovery"). Through a
  gateway, Claude Code aborts a stream after 300 seconds without a byte and
  runs no first-byte deadline ("Network configuration"); it waits for the
  response headers up to `API_TIMEOUT_MS`, 600,000 ms by default ("Errors").
- A Messages API request can be up to 32 MB (API "Errors", request size
  limits). In a stream, `message_start` carries the first usage values and
  `message_delta` the cumulative ones, so the output tokens are known at the
  end ("Streaming messages").
- Codex speaks only the Responses API: it rejects `wire_api = "chat"`, and a
  custom provider uses the WebSocket transport only when
  `supports_websockets` is set, which defaults to false
  (`codex-rs/model-provider-info/src/lib.rs`). A Responses stream ends with
  `response.completed`, `response.incomplete` or `response.failed`, each of
  which carries the whole `Response` object (`openapi.yaml` of
  `openai/openai-openapi`).
- nginx arms `proxy_read_timeout` both for the wait for the response header
  (`ngx_http_upstream_send_request`, `src/http/ngx_http_upstream.c:2269` in
  nginx 1.31.6) and between two reads of an unbuffered body
  (`ngx_http_upstream_process_non_buffered_request`, :4072), so a first-byte
  deadline shorter than the idle timeout of a stream needs a module.
  `limit_req` counts requests and `limit_conn` connections; neither counts
  tokens.

**What is on `next`.** The harness for the use case came with #554.
`test/soak/mock_llm.rb` is a mock upstream that answers like the Messages
API: streams of a given length, a hold or a reset after a given event, an
error status before the first event (`docs/test/README.md`, "Mock LLM
upstream"). The soak lane (#542, #557) runs three scenarios in front of it in
the required `soak` job: `agent_stream`, `agent_client_abort` and
`agent_upstream_reset`, which passed their checks in three runs on aarch64 and
two on the CI runner on 2026-10-04 (`docs/test/README.md`, "Thresholds and
calibration" of the soak test). The perf lane (#549, #555) measures the
scenarios of the table below; the advisory `perf` job runs those of its
default set. `test/t/cases/agent_proxy.rb` checks the recipes that work with
today's build: a server rewrite handler that rejects an unknown key with a
JSON 401 before the upstream is contacted, an access handler that routes by
the `model` of the JSON body and replaces the client's credential,
`limit_conn` per client key with a JSON 429, an upstream 529 passed to the
client unchanged, and a log handler that reads `$upstream_status`.

**Measured baselines.** One run of `test/perf/perf.rb` on 2026-10-04
(`docs/test/README.md`, "Agent proxy scenarios in the comparison"): release
builds of `next` at f62880c with the harness of #554, nginx 1.31.6, Ubuntu
22.04 (gcc 11, valgrind 3.18.1) in a container on aarch64, `PERF_N=20000`.
Values are callgrind instructions (Ir) per request, in total and without the
GC. H is the `hello` scenario of the same run (`Nginx.rputs "hello"`), 11,856
Ir per request in total (11,158 without the GC); the H column divides the
total by 11,856.

| What is measured | Scenario or difference | Ir per request (without GC) | H |
|---|---|---|---|
| Proxying a 2 KB POST, no Ruby | `proxy_plain_2k` | 21,952 (21,952) | 1.85 |
| Proxying a 64 KB POST, no Ruby | `proxy_plain_64k` | 22,264 (22,264) | 1.88 |
| Relaying a stream of 55 events, no Ruby | `proxy_stream_plain_50` | 54,294 (54,294) | 4.58 |
| Relaying a stream of 1,005 events, no Ruby | `proxy_stream_plain_1000` | 432,228 (432,228) | 36.5 |
| One more relayed event, no Ruby | (`proxy_stream_plain_1000` - `proxy_stream_plain_50`) / 950 | 398 (398) per event | 0.034 |
| An authentication check: one server rewrite handler with two Hash lookups and three variable assignments | `auth` - `proxy_plain_2k` | 27,180 (25,025) | 2.3 |
| Routing by `model`: `JSON.parse` of a 2 KB body in an access handler, and `proxy_pass` with a variable | `route_json_2k` - `proxy_plain_2k` | 87,444 (84,294) | 7.4 |
| The same with a 64 KB body | `route_json_64k` - `proxy_plain_64k` | 1,581,578 (1,577,952) | 133 |
| One more Ruby call (`mruby_set_code`) | (`ruby_call_10` - `ruby_call_1`) / 9 | 3,349 (2,722) | 0.28 |

What the measurements show:

- One Ruby call costs about 8 times what nginx spends to relay one more event
  (3,349 against 398 Ir). A Ruby call for every event would make the cost of
  a stream grow with its length, so the event filter below calls Ruby only
  for the events it lists.
- `JSON.parse` of the whole body costs about 24,100 Ir per KB without the GC
  (the 64 KB row minus the 2 KB row, over the 62 KB between them), while a
  Messages request can be 32 MB. Routing needs one field, so the JSON body
  read below returns one value, read in C.
- The authentication check in Ruby (2.3 H) costs more than proxying the 2 KB
  request without Ruby (1.85 H). It is the baseline for the Pillar B changes
  to the Ruby call and `Nginx::Var` paths, and for the dictionary operations
  that the check gains.
- The stream rows depend on how many relay calls nginx makes per request
  (4.97 and 38.43 in this run), which depends on when the bytes arrive. Null
  changes moved the agent proxy scenarios by at most 0.042% on aarch64 and
  by at most 0.39% between the base and the head of one run on the CI runner
  (x86_64), below the 3% of `WARN`.

The features, in the order of section 6 (step 4 is Pillar B, step 7 the
agent proxy):

| Feature | What it adds for the proxy | Pillar | Impact | Step |
|---|---|---|---|---|
| Log handlers before `access_log`: ngx_mruby's log-phase handlers run before nginx's log module (today they are appended after it, `src/http/ngx_http_mruby_module.c:700-706`), and an exception in a log handler does not change the status that `access_log` and later log-phase handlers see. | The cost, the tokens and the estimate for a cut stream that the log handler computes reach the access log line of the same request. | B | behavior (`access_log` and later log-phase handlers see what the mruby log handlers set) | 4 |
| Variable declaration (optional): `mruby_variable $name [value];` declares a variable that Ruby may assign, without a `set` that runs. | A server rewrite handler sets the variables of `proxy_set_header` and `access_log` without a declaration-only `location`: a server-level `set` runs after the handler in the same phase and would overwrite its values. | B (with the `Nginx::Var` row) | additive | 4 |
| Shared dictionary (the Pillar C row): `mruby_shared_dict NAME SIZE;` and `Nginx::SharedDict[name]` with `get`, `set` with a TTL, an atomic `incr` with a TTL and an option not to create a missing key, `delete`, `keys(prefix)`, and an entry count for the soak test. | Token and money counters per key and period, a cooldown per provider credential after a 429, and counters per key and model for a metrics endpoint, shared by the workers of one host. A zone with the same name and size survives a reload. | C | additive | 7a |
| JSON body read: `Nginx::Request#body_json(path)` returns one value of the JSON request body, read in C from memory or from nginx's temporary file, without a Ruby String of the whole body. If the top-level key that the path starts with appears more than once, `body_json` raises an error instead of choosing one of the values, and the handler rejects the request with 400: receivers disagree on repeated names, and many keep only the last pair (RFC 8259, section 4), so a read that kept the first `model` could approve one model while the upstream serves another. To find a repeat, the read goes on to the end of the top-level object. | Routing by `model` at a cost that does not grow like `JSON.parse` (above), up to the 32 MB of the Messages API, which is above the 10 MiB limit of a Ruby String in the default build (`MRB_STR_LENGTH_MAX`, `build_config.rb:49`). | C | additive | 7b |
| SSE event filter: `mruby_output_event_filter` (file and `_code`) with a list of event names, C-side measures of named JSON fields and a size limit per event; `Nginx::Filter::Event` with `#name`, `#data` and `#json(path)`. ngx_mruby frames the stream in C by the HTML Standard's event stream rules and runs Ruby once per complete listed event, which Ruby reads. The filter only reads (section 7, item 13): every byte of the stream, the listed events included, goes on to the client unchanged as it arrives. A listed event larger than the size limit (proposed default 1 MiB) is not given to Ruby; a variable names it for the access log, and its bytes go on unchanged. The terminal `response.*` events of the Responses API carry the whole `Response` object, so a Responses proxy sets the limit above the responses it expects. | Usage from `message_start` and `message_delta` (Messages) and from the terminal `response.*` events (Responses) with a fixed number of Ruby calls per request; counts of events and of the characters of text deltas, to estimate the output of a cut stream; variables for `access_log` without Ruby: the event count, the last event name, and the time to the first event from the start of the upstream attempt that served it. Today `mruby_output_body_filter` reads only a response of known length, as one buffer, and passes a stream on unread (`src/http/ngx_http_mruby_module.c:1826-1838`). | C, on the filter typing and merge of Pillar B | additive | 7b |
| Upstream peer hook: ngx_mruby wraps the peer `init`, `get` and `free` functions of the named `upstream {}` blocks, outside the keepalive module, only when a directive of the `http {}` block uses the hook (the first-byte deadline, later the balancer API), as the Pillar B row registers phase handlers only where a directive exists. For a location without such a directive, the wrapper calls nginx's functions and does nothing else. | The place, per request and per attempt, where the first-byte deadline and the balancer API attach. | C | none | 7c |
| First-byte deadline: `mruby_upstream_first_byte_timeout TIME;` per location, on the peer hook. `proxy_read_timeout` stays the idle timeout between reads, and `keepalive ... local` keeps matching connections to their location. | A provider that accepts a request and sends no response header is given up after the deadline (nginx's usual upstream timeout: 504, or the next server when `proxy_next_upstream timeout` is set), while `proxy_read_timeout` stays above the 300 seconds without a byte that Claude Code allows a stream. | C | additive | 7c |
| Non-blocking socket API and Redis on it (the Pillar C rows). | Budgets shared by several proxy hosts in an external store. A log handler cannot wait (`Nginx::Async` raises there since #551), so the charges are queued per worker and sent by a worker timer. | C | additive | 7d |
| Worker timers: a repeating timer per worker, stopped when the worker exits. | Sends the queued charges, and refreshes the local copy of the shared budgets and the key and price tables without a reload. | C | additive | 7d |
| Reference agent proxy: `examples/agent-proxy/` with `compose.yaml` and a README with the expected output, started in CI; `GET /v1/models` answered by a content handler from the client's model allowlist; a how-to page with trace export through `ngx_otel_module` by configuration; the client settings for Claude Code (`ANTHROPIC_BASE_URL`) and Codex (a custom provider). | The demonstration of the use case, and the configuration that the end-to-end perf and soak scenarios measure. | F | none | 7e |
| Ruby balancer API: `mruby_upstream_balancer` in `upstream {}`, on the peer hook, chooses the peer and rebuilds the request headers for each attempt. | Another credential of the same provider on a retry inside one location. A fallback to another provider on 529 does not need it: 529 is not a `proxy_next_upstream` status, and `error_page 529 = @name` sends the request to a named location with its own credential, Host and SNI. | C | additive | after v3.0.0, unless the fallback through a named location fails its test (section 8) |
| `sub_request` with a method, a body and headers, and several at once. | Calls from a handler to a key service or a ledger over HTTP. | C | additive | after v3.0.0 |

The proxy also needs four existing Pillar B rows: the execution-context type
(a per-request store across phases, and variable assignment from a filter),
a Ruby-built body with any status (the JSON error bodies of 401, 403 and
429), the exact-match `Headers#delete`, and the typing and merge of filter
handler pointers (event filter settings at server level reach the named
location of a fallback).

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

## 6. Order of work (decided 2026-10-03; the priority paragraph and steps 2, 4, 7 and 8 amended 2026-10-04)

Priority: stability, performance and current dependencies come before new
capabilities. The evidence in 2.5 shows that users are blocked by builds
breaking on new nginx and OS releases, by builds that are not reproducible,
and by behaviour under long-running load, not by missing features. New
capabilities (Pillar C) are taken up where users ask for them and where the
agent proxy, the v3.0 use case (section 7, item 12), needs them; the
Redis connection pool (#428, #505) is the one item with a demonstrated
demand from users.

1. **Finish the infrastructure PRs** (#529 to #532) and the 2.7.1 security
   release through the private fork.
2. **Safety net first** (Pillar E, parts of G): harness rewrite, ASan+UBSan
   gate, valgrind exit code, GC root test hooks, tests for untested
   directives and methods, pinned gems, nginx-tests recorded. Nothing in the
   core is refactored before this exists; otherwise v3 cannot show it keeps
   v2 behaviour. The harness of the agent proxy (#554: the mock LLM
   upstream, the `agent_*` soak scenarios, the agent proxy scenarios of the
   perf lane, `test/t/cases/agent_proxy.rb`) is part of it.
3. **Runtime** (Pillar A): mruby 4.1, NDK, OpenSSL 3.5/4.0, nginx floor,
   `build_config.rb` rewrite, build each bundled gem on mruby 4.
4. **Core stability** (Pillar B): execution context, finalization, fiber
   lifecycle, common layer, headers and variables. Proposed in the
   2026-10-04 amendment, not part of the 2026-10-03 decision: the two
   Pillar B rows of the agent proxy, log handlers before `access_log`
   (impact behavior) and the variable declaration (additive), so that this
   behavior change comes in alpha.1 with the other behavior changes of
   Pillar B. Tag `v3.0.0-alpha.1` when the v2 suite passes under the new
   core with sanitizers clean.
5. **Distribution** (Pillar D): `.so` per nginx version, images, releases
   with attestations.
6. **Docs, site, examples, video** (Pillar F) in parallel from step 4.
   Tag `v3.0.0-beta.1` when the migration guide and examples exist.
7. **Agent proxy** (section 4, "Agent proxy: the v3.0 use case"), after the
   safety net (step 2) and the runtime (step 3). By the priority above, it
   does not delay steps 4, 5 and 6. Proposed in the 2026-10-04 amendment,
   not a decision: parts (a) and (c) can start before step 4 ends and run
   beside it, and so that this does not delay steps 4, 5 and 6, they do not
   hold back step 4 or `v3.0.0-alpha.1`. Its parts and what each waits for
   (a proposal of the 2026-10-04 amendment, from the dependencies in
   section 4, not a decision):
   (a) the shared dictionary, after step 3;
   (b) the SSE event filter and the JSON body read, after step 4;
   (c) the upstream peer hook and the first-byte deadline, after step 3;
   (d) the non-blocking socket API with worker timers, Redis on it (the
   Redis pool of #428 and #505, first among the Pillar C rows in the order
   of 2026-10-03), and budgets shared across hosts, after the fiber
   lifecycle of step 4;
   (e) the reference proxy and its how-to, on the parts that exist.
   Proposed in the same amendment, not decisions: `v3.0.0-rc.1` waits for
   (a), (b), (c) and the reference proxy built on them, and (d) does not
   hold back rc.1 or v3.0.0. The design of the socket API is still to be
   evaluated (the Pillar C row), and until (d) lands the reference proxy
   keeps its budgets in the shared dictionary of one host.
   Each feature lands with its perf and soak scenarios (section 8).
8. **Capabilities on demand** (Pillar C, the rows that step 7 does not
   schedule): SSL repositioning, read-only TLS facts and stream phases only
   when asked. `v3.0.0-rc.1` when the site and the examples are complete.
   Proposed in the 2026-10-04 amendment, not a decision: the reference
   agent proxy is among those examples (on parts (a) to (c) of step 7).

## 7. Decisions (made by the owner on 2026-10-03 and 2026-10-04)

The owner accepted recommendations 1 to 11 below on 2026-10-03 and decided
items 12 and 13 on 2026-10-04. The list is kept as the record of what was
decided and why.

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
12. Use case of v3.0: **the agent proxy is scheduled work**, and this public
    plan says so (section 4, "Agent proxy: the v3.0 use case"; section 6,
    step 7): a complex proxy for LLM agents, written in Ruby on ngx_mruby
    with good performance. Its features are no longer capabilities "only
    when asked". The owner named it the new killer use case of ngx_mruby.
    It is made of the decisions that 3.5 gives ngx_mruby (authentication,
    routing, rate limits, observability), taken per request in front of
    long streamed responses, and the perf and soak lanes on `next` already
    measure its baselines (#554).
13. Protocol scope of the agent proxy: **pass-through of the Anthropic
    Messages API and the OpenAI Responses API**, including their streamed
    (SSE) responses. The proxy reads requests and the events of a stream
    that it lists. It changes only what belongs to the gateway: the
    credential, `Host` and SNI of the upstream it chooses, and its own
    responses (errors and `GET /v1/models`). It forwards the `anthropic-*`
    request headers, the request body fields and every event unchanged. An
    upstream error that it passes to the client keeps its body unchanged;
    on a 529, it may instead send the request to the fallback location of
    another provider (section 8). It does not reimplement the APIs. These are
    the APIs that Claude Code sends to a gateway and that Codex speaks
    (section 4), and Claude Code's gateway guide asks a gateway to pass the
    headers, body fields, events and error bodies through unchanged.
    Pass-through keeps ngx_mruby's part to decisions on requests and events,
    and leaves the semantics of the APIs to their providers.

One question that the 2026-10-04 amendment raises is open. It is not part of
item 13 or of any decision above. Should a later release add a mode in which
Ruby rewrites or drops events of a stream, or changes the request body?
Recommendation: not in v3.0, whose event filter only reads (section 4). Take
it up after v3.0.0 only for a use case that Claude Code's gateway guide does
not cover, since the guide asks for every event and every body field
unchanged, and only after the perf and soak scenarios of the event filter
have measured its cost per Ruby call: one Ruby call costs about 8 times what
nginx spends to relay one more event (section 4).

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
- Agent proxy (section 4, "Agent proxy: the v3.0 use case"). What shows that
  the use case works and performs:
  - Each feature of step 7 lands with scenarios of its own in the perf lane
    and the soak lane, beside the agent proxy scenarios that exist (`proxy_*`,
    `auth`, `route_json_*`, `ruby_call_*` in the perf lane; `agent_stream`,
    `agent_client_abort`, `agent_upstream_reset` in the soak lane).
  - The number of Ruby calls per request does not depend on the length of
    the stream: the perf lane counts the entry function of the event filter,
    and the count per request is the same at 50 and at 1,000 events.
  - The upstream peer hook adds nothing to a location that does not use it:
    in the PR that adds the hook, `proxy_plain_*` and `proxy_stream_plain_*`
    are measured with the hook installed by another location of the same
    configuration and show no `WARN` against the base.
  - Ir targets, proposed from the baselines of section 4 and checked when
    each scenario is added:
    - The JSON body read: a target per KB, set from a prototype measurement
      and compared with the about 24,100 Ir per KB of `JSON.parse` (section
      4), in two sets of scenarios at 2 KB, 64 KB, 512 KB and 4 MB: one with
      `model` as the first key of the body, as in the bodies that
      `MockLLM.request_body` builds (`test/soak/mock_llm.rb`), and one with
      `model` after `messages`. The read goes on to the end of the top-level
      object to find a repeated key (section 4), so its cost grows with the
      body wherever `model` is. A read that stopped at the first `model`
      could meet 0.5 H at 4 MB, about 0.0014 Ir per byte, but it would miss
      a repeated key, so the target does not assume an early stop.
    - The C-side scan of the event filter: a target per byte of the stream,
      stated with the scanning method it assumes and set from a prototype
      measurement. A share of nginx's relay cost per event does not work as
      the target: 10% of the 398 Ir of section 4 is about 40 Ir per event,
      about 0.33 Ir per byte of the mock's default `content_block_delta`
      event (121 bytes), which would also have to cover the C-side measures
      and the count of text-delta characters, and the 398 Ir depend on when
      the bytes arrive (section 4).
    - The Ruby share of the event filter: at most 1 H with two listed
      events, at both stream lengths.
    - One dictionary operation: at most 0.1 H.

    The reference proxy end to end (2 KB body, 50-event stream) is recorded,
    and its target is set from the sum of its parts once they are measured.
    After that, the relative gate of the lane (`WARN` from 3%, `FAIL` from
    5% between base and head) guards them.
  - The Responses API: the mock answers only `POST /v1/messages` today
    (`test/soak/mock_llm.rb`). It gets a Responses mode: `POST /v1/responses`
    answered with a stream that ends with `response.completed`,
    `response.incomplete` or `response.failed`, chosen per request. The perf
    lane, the soak lane and the functional tests get Responses scenarios
    beside the Messages ones: a stream relayed without Ruby, a stream through
    the event filter, and a terminal event larger than the filter's size
    limit, which reaches the client unchanged while the access log names it.
  - Recorded, not gated: throughput and p50 and p99 latency of the stream
    and end-to-end scenarios with `oha` or `h2load`; the time to the first
    event that the proxy adds (the client's first event through nginx minus
    the mock's write time); VmRSS per open stream, and per 1,000 events of
    one long stream.
  - Functional tests with the mock (`test/t/cases/agent_proxy.rb`): the
    request body arrives byte for byte (compared by hash); unknown
    `anthropic-beta` values arrive unchanged; `ping` events and every other
    event arrive in order through `message_stop`; a stream through the event
    filter arrives byte for byte, compared with the stream that
    `MockLLM.stream_body` computes for the same request; an upstream error
    body arrives unmodified; `retry-after` is in integer seconds;
    `GET /v1/models?limit=1000` answers without a redirect and lists only
    the key's models; a 529 goes through `error_page 529 = @name` to the
    other provider with its own credential, Host and SNI, and its usage is
    charged there; the first-byte deadline answers 504 for an upstream that
    accepts and never answers, does not cut a stream that pauses longer
    than the deadline between events, and leaves `keepalive ... local`
    reusing connections.
  - Several workers: N concurrent `incr` calls from 4 workers end at N. This
    needs the Pillar E harness with `master_process on`, because the perf
    lane runs `master_process off` and the soak test samples one worker.
  - The reference proxy (`examples/agent-proxy/`) starts in CI and answers
    the requests of its README; Claude Code and Codex are run against it
    before the documentation names them as supported clients.

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
- Agent proxy (fetched 2026-10-04):
  https://code.claude.com/docs/en/llm-gateway-protocol,
  https://code.claude.com/docs/en/network-config,
  https://code.claude.com/docs/en/errors,
  https://platform.claude.com/docs/en/api/errors,
  https://platform.claude.com/docs/en/build-with-claude/streaming,
  https://github.com/openai/codex/blob/main/codex-rs/model-provider-info/src/lib.rs,
  https://github.com/openai/openai-openapi (`openapi.yaml`),
  https://html.spec.whatwg.org/multipage/server-sent-events.html,
  https://www.rfc-editor.org/rfc/rfc8259 (section 4),
  https://github.com/nginx/nginx/blob/release-1.31.6/src/http/ngx_http_upstream.c
- Process: https://github.com/google/oss-fuzz/tree/master/projects/mruby,
  https://google.github.io/clusterfuzzlite/,
  https://docs.github.com/en/actions/concepts/security/artifact-attestations,
  https://github.com/orgs/community/discussions/178351,
  https://github.com/mruby/mruby/blob/master/lib/mruby/build/load_gems.rb,
  https://www.debian.org/doc/debian-policy/ch-source.html,
  https://bencher.dev/docs/explanation/thresholds/,
  https://github.com/hatoo/oha/releases

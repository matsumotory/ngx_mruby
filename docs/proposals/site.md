# Proposal: the ngx.mruby.org site and the documentation it is built from

Status: decided on 2026-10-15 (section 7); the four choices of 4.12
decided on 2026-10-19 on the specimens of step 2. Steps 1 and 2 of
section 6 are implemented (#591, #607), and step 3 (#617): the owner
approved the definition and the first diagram on 2026-10-29 with two small
fixes (section 7). Step 4 is implemented (#618 to #623), except the
observability and certificate lookup guides of 3.2, which wait for a test
build with `ngx_otel_module` and a TLS client in the sample's case, and
the narrow drawing of the agent proxy endpoints diagram, which still joins
the kinds of request with a line (should fix 1 of the review of #622).
Next: step 5, the Japanese pages, by 2026-11-05. On 2026-11-01 the
owner decided to build the site with Astro alone, without Starlight
(5.4, section 7); the implementation now uses the repository-owned Astro shell; acceptance
evidence is recorded separately from implementation status.

Evidence: the site map and writing plan of 3.2 and 3.3, and 3.5, section
4, section 6 and section 7 rest on `next` at 73fc9098f and on the source of
the owner's three sites (4.1), read on 2026-10-15. The rest rests on
`next` at ec227408d, `master` at 1ea47b0a6 (b3df70fb6 for the promotion
text that step 7 updates) and `gh-pages` at 59c923a, on the live site and
the repository's GitHub settings read on 2026-10-04, and on primary sources
on design, standards and tools (appendix D, with the date each was read).

On 2026-10-04 the owner asked for the introduction site at
https://ngx.mruby.org, unchanged since 2020, to be rebuilt as part of the
documentation work of the v3 plan
([Pillar F](./v3-plan.md#pillar-f-documentation-site-examples-video)), with
a design tuned to look slightly cyber and to lean towards open source
software and technology, with the design quality of the owner's other sites
as the bar, and for the documentation to be reorganized. This document says
how. The owner's decisions of 2026-10-15 (section 7) set, among others, that
the design starts from the owner's corporate site and product landing page,
with the owner's profile site as a third reference, and is tuned towards
cyber in colors and atmosphere (section 4), and that the site carries many
diagrams and samples, especially for v3 (3.5). Section 6 says what each step
produces and what the owner reviews.

The source and the design documents of the owner's three sites are in
private repositories. This document takes values and rules from them,
describes each source by its role ("the corporate site's token file"), and
names no path in those repositories (4.1). Rules from their design
documents are marked "owner's practice". Values marked "chosen here" are
choices of this proposal, with no source that fixes them; 4.12 records
those that the owner settled on the specimens of step 2.

## 1. Purpose and readers

The site has three jobs:

1. Say on the first screen what ngx_mruby is, who it is for and how to
   start. The home pages of nginx.org, njs, mruby.org, OpenResty, Caddy,
   Envoy and Traefik each answer at least two of these questions
   (appendix A); the current site and `README.md` answer none in plain
   words.
2. Take a reader from nothing to nginx running a Ruby handler, on current
   nginx and mruby, in minutes.
3. Hold the guides, reference and explanations for 2.x and 3.x, in English
   and Japanese, rendered from the Markdown in this repository so that the
   site and GitHub show the same text.

| Reader | Arrives with | Needs first |
|---|---|---|
| nginx operators | a production nginx and a decision to add: access control, routing, a rate limit, a certificate lookup | an install path for their nginx version, the directive reference, what runs per request and its cost |
| Ruby developers | Ruby, often without nginx internals | what mruby is next to CRuby, how long Ruby state lives across requests, the Ruby API, examples that run |
| people building LLM agent infrastructure | a gateway to put in front of Claude Code, Codex or a provider API | what Ruby decides and what nginx relays, the protocol scope, the measured cost per request, a reference proxy that runs |

English is primary and Japanese is a translation (decision 9 in
[v3-plan section 7](./v3-plan.md#7-decisions-made-by-the-owner-on-2026-10-03-2026-10-04-and-2026-10-15)).
Japanese readers exist (two of the three external articles in
[docs/use_case](../use_case/README.md) are in Japanese), yet on `next` at
ec227408d, before this proposal, no Markdown file outside the vendored trees
contained a kana or kanji character.

## 2. What exists today

### 2.1 The site

- https://ngx.mruby.org serves `index.html` of `gh-pages` byte for byte
  (identical sha256 on 2026-10-04): one English page in the Cayman theme of
  GitHub's former automatic page generator. Its content last changed in
  2016; #478 (2020-09-22) only moved five links.
- It says "Supported nginx 1.4/1.6/1.8./1.9.\*", shows a 2014 benchmark and
  badges for wercker (its host fails with a TLS error) and Travis CI
  ("unknown"; CI is on GitHub Actions). It mentions nothing written after
  2016: stream handlers, the SSL handshake handler, async, branches,
  releases, the security policy, an install command, Japanese.
- It loads Google Analytics `ga.js` with a Universal Analytics property;
  Google stopped processing hits of such properties on 2023-07-01.
- 44 of the branch's 51 files are leftovers of a theme used before 2015
  that `index.html` does not load: 32 fonts, 7 images and 2 scripts
  (720,564 bytes together) and 3 stylesheets (24,355 bytes). `params.json`
  is the input of GitHub's former page generator. The branch also holds
  `googleba3435e4002729b6.html`, a Google site verification file added on
  2014-03-08 (03a65ee4e).
- Pages settings: `build_type: legacy` from `gh-pages`,
  `cname: ngx.mruby.org`, `https_enforced: false` (`http://` answers 200
  without a redirect), no custom 404 page. The wiki has one page; GitHub
  Discussions are off.

### 2.2 The documentation

Appendix E lists the files. What the site work has to fix, not only render:

1. **Repeated blocks.** `README.md`, `docs/README.md` and the site page each
   carry the same bullets, samples, benchmark, abstract and license, with
   three different headlines and two statements of the supported nginx
   versions.
2. **A wrong statement.** The abstract in `README.md` says the server process
   frees the global variables table; [v3-plan 2.1](./v3-plan.md#21-code)
   says only `mrb->exc` is cleared and globals persist in a worker.
3. **Stale content.** The install page lists `mruby-redis` and
   `mruby-memcached` as default gems, which
   [build_config.rb](../../build_config.rb) comments out, and starts with a
   2019 Docker image that needs a Docker Hub account. A use case relies on
   `mruby_output_filter`, now a configuration error. One external article
   answers 404. [v3-plan 2.4](./v3-plan.md#24-documentation) lists more.
4. **Coverage.** The `ngx_command_t` tables in `src/` hold 42 directives:
   32 in `ngx_http_mruby_module.c`, 1 in `ngx_http_mruby_upstream.h` and 9
   in `ngx_stream_mruby_module.c`. 13 of them have no section heading in
   [docs/directives](../directives/README.md): `mruby_cache` and
   `mruby_server_context_handler_code` (listed under a TODO),
   `mruby_output_filter` and `mruby_output_filter_code` (configuration
   errors since their removal), and the nine stream directives. Six of the
   13 appear nowhere in that file: the two `mruby_output_filter` directives,
   `mruby_stream_init`, `mruby_stream_init_worker`,
   `mruby_stream_exit_worker` and `mruby_stream_server_context_code`. A few
   Ruby methods are undocumented, such as `Nginx::Utils.escape`.
5. **Reach.** `README.md` and the site link to `tree/master/docs`, so the
   pages that exist only on `next` (soak test, perf comparison, mock LLM
   upstream, v3 plan) are reachable from neither.
6. **Missing.** A plain definition, a quick start on current versions, how
   long Ruby state lives, the agent proxy for users, diagrams and samples
   that tests pin, release notes on `next` (they reached `master` with #564),
   a CONTRIBUTING file, Japanese text. No file has front matter.

## 3. Information architecture

### 3.1 Principles

- **One source per fact.** Markdown under `docs/` (English) and `docs/ja/`
  (Japanese) is the source; the site renders it and GitHub shows the same
  files. `README.md` keeps the definition, the branch table and links into
  the site.
- **Four kinds of page**, as Pillar F proposes after Diátaxis: Start
  (tutorial), Guides (how-to), Reference and Concepts (explanation). Section
  names on comparable sites vary more than
  [v3-plan 3.6](./v3-plan.md#36-documentation-examples-video) suggests: only
  nginx.org has a section named How-To (appendix A).
- **Version and language** appear in the URL and the header of every page.
- Pages with three or more second-level headings get an on-page table of
  contents (U.S. Web Design System, in-page navigation).

### 3.2 Site map

Japanese pages have the same paths under `/ja/`. The header has six links:
Docs, Agent proxy, Releases, Security, Contributing, GitHub.
`docs/proposals/` stays on GitHub only.

| Path | One line | Built from | New writing |
|---|---|---|---|
| `/` | what it is, who it is for, one example with its real output, three ways in | `README.md`; the example from a test that CI runs (3.3, item 8) | the definition (3.3); the example's test |
| `/start/` | run nginx with a Ruby handler in Docker, then change it | install 5-A to 5-C | `compose.yaml` and the walk-through |
| `/guides/install/` | images and packages once Pillar D ships them, dynamic module, build from source | [docs/install](../install/README.md) | tested versions table |
| `/guides/<task>/` | one task per page: access control, routing, rate limit, observability with `ngx_otel_module`, certificate lookup, TCP and UDP | [docs/use_case](../use_case/README.md), `test/conf/` | rate limit, observability, certificate lookup; a sample per page and per use case (3.5) |
| `/guides/agent-proxy/` | what Ruby decides and what nginx relays for LLM agent traffic | [v3-plan section 4](./v3-plan.md#agent-proxy-the-v30-use-case), [mock LLM upstream](../test/README.md#mock-llm-upstream) | the page with three v3 diagrams and today's recipes as samples (3.5); the how-to once `examples/agent-proxy/` exists |
| `/reference/directives/` | syntax, context, phase and version per directive | [docs/directives](../directives/README.md); later generated from `ngx_command_t` | missing and stream directives |
| `/reference/ruby/` | classes and methods | [docs/class_and_method](../class_and_method/README.md); later YARD | missing methods |
| `/reference/build/` | configure options, default gems, tested nginx, mruby and OpenSSL | docs/install, `build_config.rb`, [test.yml](../../.github/workflows/test.yml) | one version table; the build layout diagram (3.5) |
| `/concepts/` | the mruby VM per configuration and what lives across requests, phases and filters, async, the trust boundary | [v3-plan 2.1, 3.1](./v3-plan.md#21-code) | all pages; four diagrams (3.5) |
| `/releases/` | changes per release, behavior changes first; branches; support periods | `docs/releases/` (#564), [Branch strategy](../../README.md#branch-strategy) | the page; the v3 migration guide |
| `/security/` | private reporting, supported versions, trust boundary, advisories | [SECURITY.md](../../SECURITY.md), [Pillar G](./v3-plan.md#pillar-g-process) | the trust boundary |
| `/contributing/` | proposing a change, PR template, tests, agents and people, where to ask | [AGENTS.md](../../AGENTS.md), [PR template](../../.github/PULL_REQUEST_TEMPLATE.md), docs/test | `CONTRIBUTING.md` |
| `/v2/…` | the 2.x pages, changed only by fixes | `docs/` on `master` (on `v2.x` after the promotion, 5.2) | a banner |

### 3.3 Writing that does not exist yet

1. **The definition**, a draft for the owner to edit:

   > ngx_mruby lets you write the decisions of an nginx server in Ruby. You
   > reference a Ruby script from nginx.conf, and nginx runs it with an
   > embedded mruby VM at the point you choose: when a request arrives, to
   > compute a variable, before access is granted, to produce the response,
   > to change headers and body, during the TLS handshake, or for a TCP or
   > UDP session. nginx keeps doing the network I/O, and no application
   > server runs beside it. ngx_mruby builds as a static or dynamic module
   > of unmodified nginx.

2. **Getting started**: a `compose.yaml` that builds nginx with ngx_mruby,
   with the expected output in its README (Pillar F). Until Pillar D
   publishes images, the first run compiles nginx and mruby, and the page
   says how long that takes.
3. **Agent proxy**: what Ruby decides per request and what nginx relays, the
   protocol scope of decision 13, and the perf lane's instructions per
   request with their date. Claude Code and Codex are named as supported
   clients only after both have run against the reference proxy
   ([v3-plan section 8](./v3-plan.md#8-verification-before-implementation)).
4. **Releases**: the rule of #564 (each release file starts with the
   behavior changes), the branch table, and 2.x support for twelve months
   after v3.0.0 (decision 11).
5. **Security**: `SECURITY.md` plus the trust boundary of Pillar G: ngx_mruby
   executes code written by the operator, and injecting code for tenants is
   out of scope.
6. **Contributing**: a root `CONTRIBUTING.md`, where GitHub's community
   profile looks for it, pointing to `AGENTS.md`, the PR template and the
   test documentation.
7. **Concepts**: one `mrb_state` per `http {}` block, with globals and
   constants that persist in a worker, and the diagrams of 3.5.
8. **The home page example**: a test of its own, written the way
   [docs/test](../test/README.md#add-a-test-as-a-fragment-and-a-case-file)
   describes: a `server {}` in `test/conf/conf.d/` on a port of its own,
   its Ruby script in `test/html/`, and a case in `test/t/cases/` that
   compares the whole response body, and the headers the page shows, with a
   file of expected output next to the script. The generator copies the
   configuration, the script and that file into the home page, so the page
   shows what `test.sh` checks on every CI run, with the date of the last
   commit to those files. `example/nginx.conf` is not used, because no CI
   job starts it.

### 3.4 Versions and languages

- 3.x at unprefixed paths, 2.x under `/v2/`: Pillar F's "stable URL" with
  "no live version switcher". The header links each page's version to the
  other version's index.
- Until v3.0.0, every 3.x page carries a banner: 3.x is in development, the
  current release is 2.x, its documentation is under `/v2/`; and every 2.x
  page carries one that names 2.x the current release and links to the
  3.x documentation (step 6). Then the 2.x banner gives the end of 2.x
  support instead, and the 3.x pages carry none.
- Items added or changed in 3.x say "New in 3.0" or "Changed in 3.0", as
  nginx.org and njs mark the version that introduced each directive.
- Japanese pages live under `/ja/`, from `docs/ja/<path>.md`. An
  untranslated page shows the English text with the site’s fallback notice.
- `<html lang>` on every page, `lang="en"` on English passages in Japanese
  pages (WCAG 3.1.1, 3.1.2), and `hreflang` links to the page itself and
  the other language with absolute URLs, English as `x-default` (Google
  Search Central). Search keeps one index per version and language.
- Japanese copy has no space typed between Japanese and Latin characters;
  `text-autospace` in the site stylesheet adds the gap. No em dashes or emoji; parentheses only for identifiers and
  first uses of abbreviations (owner's practice).

### 3.5 Diagrams and samples

The owner decided on 2026-10-15 that the site carries many diagrams and
samples, especially for the content towards v3. This section plans them:
which diagrams, the tool, the samples, and how both are kept true.

#### Diagrams

Each diagram names the source it describes, at `next` 73fc9098f
(2026-10-15) unless a later commit is given.

| Diagram | What it shows | Source it describes | Page |
|---|---|---|---|
| Request phases | nginx's HTTP phases in order; in which of them ngx_mruby runs a handler from a file and an inline one (post-read, server rewrite, rewrite, access, content, log); `mruby_set` inside the rewrite module's script; where the header and body filters and the SSL handshake handler come; the directive for each; and, for TCP and UDP, the one stream handler | `src/http/ngx_http_mruby_module.c` lines 635 to 718 (`ngx_http_mruby_handler_init`), 1453 to 1525 (`mruby_set` through `ndk_set_var`), 428 (the certificate callback); `src/stream/ngx_stream_mruby_module.c` line 760 (`NGX_STREAM_ACCESS_PHASE`); the `ngx_http_phases` list of nginx 1.31.6 | Concepts: phases |
| Filter chain | ngx_mruby's header filter and body filter in nginx's two filter chains, after nginx's not-modified header filter and its range and copy body filters and before the filters of nginx's other modules; what each receives; that the body filter reads a response of known length as one buffer and passes a response without `Content-Length` on unread | `src/http/ngx_http_mruby_module.c` lines 1666 to 1676, 1824 to 1844 | Concepts: phases; Reference: directives |
| Non-blocking wait | `Nginx::Async.sleep` in a handler: the handler's fiber yields, a timer goes into nginx's event loop, the worker serves other connections, and the timer's handler resumes the fiber | `src/http/ngx_http_mruby_async.c` lines 356 to 403 (`ngx_mrb_async_sleep`), 309 to 341 (`ngx_mrb_timer_handler`), 240 to 307 (`ngx_mrb_post_fiber`), 186 to 238 (`ngx_mrb_run_fiber`) | Concepts: async |
| One `mrb_state` per worker | the `mrb_state` that nginx opens for an `http {}` block while it reads the configuration; the copy that each worker has after the fork; `mruby_init_worker` and `mruby_exit_worker`; what persists in a worker between requests (globals, constants, methods, classes); that only `mrb->exc` is cleared; that workers share nothing in Ruby, with the shared dictionary of v3 as the planned exception | `src/http/ngx_http_mruby_module.c` lines 999 to 1023 (`mrb_open`), 724 to 727 (`ngx_mrb_state_clean`), 601 to 633 (worker start and exit) | Concepts: lifetimes |
| Build layout | `build_config.rb` and mruby's `rake` producing `libmruby.a`; `./configure` writing `config` and `Makefile` from `config.in` and `Makefile.in`; nginx's `--add-module` or `--add-dynamic-module` producing a static binary or one module file that holds `ngx_http_mruby_module`, `ngx_stream_mruby_module` and ngx_mruby's upstream keepalive module; where `ngx_devel_kit` comes in | `config.in` lines 1 to 81 (the dynamic and the static branch, and `have=NDK_SET_VAR` for `ngx_devel_kit`), `Makefile.in` lines 27 to 28, 103 (nginx's configure with `--add-module=$(NDK_ROOT)`) and 118, `configure.in` lines 190 to 194 (`NDK_ROOT`), `build.sh`, `build_config.rb` | Reference: build |
| Agent proxy: the request (v3) | a client request through the server rewrite handler (the client key; 401 with a JSON body before any upstream), the access handler (the `model` of the body, the allowlist and the budget; 403 and 429; the upstream and the provider credential), and `proxy_pass` with the `Host` and SNI of the chosen provider; on an upstream 529, `error_page 529 = @name` to the location of another provider | [v3-plan, "Agent proxy: the v3.0 use case"](./v3-plan.md#agent-proxy-the-v30-use-case); for what exists today, `test/conf/conf.d/60-agent-proxy.conf` and `test/t/cases/agent_proxy.rb` | Guides: agent proxy |
| Agent proxy: the streamed response (v3) | the provider's server-sent events relayed to the client byte for byte as they arrive; the event filter framing events in C and calling Ruby once per listed event; the usage read from `message_start` and `message_delta`, or from the terminal `response.*` event; the counters of the shared dictionary charged when the response ends or is cut; the log handlers before `access_log`; the first-byte deadline and `proxy_read_timeout` as the idle timeout | the same section of the plan, its feature rows 7a to 7c | Guides: agent proxy |
| Agent proxy: the endpoints (v3) | what the proxy answers itself (`GET /v1/models` from the client's allowlist; its own 401, 403, 429 and 504), what it passes through unchanged (`POST /v1/messages`, `POST /v1/responses`, their streams, upstream errors with their bodies), and that it refuses `Upgrade` | the same section of the plan, "Protocol scope" | Guides: agent proxy |

The three agent proxy diagrams show v3 features that are not merged yet.
Until v3.0.0 they carry the label "Development version" beside "New in 3.0"
and sit under the banner of 3.4. Each element says whether it exists today
(the recipes of `test/t/cases/agent_proxy.rb`) or which step of the plan
adds it (7a to 7e), with the symbols of the owner's practice (4.2): a
filled circle for what exists, a ring for the next step, a dashed ring for
a later one, and a legend beside the diagram. They describe the plan until
the features merge, and then the source lines.

**Tool: labels in HTML, lines and symbols in SVG, as the owner's sites draw
their figures.** Each diagram has two parts:

- The drawing, `site/src/diagrams/<name>.svg`: lines, boxes, arrows and
  symbols only, with classes that refer to the tokens and no `<text>`
  element. A diagram with a narrow arrangement may have a second drawing
  for it; without one, the narrow arrangement shows the labels alone.
- The labels: a fenced block with the language `diagram` in the Markdown of
  the page, which names the drawing on its first line and gives one label
  per line as `key: text`. The keys are fixed by the drawing.

The generator of 5.2 turns the block into an HTML `figure`. The figure
holds a grid with `role="img"` and an `aria-label` taken from the caption,
which holds the drawing, inlined and hidden from screen readers, and each
label as HTML text, placed over or beside the drawing by the grid; the
`figcaption` stays outside the element with `role="img"`, whose children
are presentational, so that screen readers read the source lines too
(step 3). The
three ways compared:

| | Labels in HTML, drawing in SVG | SVG with its own text | Mermaid |
|---|---|---|---|
| Reading without JavaScript (5.1) | yes: the generator writes HTML and inline SVG | yes | no, unless a browser runs in the build: `astro-mermaid` 2.1.0 does "client-side rendering", and `rehype-mermaid` 3.0.0 "uses Playwright" outside browsers |
| Colors from the tokens in both themes | yes: the classes refer to the tokens | yes, with the colors repeated inside each file for GitHub | no: Mermaid's theming engine "will only recognize hex colors", and `rehype-mermaid`'s inline SVG output does not support its `dark` option |
| A vertical arrangement below 640 px (4.9) | yes: the labels move with CSS over a second drawing | a second file per arrangement | no: one layout for every width |
| Size of the labels | the page's text, 14 px or more at every width, enlarged by 200% text (WCAG 1.4.4) | scales with the drawing, so it depends on the width | scales with the drawing |
| Japanese labels (Q2) | from the Japanese page itself | a second file per language | a second source per language |
| On GitHub | the block reads as a list of its labels; the drawing is not shown | shown as an image | rendered |

The site uses the first way. It is the owner's practice: the corporate
site's design document sets figure text in HTML and draws only lines and
symbols in SVG, the corporate site's diagram components and the landing
page's figure components contain no SVG `<text>` element, and the profile
site's charts are HTML and CSS (4.2). Its cost is a small layout per
diagram and arrangement, and that GitHub shows the label list instead of
the picture; the facts of each diagram are also in the text (below), so
`docs/` reads completely on GitHub. Mermaid becomes the tool if the
hand-drawn diagrams fall behind the code (the check below lists them).

**Japanese labels.** The diagram block of `docs/ja/<path>.md` gives the
Japanese text for the same keys, so the Japanese page takes its labels from
its own translation (Q2). The generator stops the build when the Japanese
block lacks a key of the English block or has one that the English block
does not have. Until a page is translated, the site's fallback route shows the
English page, labels included. Japanese labels wrap by phrase with `<wbr>`
and `keep-all`, as the corporate site's figure text does (owner's
practice). Step 5 checks that every diagram on `/ja/` takes its labels from
`docs/ja/` and that no label overflows its place in the two patterns of
"Site design acceptance" (402 and 1440 px).

**Drawing rules**, after the owner's practice (4.2) and 4.11:

- Boxes and lines in `border-strong`, strokes of 1.5 to 2 px with round
  caps and `vector-effect: non-scaling-stroke`, so that lines keep their
  width when the drawing scales; labels in `text` or `text-muted`, never in
  a diagram color; the accent on at most two marks; no shadow, gradient or
  hover. Directive, function and file names are in the monospace face.
- A line joins two elements only where the diagram states a relation
  between them, such as an order or a flow. A diagram of kinds, such as
  the agent proxy endpoints, draws no line between its items, in either
  arrangement (chosen here, after the review of #622).
- Labels are short HTML text at 14 or 15 px (the caption and navigation
  sizes of 4.4), where the owner's figures go down to 13 px; details go
  into the text around the diagram.
- A diagram fits one screen at 402 by 664 and at 1440 by 900 px, so that the
  reader sees it whole, and takes a vertical arrangement below 640 px
  instead of scrolling sideways (4.9).
- Each diagram has a caption that says what it shows, and the facts it
  shows are also in the text or a table (WCAG 1.1.1). The figure's
  `aria-label` says what the diagram shows, and the drawing is hidden from
  screen readers, as on the corporate site.

**Keeping them true.** Under a diagram's caption, a note gives the source
it describes and when: a lead line with the commit and its date, then one
item per file with its lines, for example "`src/http/ngx_http_mruby_module.c`
lines 635 to 718", at the caption size of 14 px (step 3, the owner's
review of 2026-10-29). A check reads these lines: it
fails when a named file or line range no longer exists, and lists in the
run summary every diagram whose lines changed since its commit
(`git log -L <start>,<end>:<file> <commit>..HEAD`). The session that
redraws or confirms such a diagram moves the commit and the date.

#### Samples

**How a sample is made.** A sample is a `server {}` fragment in
`test/conf/conf.d/`, its script in `test/html/`, and a case in
`test/t/cases/` that compares the whole response body and the headers that
the page shows, written as
[docs/test](../test/README.md#add-a-test-as-a-fragment-and-a-case-file)
describes. The generator copies the configuration, the script, the request
and the response that the case compares into the page, as it does for the
home page example (3.3, item 8), with a line that names the case and the
date of the last commit to those files. Nothing is copied by hand, and the
generator stops the build when a referenced file or case is missing.
`examples/<use>/` of Pillar F packages the same configuration and script
with a `compose.yaml` for readers who want to run them, and its CI job
compares the output with the same expected response.

**One sample per use case of [docs/use_case](../use_case/README.md):**

| Use case | Today | As a sample |
|---|---|---|
| Hello world | `mruby_content_handler` with `Nginx.echo` | a fragment and a case that compares the body |
| Reverse proxy | `mruby_set` picks a backend for `proxy_pass` at random | a fragment with two backends; the case checks that both answer |
| Change to maintenance mode with Redis | needs `mruby-redis`, which `build_config.rb` comments out | a sample when `mruby-redis` is back in the default build (the queue of [HANDOFF](../HANDOFF.md#queue)) and the test job runs a Redis server; until then, the page marks the example as untested |
| Markdown web page | needs `mruby-discount`, which `build_config.rb` comments out | a sample when a CI job builds that gem; until then, the page marks the example as untested |
| Output filter converting Markdown to HTML | relies on `mruby_output_filter`, a configuration error since its removal | rewritten with `mruby_output_body_filter`; its filter part becomes a sample on the default build, the Markdown part waits as the use case above |
| File based access list | `mruby_access_handler` reads a deny list | a fragment with a list file in `test/html/` and two locations; the cases expect 403 for a listed client and 200 for another |
| File server like Dropbox link | needs `mruby-redis` | as the maintenance mode use case |

**Guides.** Each `/guides/<task>/` page of 3.2 carries at least one sample
with its case. The fragments that already pin such behavior are reused
where they fit, for example `test/conf/conf.d/stream/40-stream.conf` for
TCP and UDP.

**v3 samples for the agent proxy.** The agent proxy page starts with the
recipes that `test/t/cases/agent_proxy.rb` checks today: the client key
checked in a server rewrite handler with a JSON 401, routing by the `model`
of the body and the credential replaced in an access handler, a 403 for a
model without an upstream, `limit_conn` per client key with a JSON 429, an
upstream 529 passed to the client, and a log handler that reads
`$upstream_status`. Those cases do not compare whole responses: the client
of the test, `test/t/cases/_agent_proxy_client.rb`, prints one summary line
per request, and the case compares that line. For the 401, the 429 and the
529 the line holds the status, the content type and the whole JSON body; for
routing, the status, the upstream port and the credential that reached the
upstream; for the 403, the status alone; and for the log handler, the fields
of the access log line. The page shows the configuration, the script and
these compared values, labeled as such, and no other part of a response.
Step 4 moves the expected values out of the case into files next to the
scripts, which the case reads and the generator copies, so that nothing on
the page is copied by hand. The samples of the planned features (the shared
dictionary of step 7a, `body_json` and the event filter of 7b, the
first-byte deadline of 7c, timers and Redis of 7d, the reference proxy of
7e) appear when the feature and its test merge; a page never shows a sample
of a feature that has not merged. Until v3.0.0, each v3 sample carries the
label "Development version" beside "New in 3.0".

## 4. Visual direction

The 2026-10-29 local rebrand preview now applies the painted-reference
navy/graphite surfaces, silver text/edges and small copper interaction accents
to documentation pages as well as the home pages. The owner's later direction
supersedes retaining palette A for the new preview. The dark references show
near-black blue armor and concentrated reflections; the lighter references
show gunmetal/silver panels with copper joints and small metallic-red parts.
These establish roles, not a requirement to scatter all colors equally. Gold
is concentrated in the primary logo inset; purple is its comparison variant.
Code keeps distinguishable, contrast-checked syntax colors; large reading
surfaces stay quiet. The photos themselves are not published.


The owner answered Q7 on 2026-10-15 (section 7): the design starts from the
design of the owner's corporate site and the owner's product landing page,
which the owner likes, and tunes its colors and atmosphere towards cyber;
the owner likes the design of the owner's profile site as well. 4.1 says
what each site is and which of its sources this section reads, 4.2 lists
what the ngx_mruby site inherits, value by value and rule by rule, and 4.3
lists the changes towards cyber that this proposal makes. Those changes are
chosen here: the owner's answer names the direction, not the means, and the
owner chose them on the specimens of step 2 on 2026-10-19 (4.12, item 4).
4.4 to 4.10 give the rules by topic, 4.11 separates the owner's practice
from research, and 4.12 records what the owner settled on the specimens of
step 2. Each rule names its
source and its check; section 6 runs the checks. Appendix C gives the
evidence rule by rule.

### Working design: reading, implementation and agent use (2026-10-29)

The owner's later instruction removes the constraint of retaining the old
layout: "今の既存のさいとにとらわれなくていい。あなたが良いと思うものに作り直して欲しい。"
The requested uses are reading and understanding on a phone, implementation
on a PC, and reliable documentation retrieval and task assistance for agents.
The owner also requested a logo refresh; the name remains ngx_mruby. The
homepage preview below is an intermediate comparison, not a finished brand.

Implementation direction, subject to verification rather than a new runtime
API decision:

1. Keep one documentation source. Generate page-level Markdown and a compact
   machine-readable index from the same source/route/sample pipeline as HTML.
   Include the documentation version, source revision, source path, language,
   canonical HTML URL and sample provenance. Keep stable 2.x and development
   3.x in separate indexes. A missing translation must name its English
   source instead of pretending to be Japanese documentation.
2. Present the version and prerequisites before commands. On PC, bring the
   configuration, Ruby, request and expected result together with copyable
   code and links to API constraints. On phones, prioritize reading order,
   short sections and legible text rather than fitting a desktop workbench
   into a narrow viewport. Preserve stable routes and heading anchors.
3. Provide a visible Markdown/source route on documentation pages and a
   concise starting point for agent-assisted tasks. It must link to build
   requirements, execution phase/lifetime limits, reproducible examples,
   failure checks and verification. Do not fabricate a known-good result or
   silently present planned agent-proxy behavior as an available feature.
4. Validate the machine path with representative tasks: starting the correct
   version, choosing a handler for a phase, and finding the constraints of an
   upstream setter. A reader using only the exported material must find the
   version, prerequisites, source and verification evidence without guessing.
   Check version isolation, link targets and example fidelity automatically;
   use an independent reader for the task exercise. A standalone llms.txt is
   not sufficient evidence of agent usability.
5. Expand implementation guidance from reviewed code and tests, not just
   page summaries: normal and error cases; argument types, return values and
   exceptions; valid execution phases, lifetime and worker constraints; and
   versioned configuration/Ruby/request/expected-result examples. Each
   example names the case that checks it. Internal stress fixtures and
   deliberately invalid configurations are not recommendations. Preserve
   enough detail for an agent to implement a task without guessing.
6. Publish performance evidence with its method: tested source/base commits,
   nginx/mruby versions, build options, OS/CPU when actually recorded,
   request/workload counts, warm-up, repetitions or known variability,
   reproduction steps and limits. Distinguish historical measurements from
   current guarantees. Do not invent missing environment details or compare
   numbers from different conditions as a product superiority claim. The
   existing callgrind lane is an initial evidence source, not a throughput
   benchmark. Link back to the public CI artifact and comparison report.
7. Keep the visual language technical, with dark navy/graphite, metallic
   contrast and restrained accents. Use the selected metallic C mark, with small-size derivatives and the
   existing wordmark. Review their visual consistency together with the site. Publish coherent iterations after the normal PR, independent-review and
   deployment checks; the owner authorized iterative site deployment on
   2026-10-29. This is not authorization for a v3 software release. No new external service, account, payment or
   authentication change is needed for these static site capabilities.

#### First retrieval experiment and remaining content work

The preview exports 51 development and 16 stable source pages, each from
its HTML source pipeline, at `/markdown/<route>.md` and
`/v2/markdown/<route>.md`, indexed by `/docs-index.json` and
`/v2/docs-index.json`. These are source-language pages: Japanese HTML
fallbacks link to English Markdown. Metadata records the release line,
channel, language, source revision/hash and dirty state; an edited source
has no misleading link to its old bytes at HEAD. Sources not yet present
in HEAD stop export. The generator retains full Markdown bodies for the
build checker, and preserves code while omitting display word breaks and
SVG. Diagram labels and source provenance remain; label order is not a
claim about connections. The page footer exposes the outputs. The 2.x channel is
`maintenance`, not a release guarantee. Its shared banner and machine metadata
read the latest reachable stable release tag and newer release-note filenames
from the documented source tree. They name the released tag and unreleased
versions without duplicating version constants in components. A full-history,
full-tag checkout is required; no tag fails the build instead of guessing.
Examples keep their explicitly tested target (such as the released tag in the
installation guide), which can differ from maintenance-branch API changes.

An independent reader using only those outputs could identify version and
sample provenance, and distinguish callgrind instruction counts from
throughput. It also found substantive gaps, which export alone does not fix:

- The stable install page had historical version/output/path examples.
  [PR #660](https://github.com/matsumotory/ngx_mruby/pull/660) replaces them
  with a versioned source-build and HTTP walkthrough, executed on released
  ngx_mruby 2.7.2 with nginx 1.31.8. Its local preview is verified; the
  stable PR and its current CI remain the authoritative publication record.
- The development upstream API lacked constraints documented by the stable
  fixes. [PR #658](https://github.com/matsumotory/ngx_mruby/pull/658), merged
  into next at `258c852fa`, supplies that text and is included in this branch.
  Planned rejection of HTTP setter hostnames and exception normalization
  are not implemented by this site change. Check the actual source contract
  when reading examples; future runtime changes need their own tests.
- Historical performance tables must stay beside their recorded conditions.
  Add current, reproducible comparisons only from actual runs and preserve
  missing-environment and upstream timing limitations.

The export and first two source corrections are implemented; this is not
a claim that agent-assisted implementation coverage is complete. The next content pass will connect prerequisites,
complete examples, errors and verification before broadening the landing page.

The owner selected logo direction C on 2026-10-29: "白黒にした時のバランスがCがいいのでCが好き。ロゴ自体はメタリックなやつかっこいいね".
The owner clarified later the same day: "最初のcの1番下が好き" and
"隙間が金のやつ、あれ系で紫とか金の差し色使えると良い". The preferred
primary treatment is the initial metallic C with gold in the gap; the
monochrome balance was a selection criterion, not a request to make a flat
mark the primary identity. The earlier silver-only conversion is not
adopted. The revised metallic gold-inset SVG is used in the local desktop hero;
the purple-inset SVG is retained as the comparison variant. Both were
visually checked against the supplied reference before use.
Flat black/white are small-size and single-color derivatives only. The
header can preview those derivatives while the primary metallic asset remains the larger display treatment.
The favicon uses white on an opaque dark tile for visibility in either
browser tab theme. The existing Geist Mono wordmark keeps `ngx_mruby`.

Asset adoption checklist: header uses a monochrome candidate in this
preview; the homepage previews the gold-inset metallic treatment; favicon points to the background-backed SVG; README still uses
`misc/logo.png`; its replacement is a separate adoption task; there is no dedicated OG image configured.
The old `site/public/favicon.png` and `misc/logo.png` remain for comparison
and existing links. Source geometry, surface treatment and favicon background
are distinct. The reference photographs, kit builder, kit README, QA sheet
and temporary metadata are not repository assets. Each deployment reviews the changed favicon, header and home together.
README and a dedicated social-sharing image remain explicit follow-up work.

### Homepage revision requested on 2026-10-29

The owner asked for a more technical, engineer-facing site and for richer
code and terminal examples: "ソフトウェアのサイトなのでサンプルとかターミナル画面とかそういうのを色々リッチにみせたい".
The direction uses how Linear and Resend present software as a reference,
without copying their layout, wording or assets. The owner also supplied
painted-model photographs as references for color and material: dark navy,
graphite, silver edges and small warm or violet accents. The photographs
are not site assets.

The owner authorized iterative site publication on 2026-10-29. This
revision applies the dark navy/graphite palette to the home and documentation
pages, preserving the documentation type scale and layout. Normal PR,
independent-review and deployment checks still precede publication.
For the home pages, this revision supersedes the earlier small heading,
teal palette and plain sample layout. The request for real software and
terminal examples also supersedes the earlier blanket rejection of terminal
motifs; this implementation shows the actual HTTP exchange with labelled
code panels and adds no fictional shell prompt or operating-system chrome.

- `home.css` uses a two-column introduction and nginx/mruby execution
  structure, followed by a configuration, Ruby handler, request and response
  workbench. The four panels stack on narrow screens. Selected HTTP phases
  and links into the existing guides complete the page.
- The home title uses `clamp(2.375rem, 1rem + 4.5vw, 4.5rem)` in English
  and `clamp(2rem, 1rem + 3.5vw, 3.5rem)` in Japanese. Other text retains
  the existing type scale, gutters and spacing tokens. Controls retain a
  minimum height of 44 px and visible focus rings.
- Shared and homepage token blocks in `tokens.css` define graphite/navy
  surfaces, silver text and a restrained copper accent. Light and dark themes
  follow the theme control and the OS setting without JavaScript. The
  metallic SVG family uses gradients and subtle surface filters; six SVG
  assets cover the family, small monochrome derivatives and favicon. There
  are no new page animations.
- `Sample.astro` reads the same case and fixtures as before. Its caption
  identifies the compared response fields, date and commit; no measured
  performance or terminal output is invented. 3.x is labelled development
  and the stable 2.x documentation has its own link. The agent proxy guide
  retains the distinction between current implementation and planned work.
- `check-styles.mjs` checks the home scale and palette separately while
  retaining the documentation checks. `contrast.py` checks both palettes,
  matching dark-media tokens, and the shared syntax colors on the new home
  surfaces. `check-home.mjs` continues checking the actual code and fixture
  text, provenance and absence of unsupported performance claims. The
  existing language, keyboard, no-JavaScript and mobile checks still apply.
- Python bytecode from the site checks is ignored only under
  `site/scripts/__pycache__/`; source, tests and documentation remain
  visible to Git. Screenshots and local work records are not committed.

### 4.1 The three sites and their sources

| Site | Built with | Sources read on 2026-10-15 | Served publicly that day |
|---|---|---|---|
| The owner's corporate site | Next.js | its token file, base and page stylesheets, its brand page's stylesheet, header, footer, theme toggle and entrance-motion components, its diagram stylesheet, its design system document and its brand document | no: the domain answers with a sign-in page |
| The owner's product landing page | Next.js | the landing page's shared module (palette, layout, header, footer, narrow screens), the shared site token module (type and radii), the shared header module, the hero and figure stylesheets, the stylesheet of the product's connection page, its Japanese typography checklist, its design skills, and its rules for procedure pages | no: it answers 401 |
| The owner's profile site, https://research.matsumoto-r.jp/ | Astro | its token file and stylesheets, which it also publishes under `/_astro/`, and its design notes | yes: Japanese at `/`, English at `/en/` |

- The sources are the heads of the three sites' private repositories on
  2026-10-15. This document describes each source by its role, as in the
  table, and names no path in those repositories. The design values are
  not secret; the names and paths of the repositories stay out.
- The landing page applies the corporate site's palette inside the landing
  page only. The three sites share that palette, one pair of font stacks,
  the radius steps 8, 12, 16 and 24 px, the ring before section headings,
  and the rules of 4.2. None of them uses IBM Plex, so IBM Plex is not a
  candidate.
- Code and monospace on the three sites: the corporate site's brand page
  shows the SVG source of each logo in `<pre><code>` blocks set in the
  system monospace stack, and sets the stroke widths of its logo diagram,
  numbers with units, in nearly the same stack; the product's connection
  page sets the value a reader copies in Geist Mono. The landing page and
  the profile site show no code (4.2).
- Rules taken from their design documents are marked "owner's practice".
  Values marked "chosen here" are choices of this proposal, with no source
  that fixes them.

### 4.2 What the site inherits

**Type and layout.** The middle columns are the three sites of 4.1, with
the sources read; the last column says what the ngx_mruby site takes.

| What | Corporate site (token file, page stylesheet) | Landing page (shared module, shared site tokens) | Profile site (token file) | ngx_mruby site |
|---|---|---|---|---|
| Japanese-first stack | `"Hiragino Sans"`, Noto Sans JP, `sans-serif` | the same | `"Hiragino Sans", "Noto Sans JP Variable", "Noto Sans JP", sans-serif` | first on Japanese pages (4.4) |
| Inter | Latin-only words in headings: `Inter, "Helvetica Neue", Arial, sans-serif` | large numerals (56 px, weight 500, letter spacing -0.045em) and the copyright line | Latin-only words and large numbers: `"Inter Variable", "Inter", "Helvetica Neue", Arial, sans-serif` | first on English pages (4.4) |
| Monospace | the brand page's code blocks: `"SFMono-Regular", Menlo, Consolas, "Liberation Mono", monospace` at 0.8rem (12.8 px), line height 1.7, on the secondary background with a 1 px border, 20 by 24 px padding and a 12 px radius, scrolling sideways; the stroke widths of the logo diagram: `"SFMono-Regular", Menlo, Consolas, monospace` at 0.72rem, weight 600 | none on the landing page; the product's connection page sets the value to copy in `var(--font-geist-mono), monospace` (Geist Mono) at 15 px, line height 1.7 | none | code and numbers (4.3, 4.12) |
| Top heading | `clamp(1.625rem, 1.1rem + 2vw, 2.375rem)`, 26 to 38 px, weight 800, line height 1.4 | 42 px, 38 px at 1000 px and below, 32 px at 760 px and below; weight 700, line height 1.4 | `clamp(1.75rem, 1.3rem + 2vw, 2.375rem)`, 28 to 38 px, weight 800, line height 1.4 | home page heading (4.4) |
| Section heading | `clamp(1.4rem, 3vw, 2rem)`, 22 to 32 px, weight 700, line height 1.3 | 32 px, 26 px at 760 px and below; weight 700, line height 1.4 | `clamp(1.25rem, 1.1rem + 0.7vw, 1.5rem)`, 20 to 24 px, weight 700, line height 1.4 | h2 (4.4) |
| Item heading | 1.15rem (18.4 px), weight 700 | 20 px, weight 600, line height 1.5 | 1.0625rem (17 px) | h3 (4.4) |
| Japanese headings | `font-feature-settings: "palt" 1`, letter spacing 0.02em, `word-break: keep-all` then `auto-phrase`, `line-break: strict`, `overflow-wrap: anywhere` on the top and section headings | `font-feature-settings: "palt" 1`, letter spacing 0.02em, `word-break: keep-all` | `"palt" 1`, letter spacing 0.02em, `keep-all` with `auto-phrase` | `"palt"` and 0.02em on Japanese headings (4.4) |
| Body | 1rem (16 px), line height 1.8 | 16 px, and 17 px for the descriptive text of its home page (16 px at 760 px and below); line height 1.8, letter spacing 0.01em | 1rem (16 px), line height 1.8 | 16 px everywhere (4.4) |
| Notes, captions, labels | 0.875rem (14 px) | notes 15 px, captions 14 px, labels 12 to 13 px | 15 px and 14 px, line height 1.7 | 15 px and 14 px, nothing smaller (4.4) |
| Body measure | 720 px | 720 px | 720 px | 38rem (4.4) |
| Container | 1032 px, sections padded 80 by 24 px (60 px vertical at 640 px and below) | 1032 px with 32 px gutters, 20 px at 760 px and below; sections 88 px (56 px) | 1032 px, gutter 24 px, 20 px at 640 px and below | 1032 px for the home page, gutter 24 and 20 px (4.5) |
| Spacing | 16 to 32 px inside a group, 80 px between groups (64 px at 640 px and below) | no fixed set of steps (gaps such as 9, 14, 22, 28 and 64 px) | 4, 8, 12, 16, 24, 32, 48, 64, 80 px | the profile site's steps (4.5) |
| Radii | 8, 12, 16, 24 px; cards 16 px, inputs 12 px, buttons 999 px | panels 12 px, controls 8 px | 8, 12, 16, 24 px and 999 px | 0, 8, 12 and 999 px (4.5) |
| Borders and shadows | 1 px borders; a small shadow on the header after scrolling and on icon badges; the hero has a vertical gradient and soft radial spots | 1 px lines; no shadow or gradient | 1 px borders; an inset `box-shadow` marks the current page in the header | 1 px borders only (4.3) |
| Numbers | tabular figures in the company data table | tabular figures in prices and step numbers | tabular figures in periods and charts | monospace in tables and measurements (4.3) |
| Transitions | `transition: all 0.3s` on the header and on one button; color, transform, opacity and border color in 0.2 to 0.3 s elsewhere | background, border and text color in 160 ms, none under reduced motion | color and border color in 0.2 s | color only, 200 ms or less (4.8) |
| Entrance motion | a fade-up of 12 px in 0.5 s on about five blocks per page | none | none | none (4.8) |

**Color.** All three sites use the same light palette. The dark values of
the corporate and profile sites are the same; the landing page's differ in
muted text, border and control outline, and it adds a button fill.

| Role | Light | Dark, corporate and profile | Dark, landing page |
|---|---|---|---|
| Page | `#faf8f3` | `#14120d` | `#14120d` |
| Secondary surface (header controls, code blocks) | `#ffffff` | `#1a1811` | `#1a1811` |
| Card background | `#ffffff` | `#1b1812` | `#1a1811` (the surface) |
| Alternate surface (alternate section bands, notes) | `#f3f0e8` | `#211e15` | `#211e15` |
| Text | `#232017` | `#ece7db` | `#ece7db` |
| Secondary text | `#4b4536` | `#c9c2b1` | `#c9c2b1` |
| Muted text | `#5f5949` | `#9a937f` | `#aaa28f` |
| Accent, for marks and fills | `#d4a843` (2.08:1 on the page) | `#c9a34e` | `#c9a34e` |
| Text accent, for links and the focus ring | `#82672c` (5.04:1 on the page) | `#c9a34e` | `#c9a34e` |
| Button fill (landing page), with `#232017` text | `#c6a661` | | `#b69b60` |
| Border | `#e7e3d8`; card border and lines `#e0dbcd` | `#2b2719`; `#332e1f` | `#3a3524` |
| Control outline (3:1) | `#8a8271` | `#7d7458` | `#8f856a` |

Computed with the conversion of [contrast.py](../../site/scripts/contrast.py), every
color of this table except white, the gold included, has an OKLCH hue
between 84.4 and 94.1: neutrals and accent share one hue.

The profile site also defines colors for its charts, with light and dark
values: five categorical colors (`--viz-series-1` to `--viz-series-5`,
light `#2a78d6`, `#eb6834`, `#1baf7a`, `#eda100`, `#e87ba4`), a gold for
single bars and a gold scale for counts (`--viz-single`, `--viz-heat-0` to
`--viz-heat-4`). The ngx_mruby site plans no chart. If it charts the perf
lane's measurements (Q8), it starts from these colors and checks them
against palette A of 4.6 then.

**Components.**

- **Theme order.** The corporate and profile sites put light tokens on
  `:root`, dark ones under `prefers-color-scheme: dark` for
  `:root:not([data-theme="light"])`, and on `:root[data-theme="dark"]`
  (4.7).
- **Section heading mark.** A ring in the accent before each section
  heading: 9 px with a 1.5 px border on the profile site, hung 21 px into
  the left margin on screens wider than 1121 px and inline otherwise;
  the same 9 px ring hung 21 px into the margin on the corporate site (14 px
  at 640 px and below); 12 px with a 2 px border (10 px at 760 px and
  below), inline, on the landing page. The site takes the 9 px ring of the
  corporate and profile sites, which suits headings of 22 to 26 px (4.4).
- **Links and focus.** Links in the text accent, underlined: 1 px at an
  offset of 0.2em on the profile site, an offset of 3 px on the corporate
  site; the landing page underlines its text links in the control outline
  color at an offset of 6 px. Focus is a 2 px solid outline in the text
  accent, offset 3 px (5 px on the landing page).
- **Buttons.** The corporate site fills its primary button with the accent
  and rounds it fully (999 px); the landing page fills it with its button
  color and ink text at a radius of 8 px, 15 px at weight 600, and draws a
  secondary button with a 1 px text-accent outline. On the landing page, a
  button that cannot be used shows at an opacity of 0.6 without a hover
  change.
- **Header.** Corporate site: fixed, 64 px, translucent over a 16 px blur,
  1 px bottom border, a shadow after scrolling; its links move into a menu
  below 1060 px; the menu button is 44 by 44 px and the theme toggle a
  36 px square with a radius of 8 px. Landing page: sticky, opaque page
  color, 1 px bottom border, 88 px high (64 px at 900 px and below), the
  name at 21 px weight 700, links at 13 px (15 px from 901 px), a menu at
  900 px and below with rows 56 px high, and a fixed bar of actions at the
  bottom of narrow screens. Profile site: fixed, 64 px, translucent over a
  16 px blur, 1 px bottom border, links at least 44 px high at 15 px weight
  600, the current page marked by a 2 px accent line, the language link a
  pill with a 1 px outline, the theme toggle and the menu as 44 px round
  buttons with a 1 px outline, the links in the menu at 900 px and below,
  and the language link in the menu at 640 px and below.
- **Footer.** Corporate site: one footer component on every page, with a
  table of contents of the site, the privacy policy and the copyright, 1 px
  top border, 14 px text, 40 px above and 32 px below. Landing page: 1 px
  top border, the name at 20 px, links at 12 px in muted text, the
  copyright at 12 px, 40 px above and 32 px below. Profile site: 1 px top
  border, 14 px muted text, 48 px above and 32 px below.
- **Narrow screens.** One column for two-column sections below 1024 px
  (corporate) or at 760 px and below (landing page); gutters of 20 px on the
  landing page and the profile site, 24 px on the corporate site; the top
  heading and the section headings step down at 760 px (landing page).

**Practice from their design documents** (owner's practice), which the
site inherits:

- **Palette.** The page is a measured warm white (red at least green,
  green above blue). One accent family is the only accent, with a darker
  shade for text measured at 4.5:1 or more; the accent lights up only in a
  few places (links, the section heading mark, the primary action).
  Neutrals take the page's hue; no framework grays. Contrast is measured:
  4.5:1 for text, 3:1 for controls (corporate design system document).
- **Type.** A Japanese face first, the Latin face only for Latin-only
  words. Phrase wrapping only in titles and section headings, through
  `<wbr>` at phrase boundaries with `keep-all`; body text wraps by
  character, at most 720 px (about 40 Japanese characters); no
  `text-wrap: pretty` or `balance`. Headings at a line height of 1.3 to
  1.4, body at 1.7 or more, letter spacing at most 0.02em. One descending
  scale with the top heading largest, the same size for the same role on
  every page (corporate design system document). Japanese headings are
  smaller than English ones; the top heading takes two lines on a desktop
  and at most three; Japanese sizes follow a scale of about 1.2: 38, 32,
  26, 22, 18, 17, 16, 15 and 13 px; layouts are checked at 360, 375, 390,
  1024, 1200, 1280 and 1440 px (landing page's Japanese typography
  checklist).
- **Layout.** One left axis for every section, set by one container. Small
  gaps inside a group, large gaps between groups. One kind of section
  heading, the ring before it; no uppercase labels above headings; no row
  of identical cards repeated across sections (corporate design system
  document).
- **Surfaces.** A border or nothing, never a shadow on a bordered card; no
  framed card inside a framed card; no hover effect on what cannot be
  clicked; radii from a fixed set, the inner smaller than the outer; fixed
  data in tables with tabular figures (corporate design system document).
- **Motion.** An entrance fade-up of 0.5 s, moving only `translateY` and
  `opacity`, on about five blocks per page; no blur-in, no fade over a
  second, no `transition: all`; under reduced motion, nothing moves
  (corporate design system document and entrance-motion component).
- **Diagrams.** Figure text is set in HTML, and only lines and symbols are
  drawn in SVG; a figure that shows relations carries `role="img"` and an
  `aria-label`, and its SVG is hidden from screen readers; Japanese figure
  text wraps by phrase with `keep-all`, `line-break: strict` and `<wbr>`
  (corporate site's design document; neither the corporate site's diagram
  components nor the landing page's figure components contain an SVG
  `<text>` element). Colors from the tokens only; the accent on one or two
  places per figure; no shadow, gradient or hover; strokes of 1.5 to 2 px
  with round caps that keep their width when the drawing scales; short
  labels, the details in the text; a vertical arrangement on narrow screens
  (corporate diagram stylesheet, landing page's figure stylesheet). A figure
  is seen whole on one screen; a figure read against an axis fits half of a
  402 by 664 px screen; figures scale with the width and never scroll
  sideways; values are readable without hover, as a table or as numbers
  (profile site's design notes). A filled circle means established or
  current, a ring means next, a dashed ring means later, always with a
  legend or text, since the symbols alone do not reach 3:1 (corporate brand
  document).
- **Languages.** The language link names the other language in that
  language; no flags; no language chosen from the browser or location; a
  path prefix per language; `hreflang` both ways with `x-default`; a 404
  page per language (profile site's design notes).
- **English.** Active voice, one statement per sentence, sentence-case
  headings, no em dashes, after the Google developer documentation style
  guide and the Microsoft Writing Style Guide (profile site's design notes).
  Procedure pages, after the same guides, Diátaxis and W3C COGA: the
  conditions that stop a reader before step 1, one action per numbered
  step, each step ending with what the reader sees, one sequence per
  heading, the date and environment in which the steps were checked, a last
  step that checks the result, explanations outside the numbered steps, and
  no "simply" or "just" (landing page's rules for procedure pages).
- **Before shipping.** A list of signs of generated design checked one by
  one (purple-to-blue gradients, glows, framework grays, glass cards on
  every surface, uppercase labels, a Latin face first on Japanese pages,
  blur-in, emoji); screenshots of every page in both themes; narrow screens
  in WebKit as well as Chromium (corporate design system document).

### 4.3 What changes towards a slightly cyber tone

The tuning keeps every rule of 4.11. Each item says what the three sites do
and what the ngx_mruby site does instead. Every item is chosen here, as
this proposal's way to tune the colors and atmosphere towards cyber; the
owner chose them on the specimens of step 2 on 2026-10-19 (4.12, item 4).

1. **Code that runs is the first content.** Of the three sites, only the
   corporate site's brand page shows code, the SVG source of its logos below
   the logos. The home page's first example is real `nginx.conf` and Ruby
   from a test that CI runs (3.3, item 8), followed by the response that the
   test compares on every run. No mock terminal windows or decorative code.
2. **Monospace for code and numbers.** The corporate site sets its code
   blocks and the numbers of its logo diagram in the system monospace
   stack, and the product's connection page sets a value to copy in Geist
   Mono, so monospace for code and for numbers has precedents there. Code
   blocks are 15 px on the site (4.4), where the corporate site's are
   12.8 px, so that no text is below the floor of 4.4. The site sets a
   monospace face (4.12, item 2) for code, `kbd`, the wordmark
   `ngx_mruby`, directive, method and file names, commands, and the numbers
   of tables and measurements: versions, ports, sizes, durations, and the
   perf lane's instructions per request with their date (Q8). Prose,
   headings and navigation stay proportional, because they are read rather
   than copied (chosen here). Numbers inside prose keep the text face with
   tabular figures, as on the three sites. Check: the computed
   `font-family` of `code`, `pre`, `kbd`, the wordmark and the numeric cells
   of tables starts with the monospace face, and that of body text,
   headings and navigation does not.
3. **The accent comes from the ngx_mruby logo.** The three sites use one
   gold accent. The site uses the teal `#40a798` of
   [misc/logo.png](../../misc/logo.png), hue 182 in OKLCH, with the same
   split into `accent` for marks and fills and `accent-text` for text
   (4.6). The project's own mark identifies the project; the gold belongs
   to the owner's other sites.
4. **The quality of the dark theme.** The three sites' dark page is a
   near-black of the page's hue (`#14120d`, OKLCH lightness 0.183), with
   surfaces one step lighter instead of shadows, and one accent value for
   marks and text, lighter than the light theme's text accent. The site
   keeps the near-black page and the lighter surfaces with the teal: page
   `#0e1413` (lightness 0.185, hue 182) in palette A, surfaces one step
   lighter. It keeps two accent values in dark, both lighter than in light:
   `accent` `#56b1a3` for marks and fills and `accent-text` `#81cfc1` for
   links (chosen here). Every syntax color reaches 4.5:1 on the dark
   surface, and the dark theme works without JavaScript (4.7). The dark
   theme is where the teal on a near-black page, the monospace code and the
   1 px lines read as slightly cyber (chosen here).
5. **An opaque header and no shadows.** 1 px borders separate regions;
   there are no shadows, gradients, glows or translucent panels. The
   corporate and profile headers are translucent over a blurred backdrop;
   the corporate header adds a shadow after scrolling and its hero a
   gradient with radial spots; the profile header marks the current page
   with an inset `box-shadow`. The site takes the landing page's opaque
   header in `surface`, marks the current page with a 2 px bottom border in
   `accent`, and drops the gradient and the spots. The site's components have no
   shadows (4.6), and the search dialog has no blurred backdrop. Check: on three page types
   in both themes, with the search dialog and the narrow-screen menu open,
   every computed `box-shadow`, `text-shadow` and `backdrop-filter` is
   `none`, and no computed `background-image` holds a gradient.
6. **No entrance animation** (4.8). The corporate site's allowance of about
   five entrance animations per page is not used.
7. **Sharper and fewer radii.** Of the inherited steps, the site uses 8 and
   12 px, and 999 px only for the language link and the round header
   buttons; the 16 and 24 px of cards and the fully rounded primary button
   of the corporate site are not used (4.5).
8. **Structure that shows the system.** The sidebar mirrors the four kinds
   of page, headings name the directive, method or task, and diagrams show
   where Ruby runs inside nginx (3.5). Diagram labels are at least 14 px,
   where the landing page's figures go down to 13 px, so that no text is
   below the floor of 4.4.

Not used: decorative gradients, neon colors and glows, terminal motifs,
grids of emoji or icons, glowing or lifting cards, rows of identical feature
cards, uppercase labels above headings, hero illustrations, mock application
windows, a fixed bar of actions at the bottom of narrow screens.

### 4.4 Type

**Families.**

- English pages: `--font-latin`, then `--font-sans` for Japanese characters:
  `"Inter Variable", "Inter", "Helvetica Neue", Arial, "Hiragino Sans",
  "Noto Sans JP Variable", "Noto Sans JP", sans-serif`.
- Japanese pages: `--font-sans` first, so that digits, quotation marks and
  symbols inside Japanese text take the Japanese design (owner's practice).
  The runtime stack still prefers Hiragino Sans where installed, with
  served Noto Sans JP as its fallback. The migration does not change that
  stack. Validation uses Noto Sans JP on all Japanese pages, supplemented
  only by a Hiragino Sans check of the Japanese home page where available.
- Code and the numbers of 4.3, item 2: the monospace face of 4.12, then
  the corporate site's stack `"SFMono-Regular", Menlo, Consolas,
  "Liberation Mono", monospace`, then `--font-sans` for Japanese characters
  in code comments, since the monospace faces have no kana or kanji.
- The site serves its fonts from the Fontsource packages
  `@fontsource-variable/inter` 5.3.0 and `@fontsource-variable/noto-sans-jp`
  5.3.1 (SIL Open Font License 1.1), as the profile site does; the Japanese
  font is split by `unicode-range`.
- Japanese uses gothic (sans-serif): in a calculation by Sagawa and
  Kurakata for a reader of 70, the smallest legible kanji was 13.5 pt in
  gothic and 14.8 pt in Mincho.

**Scale.** Seven sizes per language, one per role, and no others.

| Role | English | Japanese | Weight | Line height, English / Japanese |
|---|---|---|---|---|
| Home page heading | `clamp(2.375rem, 1rem + 4.5vw, 4.5rem)`, from 801 px at most the column's width divided by 14.2 em: 39.3 px at 402 px, 58.0 px at 1440 px | `clamp(2rem, 1rem + 3.5vw, 3.5rem)`, at most the column's width divided by 13.7 em up to 800 px and by 21.9 em from 801 px: 26.4 px at 402 px, 37.6 px at 1440 px | 700 | 1.05 / 1.3 |
| Page title (h1) | 2rem, 32 px | 1.625rem, 26 px | 700 | 1.25 / 1.4 |
| Section heading (h2) | 1.625rem, 26 px | 1.375rem, 22 px | 700 | 1.3 / 1.4 |
| Subsection heading (h3) | 1.375rem, 22 px | 1.125rem, 18 px | 600 | 1.35 / 1.4 |
| Body text | 1rem, 16 px | the same | 400 | 1.6 / 1.8 |
| Navigation, tables, code blocks | 0.9375rem, 15 px | the same | 400; 600 for the current item | 1.5 / 1.7 |
| Captions, footer, notes | 0.875rem, 14 px | the same | 400 | 1.5 / 1.7 |

- **Where the values come from.** Inherited (4.2): the body, navigation and
  caption sizes, the Japanese line heights, the heading weight of 700, and
  `palt` with 0.02em of letter spacing on Japanese headings. The heading
  sizes are steps of the owner's reference scale for Japanese text, 38, 32,
  26, 22, 18, 17, 16, 15 and 13 px, a ratio of about 1.2 (owner's
  practice). Japanese headings are one step smaller than English ones, with
  a line height of 1.4, because the owner's Japanese typography checklist
  sets Japanese headings smaller than English ones, with a line height of
  1.3 to 1.4 (owner's practice). The Japanese sizes fall inside the ranges
  of the three sites (4.2): the home page heading of 26 to 32 px inside
  their top headings of 26 to 42 px, h2 of 22 px inside their section
  headings of 20 to 32 px, h3 of 18 px beside their item headings of 17 to
  20 px. Documentation pages need three levels of heading below the page
  title, so each level takes one step of the reference scale (chosen
  here). Nothing is below 14 px, and body text is 16 px
  (Digital Agency design system). Chosen here: the English line heights,
  with body text at 1.6 (above the 1.5 that the Digital Agency asks for
  body text and that WCAG 1.4.12 tests), and weight 600 for h3.
- **The root size at 640 px and below.** The sizes are written in rem,
  and the px values of the table are for a root of 16 px. At 640 px and
  below, `tokens.css` sets the root to
  `clamp(100%, (100vw - 2 * var(--gutter)) / 21.875, 106.25%)`: the text
  column between the 20 px gutters keeps the 21.875 em that it has at
  390 px, where the pages' lines were set, so the lines break at the same
  places. The root is 16 px up to 390 px, 16.55 px at 402 px (the phone
  pattern of "Site design acceptance") and 17 px from 412 px; every role
  of the scale follows it, so the roles keep their ratios. Above 640 px
  the root is 16 px. `check-styles.mjs` checks the root size and compares
  each role in rem (chosen here, following the owner's words of
  2026-11-01: 「あまりに箇所が多ければ、文字数というかフォントサイズなどで調整してその上で細かいところは分量で調整したら良さそう」).
- **Seven sizes.** A survey summary of Material Design 3 suggested three to
  six steps, but Material Design 3 itself names five roles in three sizes
  each (summary), so the number here follows the seven roles of the table,
  with one size per role and language and no size outside the table.
- Capitals only for acronyms (Tinker 1963: running capitals read slower).
- **Measure.** The text column is at most 38rem (608 px): 38 Japanese
  characters at 16 px, under the "about 40" of JLREQ 2.4.2; an estimated 75
  Latin characters, inside the U.S. Web Design System's 45 to 90 and at
  GOV.UK's 75. The three sites' measure of 720 px holds 45 Japanese
  characters at 16 px, so the column stays narrower (chosen here). Check at
  1440 px: Japanese body lines hold at most 40 characters (step 5) and
  English body lines at most 90, counted line by line from the client
  rectangles of the text.
- **Line height.** JLREQ 2.4.2 puts the gap between Japanese lines between
  half and a full character, nearer a full one past 35 characters, and finds
  no gain beyond that: 1.8 for Japanese body text (inherited), 1.6 for
  English.
- The page keeps working with the text spacing of WCAG 1.4.12 and at 200%
  text (1.4.4). Text is left-aligned, never justified (1.4.8).
- **Wrapping.** Japanese text wraps by character (`word-break: normal`,
  `line-break: strict`). The owner's practice allows phrase wrapping only
  in titles and section headings; this proposal uses it only in section
  headings (h2) of Japanese pages, in diagram labels, which the owner's
  sites also wrap by phrase (3.5), and in the Japanese home page heading,
  a title, which takes one line per phrase up to 800 px: the frontmatter
  field `headline` of `site/src/content/docs/ja/index.mdx` lists the
  phrases, `PageTitle.astro` sets each in a span of its own, which is a
  block up to 800 px and inline from 801 px, and the build stops when they
  do not join to the `title`. h3, captions, other labels and
  table cells wrap by character (chosen here, to keep the owner's
  exception as narrow as the owner stated it).
  - **Section headings (h2).** The Japanese Markdown source puts `<wbr>` at
    the phrase boundaries, and `h2` of Japanese pages has
    `word-break: keep-all` and `overflow-wrap: anywhere`, as the three
    sites' section headings do. GitHub drops the `<wbr>` without showing it
    (appendix B), so `docs/ja/` reads normally there.
  - **Page titles (h1)** wrap by character and are short instead (chosen
    here). The site's `DocTitle.astro` renders `title` as an escaped
    expression, and the generator of 5.2 takes `title` from the first
    heading, so a `<wbr>` there would show as text or be stripped; the same
    `title` fills `<title>`, the sidebar and search (appendix B). A
    Japanese title fits on one line at 402 px, about 13 characters at
    26 px; the longer statement of what the
    page covers is its first paragraph. `overflow-wrap: anywhere` on `h1`
    breaks a long identifier, and the generator stops on a first heading
    that contains HTML.
  - `word-break: auto-phrase` is not relied on: MDN's compatibility data
    lists it for Chrome 119 and later, for Safari only in Technology
    Preview and not for Firefox, so WebKit would wrap those headings by
    character.
- **Section heading mark.** h2 of content pages carry the inherited 9 px
  ring of 4.2 in `accent`, hung into the left margin where the margin
  allows and inline otherwise. It is decorative: the heading level is in
  the markup.
- The home page heading takes one line at 1440 px, in both languages,
  and at most two lines at 402 px (the owner on 2026-11-01:
  「pcビューのヒーロータイトルは1行に収まるフォントサイズがいいかな、日英ともに」).
  From 801 px, where the showcase image stands beside the heading, its
  size is at most the width of its column divided by the width of the
  heading on one line plus about 2%: 14.2 em in English, whose heading is
  13.9 em wide in Inter Variable, and 21.9 em in Japanese, whose heading
  is 21.5 em wide in Hiragino Sans and 20.7 em in Noto Sans JP, measured
  with the wider face. At 1440 px the column is 824 px: 58.0 px in
  English (806 px of text) and 37.6 px in Japanese (808 px in Hiragino
  Sans, 777 px in Noto Sans JP). Up to 800 px the Japanese heading takes
  its two lines, 「LLMリクエストの認証と転送を」 and 「Rubyで制御する。」,
  at every width: its size is at most the width of its column divided by
  13.7 em, because its first line is 13.3 em wide. That cap is below the
  size of the scale under about 498 px (20.4 px at 320 px, 28.5 px at
  430 px), and below h2 (22 px) under about 341 px (the owner on
  2026-10-31:
  「ヒーローの見出し、モバイルだとこういう改行で微妙なので2行にしておきたい。シュッと直しといてこれ」,
  then the choices 「文はそのまま、モバイルだけ字を小さく」 and, for the
  読点 after 転送を, 「取る (推奨)」).
- The row of project badges of 4.10 stands directly above the home page
  heading, at its left edge and 4 px above it, in both languages; it
  changes neither the heading's size nor its number of lines.
- No `text-wrap: pretty` or `balance` anywhere: Safari applies `pretty` to
  every line and Chromium to the last four, so the same CSS wraps
  differently per engine (WebKit blog; MDN). The site’s banner also uses
  normal wrapping, with no framework override.
- Prose links are underlined (WCAG 1.4.1).
- Checks: computed font sizes equal the scale of each language; no text
  below 14 px; the built CSS has no `text-wrap: pretty` or `balance`;
  `keep-all` and `auto-phrase` appear only on the `h2` selector of Japanese
  pages and on the labels of diagrams; the line count of the home page
  heading at 1440 and 402 px in both languages; every Japanese h1 takes
  one line at 402 px; no h1, `<title>`, sidebar
  entry, table-of-contents entry or heading `id` on `/ja/` contains the text
  `wbr`, and the h2 of the test page of step 1 keep their `<wbr>` elements;
  no external font URL in the built site, and the build succeeds with
  network access blocked after `npm ci`.

### 4.5 Spacing and radii

- Values 4, 8, 12, 16, 24, 32, 48, 64 and 80 px, the inherited
  `--space-1` to `--space-9`, and no others in layout CSS. They are
  multiples of the 8 CSS px base unit of the Digital Agency design system's
  spacing page, with 4 and 12 px as half steps inside components.
- Space above a heading is at least twice the space below, so the heading
  groups with its text (proximity, Wertheimer 1923; Digital Agency design
  system): h2 48 and 16 px, h3 32 and 8 px (chosen here).
- Gutters: 20 px at 640 px and below, 24 px above, as the profile site's
  `--gutter` (the corporate site pads its sections by 24 px; the landing
  page uses 32 and 20 px); the header's side padding is 32 px above 640 px,
  as on the corporate and profile sites. Both gutters stay inside the
  standards of appendix C: at least 16 px at narrow widths (the U.S. Web
  Design System's `grid-container` padding of 2 units of 8 px) and a step
  at 640 px (GOV.UK's responsive spacing, which grows at 640 px). Check:
  at 402 px, every text block and any marker in the margin is at
  least 20 px from both edges.
- The sections of the home page use the inherited content width of
  1032 px. Documentation pages use the site's sidebar, content and table-of-contents columns, with the text
  column of 4.4.
- Radii, from the inherited set: 8 px for buttons, inputs and the search
  field; 12 px for code blocks, as the corporate site's code blocks (4.12,
  item 3), asides, diagram frames and the frame of the home page example;
  999 px for the language link and the round header
  buttons, as on the profile site; 0 for inline code and table cells,
  where the monospace face marks the code (4.3, item 2). 16 and 24 px, the
  radii of cards, are not used, since documentation pages have no cards.
  The owner's practice is a fixed set of radii, with the inner radius
  smaller than the outer one when frames nest.
- Checks: every length that the built CSS gives to a margin, padding or
  gap is 0 or a value of the set (`auto` and percentages excepted), and
  every border radius is 0, 8, 12 or 999 px or 50% (the round buttons),
  including the site-owned base CSS; exceptions must be listed by selector.

### 4.6 Color

Two palettes went to the specimens of step 2, and the owner chose palette A
on 2026-10-19 (4.12, item 1); palette B is kept below as the alternative
that was compared. Both use the teal accent of 4.3, item 3, and the
inherited split between `accent` and `accent-text`. Palette A carries over
the rule of the three sites, neutrals in the hue of the accent, with the
logo's hue; palette B keeps the three sites' neutrals. `tokens.css` holds
palette A, with the custom property names of the last column of the first
table.

Palette A: each token is an OKLCH source value at hue 182, converted to
sRGB hex. Palette B: the neutrals of the corporate and profile sites' token
files (4.2), with the accent tokens of palette A; `surface` there is their
alternate surface. The ratios are WCAG 2.2 contrast ratios
against `bg` and `surface`, truncated to two decimals and never rounded,
since WCAG's Understanding document for 1.4.3 says "4.499:1 would not meet
the 4.5:1 threshold". [contrast.py](../../site/scripts/contrast.py) reads
palette A and the code colors from `site/src/styles/tokens.css`, converts
the OKLCH source values, compares the unrounded ratio of every pair a role
needs with its threshold (4.5:1 wherever a role puts text on or in the
color, 3:1 for outlines and the focus ring) and exits 1 on a failure. With
the light `accent` planted at `oklch(0.528 0.089 182)`, `#167c6f`, which is
4.4992:1 on `surface`, it prints 4.49 and exits 1. The rows of the table of
palette A below are the output of `contrast.py --markdown`; those of palette
B are its output while palette B was in `tokens.css` for the specimens
(#607), when the light `surface` of palette B planted at `#f0ece2` gave
4.345164:1 for `accent` on it and exit 1.

Palette A:

| Token | Role | Light | Ratio bg / surface | Dark | Ratio bg / surface | Custom property |
|---|---|---|---|---|---|---|
| `bg` | page | `#f7fbfa` oklch(0.985 0.004 182) |  | `#0e1413` oklch(0.185 0.010 182) |  | `--color-bg-primary` |
| `surface` | header, sidebar, code blocks | `#ecf3f1` oklch(0.958 0.008 182) |  | `#161e1c` oklch(0.225 0.012 182) |  | `--color-bg-tertiary` |
| `text` | body text | `#172522` oklch(0.250 0.020 182) | 15.20 / 14.08 | `#e2eae8` oklch(0.930 0.009 182) | 15.21 / 13.88 | `--color-text-primary` |
| `text-muted` | captions, code comments | `#4c5c59` oklch(0.460 0.020 182) | 6.75 / 6.25 | `#a6b1ae` oklch(0.750 0.013 182) | 8.43 / 7.69 | `--color-text-muted` |
| `accent-text` | links | `#0f695e` oklch(0.470 0.080 182) | 6.28 / 5.82 | `#81cfc1` oklch(0.800 0.080 182) | 10.30 / 9.40 | `--color-accent-text` |
| `accent` | focus ring, current navigation item, primary button, marks | `#167b6f` oklch(0.527 0.089 182) | 4.91 / 4.55 | `#56b1a3` oklch(0.700 0.090 182) | 7.28 / 6.64 | `--color-accent` |
| `border-strong` | outlines of inputs and controls, lines of diagrams | `#748481` oklch(0.600 0.019 182) | 3.75 / 3.48 | `#6b7775` oklch(0.560 0.015 182) | 4.00 / 3.65 | `--color-border-strong` |
| `border` | separators, outlines of round buttons, decorative | `#d4dddb` oklch(0.890 0.010 182) | 1.32 / 1.23 | `#2c3533` oklch(0.320 0.013 182) | 1.47 / 1.34 | `--color-border` |

Palette B:

| Token | Light | Ratio bg / surface | Dark | Ratio bg / surface |
|---|---|---|---|---|
| `bg` | `#faf8f3` |  | `#14120d` |  |
| `surface` | `#f3f0e8` |  | `#211e15` |  |
| `text` | `#232017` | 15.33 / 14.28 | `#ece7db` | 15.16 / 13.49 |
| `text-muted` | `#5f5949` | 6.56 / 6.12 | `#9a937f` | 6.10 / 5.43 |
| `accent-text` | `#0f695e` | 6.17 / 5.75 | `#81cfc1` | 10.36 / 9.22 |
| `accent` | `#167b6f` | 4.82 / 4.50 | `#56b1a3` | 7.31 / 6.51 |
| `border-strong` | `#8a8271` | 3.58 / 3.34 | `#7d7458` | 4.02 / 3.57 |
| `border` | `#e7e3d8` | 1.20 / 1.12 | `#2b2719` | 1.25 / 1.11 |

- All text reaches 4.5:1, large Japanese headings included: WCAG 1.4.3 gives
  no pixel threshold for large CJK text, and the Digital Agency design
  system asks for 4.5:1 at every size. Outlines that are a control's only
  cue, and the focus ring, reach 3:1 (WCAG 1.4.11). The light `accent` of
  palette B reaches 4.501:1 on `surface`, with no margin.
- The logo's teal is 2.79:1 on the light background of palette A, so it
  stays inside the logo, as does its pink `#f5e1da`; there is no second
  accent.
- The accent hue has six roles: links (`accent-text`); and the focus ring,
  the current navigation item, the home page's one primary button, the
  section heading mark of 4.4 and at most two marks per diagram (`accent`).
  The current item is `text` at weight 600 with a 2 px `accent` bottom
  border, as the profile site marks it with a 2 px accent line (4.55:1
  light, 6.64:1 dark for the border in palette A); the button is `bg` text
  on an `accent` fill (4.91:1 light, 7.28:1 dark). The focus ring is a
  2 px `accent` outline, which reaches 3:1 in palette A (and reached it in
  palette B while it was compared); the three
  sites draw it in their text accent, because their gold `accent` does
  not.
- Links are underlined 1 px at an offset of 0.2em, as on the profile site,
  with the underline in the link color, so that every computed color is a
  token value (the profile site mixes the underline with transparency).
- Neutrals carry the hue of the page background, not a framework's gray
  scale, and component CSS uses tokens, not hex colors (owner's practice).
  On the three sites, neutrals and accent share one hue (4.2). Palette A
  carries that over with the logo's hue, 182, with an OKLCH chroma of at
  most 0.020 for every neutral in its source value (chosen here; the
  inherited neutrals reach 0.027 in light and 0.042 in dark). The hex values
  are rounded, so a chroma computed back from them can be slightly higher:
  0.0201 for light `text`, 0.0203 for light `text-muted`. Palette B keeps
  the warm neutrals at hues of 85.8 to 94.1, so the teal accent has a hue
  of its own.
- **Site-owned colors.** The site-owned base CSS, asides, badges and
  components use the site's tokens directly, without Starlight palette or
  shadow mappings. Asides and badges have a 1 px `border-strong` border,
  `text` on `bg`, and a text label (Note, Tip, Caution, Danger) instead of
  another accent color. Pagefind's stylesheet is normalized to the same
  tokens by the PostCSS plugin.
- Code highlighting uses at most four token colors besides `text` and
  `text-muted` (chosen here), each 4.5:1 on `surface` in both themes; the
  contrast script reads them from `tokens.css` (`--color-code-*`).
- **Code blocks.** The Astro integration renders them with Expressive Code, whose
  default themes bring hex colors of their own, adjust syntax colors below
  5.5:1 and draw shell languages as a terminal window, which item 1 of 4.3
  rules out (appendix B). `ec.config.mjs` sets:
  `themes`, a light and a dark theme that a script in `site/scripts/`
  writes from `tokens.css`, so that every syntax color is `text`,
  `text-muted` or a code color; `minSyntaxHighlightingColorContrast: 0`,
  so that those values stay as written, with the contrast script as the
  gate; theme-specific frame and marker customization, plus `styleOverrides`
  with `var()` references to site tokens for the border, scrollbars, text
  markers and title row; and
  `defaultProps: { frame: 'code' }`, so that no block becomes a terminal
  window and a title such as `nginx.conf` stays one flat row of text.
  Expressive Code's stylesheet (`/_astro/ec.<hash>.css`) and the `style`
  attributes of highlighted spans hold hex values from those themes; they
  are exempt from the hex check, and the checks below cover them.
- Checks: the contrast script over palette A and the code colors; no
  hex color in component CSS, and none in the built CSS outside
  `tokens.css` and Expressive Code's stylesheet; on three page types in both themes, every
  computed text, background and border color, code blocks and diagrams
  included, is a token value or transparent; the hex values in the `style`
  attributes of highlighted spans are code colors, `text` or `text-muted`;
  no element has the class `is-terminal`; accent tokens used only by the
  six roles.

### 4.7 Light and dark

- The default follows `prefers-color-scheme`; light applies when the browser
  states no preference. Dark text on a light background gave better
  proofreading performance (Buchner and Baumgartner 2007), in younger and
  older adults (Piepenbrock et al. 2013); Nielsen Norman Group recommends
  offering dark mode for long reading (Budiu 2020).
- The site-owned base stylesheet uses the theme order
  of the corporate and profile sites (4.2): light tokens on `:root`, dark
  ones in `@media (prefers-color-scheme: dark)` for
  `:root:not([data-theme="light"])` and on `:root[data-theme="dark"]`, so
  the OS setting works without JavaScript and the toggle overrides it.
- The dark background is not pure black (Material Design, dark theme), and
  surfaces are lighter than the page instead of casting shadows (4.3,
  item 4).
- Check: three page types in both schemes, with JavaScript on and off, pass
  the contrast check on computed colors; in dark, no computed color is
  `#000000`, and `surface` is lighter than `bg`.

### 4.8 Motion

These are the default documentation-page rules. The later homepage rebrand
allows finite, user-triggered route indications that explain a selection;
its existing 800 ms indication is recorded below. It must keep all text
readable, finish without further interaction and be static under reduced
motion. The documentation checks below do not establish homepage motion
acceptance; the interaction check covers that separately.

- Only interactive elements animate, only color, background color, border
  color, opacity and transform, for 200 ms or less (Material Design 3's
  short durations, 50 to 200 ms). The landing page changes background,
  border and text color in 160 ms, the profile site color and border color
  in 0.2 s.
- The owner's practice forbids blur-in entrances, fades longer than a
  second, entrance animation on every element, `transition: all`, and
  animation of `top`, `left`, `width` or `height`. It allows a few entrance
  animations per page: about five, of 0.5 s, moving only `translateY` and
  `opacity`, which the corporate site uses (4.2).
- This site uses no entrance or scroll-triggered animation at all (chosen
  here; the owner chose it on the specimens of step 2, 4.12): documentation
  pages are read and searched more than they are presented, and the home
  page's first content is code.
- `prefers-reduced-motion: reduce` sets durations to 0 (WCAG 2.3.3).
- Checks: on three page types, every computed `transition-duration` and
  `animation-duration` is 200 ms or less, and 0 under the
  `prefers-reduced-motion: reduce` emulation; no `transition-property: all`
  and no animation of `top`, `left`, `width` or `height` in the built CSS;
  no animation runs when a page loads.

### 4.9 Narrow screens

- One column below 768 px (the Digital Agency design system's layout
  example). The sidebar becomes a menu, and "On this page" moves to the top
  of the content as a plain list: a table of contents collapsed and pinned
  to the top went unnoticed by many participants of Nielsen Norman Group's
  tests (2023).
- No horizontal page scroll. WCAG 1.4.10 asks for reflow at 320 CSS px,
  and writers keep that in mind; the check measures the iPhone pattern of
  "Site design acceptance" (402 px in WebKit). On 2026-10-30 the owner
  required code to be readable without horizontal scrolling (「横スクロールを
  強制」は「絶対やめて」). Code blocks soft-wrap, including long paths and
  tokens; copying keeps the original source. This supersedes the earlier
  cut-off-code treatment. Tables and inline-code cells must also be readable
  without forced sideways scrolling: wrap identifiers and restructure status
  ledgers into sections. A genuinely wide comparison needs a readable narrow
  representation rather than a scrollbar as its only access. Diagrams do not
  scroll sideways; they take a vertical arrangement instead (3.5).
- **Right edge.** At 402 px in WebKit (the iPhone pattern of "Site design
  acceptance"), the longest line of
  every Japanese text block (`lang="ja"`) of two or more lines ends less
  than 2 em of the block's font size from the block's right edge; failing
  blocks are listed by selector. The rule comes from the owner's practice
  for Japanese text, which can wrap between any two characters. English wraps
  only between words, so a line can end a long identifier's width from the
  edge; for English blocks the check is only that no `text-wrap: pretty`
  or `balance` applies. WebKit is measured because it is the engine of
  Safari on iPhone.
- Japanese h2 wrap by phrase (4.4), so they are left out of the 2 em
  check: at 402 px a 22 px h2 holds about 14 characters per line beside the
  inline mark of 4.4, and a break before a phrase leaves that phrase's
  length free. Instead (chosen here) they take at most two lines at 402 px,
  and the longest line ends less than 6 em from the right edge; a longer
  gap marks a phrase to split with another `<wbr>`. Japanese h1 take one
  line at 402 px (4.4).
- Targets at least 24 by 24 CSS px (WCAG 2.5.8), header buttons and menu
  rows 44 by 44 (owner's practice, as on the profile site; Apple's Human
  Interface Guidelines give 44 by 44 points). The fixed header never covers
  the focused element (WCAG 2.4.11), checked by tabbing through each page
  in both engines.

### 4.10 Header, footer and the language link

- **Wide screens**: logo and wordmark (home; the wordmark in the monospace
  face), the five section links, search, the version link, the language
  link, the theme toggle, and GitHub with a text label and its mark in
  black or white only (GitHub's logo guidelines). 64 px high, as the
  corporate and profile headers and the landing page's header at 900 px
  and below; opaque `surface`, as the landing page's header; 1 px bottom
  border. The landing page's 88 px suits a page with one call to action,
  not a documentation header (chosen here). Links
  are at least 44 px high, 15 px at weight 600; the current page is `text`
  with a 2 px `accent` bottom border (4.6).
- **The theme toggle and the menu button** are 44 px round buttons that
  show an icon, carry their name as text for assistive technology, and
  have a 1 px `border` outline, as on the profile site. The icon, not the
  outline, identifies the button, so the outline needs no 3:1 contrast
  (WCAG 1.4.11, Understanding).
- **The language link** follows the U.S. Web Design System's pattern for two
  languages on wide screens: one control at the top right, separate from
  the navigation, before the theme toggle, naming the other language in
  that language: "日本語" on English pages, "English" on Japanese pages. It
  is a pill with a 1 px `border` outline, as on the profile site. It leads
  to the same page in the other language. No language is picked from
  `Accept-Language` or location; no flags. The site component renders a
  plain link, which works without JavaScript.
- **Section links and the menu.** The section links stand in the header
  from 76rem (1216 px) on English pages and from 88rem (1408 px) on
  Japanese pages. Below that they are in the menu: behind the menu button
  on pages without a sidebar, at the top of the sidebar on pages with one.
  The Japanese labels (ドキュメント, エージェントプロキシ, 開発に参加する)
  are longer than the English ones. In Chromium, with or without the
  sidebar, the header holds every item on one line from 1136 px in
  English, and in Japanese from 1352 px in Hiragino Sans and 1344 px in
  Noto Sans JP; 88rem stays above both. The labels of the header do not
  break inside a word (`white-space: nowrap`). The owner on 2026-11-01:
  「英語はいいんやけど、日本語のとき、英語のヘッダーがバーガーメニューに切り替わるタイミングだとヘッダーの文字列が折れ曲がる。もっとはやくハンバーガーメニューにしないといけないっぽい」.
- **Narrow screens** (640 px and below): logo, wordmark, search, the theme
  toggle and the menu button stay. The language link becomes the first item
  of the menu, under the heading "Language", as on the profile site; the
  Digital Agency's language selector puts it into the menu when the page
  has a menu button (appendix C). The rest of the header moves into the
  menu as well.
- **Footer**: 1 px top border, 14 px `text-muted`, 48 px above and 32 px
  below, as on the profile site. As on the corporate site, one footer
  component serves every page, so that every page reaches the same links:
  the language link, Releases, Security, the license and GitHub. The license
  is labeled MIT and links to the `LICENSE` file of the page's version.
  The footer holds text links only, and wraps as a unit at narrow widths.
- **Project badges.** The four index pages (`/`, `/ja/`, `/v2/` and
  `/v2/ja/`) show one row of badges directly above the heading, at its left
  edge: CI (`test.yml`) and CodeQL (`codeql.yml`) of the branch that the
  page describes, `next` on the 3.x pages and `master` on the 2.x pages,
  each linking to its workflow's runs on that branch; OpenSSF Best
  Practices, linking to project 16057; and the license, an SVG of the site
  in the flat style of the OpenSSF badge without its gradient (4.3, item
  5), linking to the `LICENSE` file of that branch, as the footer does.
  The owner decided on 2026-11-01 that the badges stand above
  the hero heading and not in the footer:
  「footerにおいても誰もみないからなぁ、開発プロセスちゃんとやって理という意味では見せるべきな気がするので」.
  A CI badge shows only the branch that its page describes, so the status
  of `next` never stands beside the 2.x documentation, nor that of
  `master` beside the 3.x pages. The row shows the project's state and is
  not decoration (4.3): the images keep their services' colors, nothing
  recolors them, no label, frame or icon is added, and no text turns a
  current status into a fixed certification claim. The badges are 20 px
  high, with 8 px between them and 4 px, the smallest step of 4.5, between
  the row and the heading; their links are 24 px high (4.9). Each image has
  the width and height of its badge and is not lazy-loaded, since it is in
  the first view, so the heading does not move while the images load or
  when they fail. The row takes one line at 1440 px and wraps to at most
  two at 402 px. `check-project-badges.mjs` checks the exact links, images,
  sizes and alt text of the row on the four pages, the absence of a row on
  every other page, and a footer of text links; in a browser, in the two
  configured patterns in light and dark, it checks the size of each badge,
  the left edge, the 4 px, the number of lines and the keyboard order, and,
  with the external images refused, that the heading stays where it is.
  The checks before the deploy serve the external badge URLs from local
  stand-ins, so GitHub or bestpractices.dev cannot hold the publication;
  `check-live.mjs` fetches the real images after the deploy, with retries.
- Check: each page's language link answers 200 with the same path under the
  other prefix; `/` with `Accept-Language: ja` returns English without a
  redirect; in Chromium at 1440 px, at the first width where the header
  holds the section links (1216 px in English, 1408 px in Japanese) and
  1 px below it, every item of the header is on one line, inside the
  header and without overlap, in both languages (`check-styles.mjs`).

### 4.11 What the owner's practice forbids and what research supports

The owner's practice forbids `text-wrap: pretty` and `balance`, phrase
wrapping in body text, a Latin face first on Japanese pages, uppercase
labels above headings, shadows on bordered cards, nested cards, translucent
panels, hover effects on surfaces that cannot be clicked, blur-in entrances,
fades over a second, entrance animation on every element,
`transition: all`, animation of `top`, `left`, `width` or `height`, hex
colors outside the tokens, radii outside a fixed set, em dashes, emoji,
decorative symbols, purple-to-blue gradients, glows and framework default
grays, and checking narrow screens in Chromium only. The values that this
proposal adds inside those rules are its own choices (chosen here), which
the owner chose on the specimens of step 2 (4.12): no shadows, gradients or
entrance animation at all, where the corporate site has a hero gradient, a
shadow on its header after scrolling and about five entrance animations
per page; the teal accent and the chroma limit of 0.020 of palette A; the
radii it uses from the inherited set; and monospace for code and
numbers.

Research and standards support 4.5:1 for all text, light by default with a
dark option, body text of 16 px or more, at most about 40 Japanese
characters per line, underlined links, few capitals, lower visual
complexity and typical layouts for first impressions (Tuch et al. 2012,
Reinecke et al. 2013), and the engine differences behind the `text-wrap`
rule. No study tests gradients, glows, emoji, radii or hover effects one by
one; those rules rest on the owner's practice and on keeping the site close
to the documentation layout readers know.

### 4.12 Decided on the specimens of step 2 (2026-10-19)

Step 2 rendered the home page and a reference page that holds one diagram
and one sample, in light and dark, at 390 by 664 and 1440 by 900 px, in
Chromium and WebKit, once for each choice below (#607). The owner chose on
2026-10-19, in a session, after seeing one contact sheet per set of the
workflow artifact `specimens` and a full-size crop of the corners of the
code blocks, and took the recommendation in each item. The option labels
the owner chose are quoted.

1. **Neutrals: palette A** ("配色 A (推奨)"). On the three sites the
   neutrals and the accent share one hue (4.2), and palette A keeps that
   rule with the teal. The alternative was palette B, the three sites' warm
   neutrals with the teal accent, whose light `accent` has no margin on
   `surface` (4.6).
2. **Monospace face: Geist Mono** ("Geist Mono (推奨)"), served by the site
   from `@fontsource-variable/geist-mono` 5.3.0 (SIL Open Font License 1.1),
   with the corporate site's system stack `"SFMono-Regular", Menlo,
   Consolas, "Liberation Mono", monospace` after it as the fallback. On this
   site code is the first content (4.3, item 1), and the screenshots and
   measurements of the steps run in CI on Linux: with the system stack they
   would check a face that readers on macOS and Windows do not see, while a
   served face is the same in the checks and for every reader. Geist Mono
   met the two conditions of the specimen: it tells 0 from O and 1 from l
   and I, and its x-height at 15 px is not larger than Inter's at 16 px
   (7.95 px against 8.73 px in Chromium on macOS, 8.00 px against 9.00 px in
   Chromium on Linux), so JetBrains Mono was not needed. The alternative was
   the system stack alone, which downloads nothing.
3. **Radius of code blocks: 12 px** ("12 px (推奨)"), inherited from the
   corporate site's code blocks, the only ones on the owner's sites, and the
   radius of the site's other content frames (asides, diagram frames, the
   home page example), so that a code block matches the frames beside it;
   8 px stays the radius of controls. The alternatives were 8 px and 0,
   Starlight's default.
4. **How cyber: the means of 4.3** ("4.3 の手段のまま (推奨)"): the teal
   accent, the dark theme, monospace for code and numbers, the opaque
   header, no shadows, gradients or entrance animation, and fewer radii.
   The specimens also showed the two further steps within 4.11 (the
   monospace face for h1 and h2 on English pages; a dark first screen on the
   home page in both themes) and the step back towards the corporate site
   and the landing page (the gold accent with palette B's neutrals, the
   corporate site's shadow on the header and its entrance animations).

Where the specimens live: the workflow artifact of the `site` run and the
owner's review in a session ("CI の artifact とこの会話 (推奨)"); no image
is committed or attached to the pull request. After the decision the site
builds only the chosen configuration; the specimen pages and their
screenshot script stay for the browser checks and the screenshots of the
later steps (5.2, section 6).

The other values marked "chosen here" are not a matter of preference: the
checks of section 6 settle them, among them the limits for Japanese headings
of 4.4 and 4.9 and the measure of 4.4.

## 5. Tooling

### 5.1 Requirements and recommendation

The tool must render `docs/` without committed copies, plus a home page;
serve English and Japanese; hold 2.x and 3.x; search without a hosted
service; offer light and dark themes; highlight nginx configuration and
Ruby; serve its own fonts; deploy to GitHub Pages from GitHub Actions under
ngx.mruby.org; read without JavaScript; and be maintainable by one person.
Of seven tools (appendix B), Astro with Starlight and Hugo with Hextra
remain. **Recommendation: Starlight.** The owner decided so on
2026-10-15 (Q1), and the site was built with it from step 1. On
2026-11-01 the owner replaced it with Astro alone and components of the
repository's own: see [5.4](#54-astro-without-starlight-decided-2026-11-01).
This subsection stays as the record of why Starlight was chosen.

1. It does the most for Japanese without code of ours: Japanese UI strings,
   `text-autospace` on Japanese pages, Pagefind search that segments
   Japanese, and a fallback for untranslated pages.
2. Reading needs no JavaScript. The two places that do, the language picker
   and the light theme, are fixed by one component override and the token
   order of 4.7.
3. Pillar F already names it, so step 6 of the v3 plan starts without
   choosing again.
4. Neither tool switches versions across two branches (Starlight only through
   a community plugin "still in early development"; Hextra's own site builds
   each git ref separately), so both need a separate build under `/v2/`,
   which is what Pillar F asks for.

Its costs: a content folder fixed at `src/content/docs` with a `title`
required on every page, which `docs/` lacks (handled by the generator of
5.2); 259 required npm packages and Node 22.12 or later; six Starlight minors
in twelve months, 0.42.0 marked potentially breaking (handled by exact
versions in `package-lock.json` and by reviewing updates with the screenshot
checks of step 3). Hugo becomes the choice if the prototype of step 1 shows
that the generator cannot keep titles, last-updated dates and language
detection, or that pinned versions do not keep Starlight stable.

### 5.2 Repository layout

- `site/` on `next`: `package.json`, `package-lock.json`,
  `astro.config.mjs`, the home pages `src/content/docs/index.mdx` and
  `ja/index.mdx`, site-owned layouts and components, `src/styles/tokens.css`, `public/`
  (logo, favicon, the verification file that Q5 keeps) and `scripts/`
  (generator and checks).
- `docs/` stays the English source, `docs/ja/` the Japanese one, both
  readable on GitHub. The drawings of the diagrams of 3.5 are
  `site/src/diagrams/<name>.svg`; their labels are in the pages of `docs/`
  and `docs/ja/`.
- **The generator** (`site/scripts/sync-docs.mjs`) runs before
  `astro build`. For each Markdown file under `docs/` except `proposals/`, it
  writes a page into `site/src/content/docs/`, at the folder of its route,
  beside the committed home pages, which `.gitignore` keeps tracked while
  it ignores the rest of the folder: the
  title from the first heading (a heading with HTML stops the build, 4.4),
  `lastUpdated` from
  `git log -1 --format=%cs -- <file>` in the schema’s explicit date field, `README.md` as the folder index, relative
  links rewritten to site routes, links into `src/` or `test/` turned into
  GitHub URLs. It turns each diagram block of 3.5 into a figure with HTML
  labels around the inlined drawing, and copies each sample of 3.5 from the
  test files that pin it. The generated reference of Pillar
  F goes the same way. Nothing generated is committed.
- **Why `next`, not a separate branch**: a documentation change and its
  rendering are reviewed in one pull request, and CI builds the site on
  every pull request. `gh-pages` shows what a separate branch does over
  time: no content change since 2016.
- **2.x**: the site workflow checks out `master` and builds its `docs/`
  with the base `/v2/` (`site/scripts/build-v2.mjs`: the build of `site/`
  in a copy of it, with `docs/` of `master` and its own search index),
  into `dist/v2/` beside the 3.x build.
- **At the promotion** (the procedure is "Promoting v3 to master" in
  `docs/DEVELOPMENT.md` on `master`), the unprefixed 3.x build moves from
  `next` to `master` and the `/v2/` build from `master` to `v2.x`, whatever
  `next` becomes afterwards, so that pages of an unreleased 3.1 never become
  the current version. The environment rule of 5.3 moves with them. Step 7
  writes this into that procedure: in its step 4, a pull request to `next`
  makes `site.yml` run on and deploy from `master` and build `/v2/` from
  `v2.x`, and removes `site-v2.yml` and `site-dispatch.yml`; on the day of
  its step 5, the owner moves the deployment branch rule to `master`; in
  its step 7, the pull request to `v2.x` points the mirrored copies of
  those two workflows at `v2.x` and the dispatch at `--ref master`.
- **Check scripts in Python**:
  [check_links.py](../../site/scripts/check_links.py) resolves the relative links and
  heading anchors of Markdown files, and [contrast.py](../../site/scripts/contrast.py)
  checks palette A of 4.6 and the code colors in `tokens.css`. Both
  run with Python 3 and no packages. The other checks of section 6 are
  Node.js scripts beside them ("The site" in AGENTS.md).

### 5.3 Deployment and previews

- `.github/workflows/site.yml` on `next` runs on pull requests to `next`
  that touch `site/`, `docs/` or the file itself, on every push to `next`,
  and on `workflow_dispatch`. Pushes are not filtered by path because
  `docs/` links to files outside `docs/` and `site/` (`AGENTS.md`,
  `build_config.rb`, `.github/workflows/test.yml` and others), and the
  generator stops on a link to a path that git does not track: a pull
  request that removes or renames such a file without touching `docs/`
  passes, and the push of its merge then fails, instead of the next pull
  request that touches `docs/`. The build job checks out `next` with full history
  and `master`, runs `npm ci`, the generator, both builds, Pagefind and the
  checks of section 6, and uploads the result. The deploy job runs
  `actions/deploy-pages` (v5.0.1) with `pages: write` and
  `id-token: write`, one deployment at a time, and only when `github.ref`
  is `refs/heads/next`; actions are pinned by commit SHA (Pillar G). Step 7
  adds the deploy job, since a deployment from `next` is refused before
  the settings below and would fail every push to `next`.
- **A change to `docs/` on `master`.** `.github/workflows/site-dispatch.yml`
  on `master`, on every push (not filtered by path, for the reason above:
  the 2.x pages link to files outside `docs/`), calls
  `gh workflow run site.yml --ref next` with the job's token and
  `permissions: actions: write`, and fails when it cannot name the run
  that the dispatch started. A
  `repository_dispatch` would run on the default branch, where setting 2
  refuses the deployment; a `workflow_dispatch` runs on the ref it names.
  GitHub's documentation allows that once the workflow has run, as
  `site.yml` has on `next` since step 1, but also says that the workflow
  must be on the default branch (appendix B). The check of step 6 settled
  it on 2026-10-30 (#656): with `actions: write` the job's token started
  `site.yml` on `next`, which was not on `master`; with `actions: read`
  GitHub refused the dispatch with HTTP 403. No token or `site.yml` on
  `master` is needed. The `master` workflows trigger only for `master`, so
  their copies merged into `next` do not run there.
- **The 2.x documentation before it merges.** `.github/workflows/site-v2.yml`
  on `master` runs on every pull request to `master`, without a path
  filter for the same reason: it checks out `next`, builds the site with `site/` and the 3.x pages of
  `next` and the 2.x pages of the pull request, and runs the checks of
  step 6, so a change to the 2.x documentation sees them before it merges.
  It builds the 3.x pages too, because the 2.x pages link to 3.x pages
  (the banner and the version link) and the search check needs both
  indexes.
  Pull requests to `next` build both parts, with `docs/` of `master`, so a
  change to `site/` that breaks `/v2/` fails there. The deploy job then
  meets a `/v2/` failure only if `master` and `next` changed in ways that
  each passed alone.
- Settings, for the owner, both in step 7 and in this order, which follows
  the `actions/deploy-pages` README (Security considerations, items 4 and
  5, quoted in appendix B): with a source branch, the environment's
  protection rules take precedence over the source branch; with GitHub
  Actions as the source, GitHub protects the environment by default.
  1. Switch the Pages source from "Deploy from a branch" to "GitHub
     Actions" and keep ngx.mruby.org as the custom domain in the settings,
     since under a custom workflow "no CNAME file is created, and any
     existing CNAME file is ignored" (GitHub Docs); then enforce HTTPS.
     `gh-pages` stays as history. The switch may itself add a rule for the
     default branch, `master`.
  2. Give the `github-pages` environment a deployment branch rule that
     allows only `next` (only `master` after the promotion), in place of
     any rule that setting 1 added. Today the environment has none
     (`deployment_branch_policy: null`). Without a rule, a workflow pushed
     on any branch, including the `claude/<topic>` branches that agents
     push, can publish ngx.mruby.org without the review and the merge
     conditions of AGENTS.md. The GitHub Pages documentation recommends "a
     deployment protection rule so that only the default branch can deploy
     to this environment", but the default branch is `master`, so that rule
     as written would refuse the deployment from `next`.

  Setting 1 comes first, because a rule for `next` set while the source is
  still a branch would let a deployment from `next` replace the live site
  early. The pull request that adds the deploy job passes CI before the
  settings and merges right after them, since what the site serves in
  between is not documented.
- **Previews.** GitHub Pages has no public per-pull-request preview:
  `actions/deploy-pages` calls its `preview` input "only in alpha currently
  and is not available to the public". Each pull request that touches
  `site/` or `docs/` builds the site, runs the checks and uploads the built
  site and the step 3 screenshots as a workflow artifact, with the measured
  values in the run summary. A preview on another host needs a token that
  pull requests from forks cannot use, so it is not proposed now.

### 5.4 Astro without Starlight (decided 2026-11-01)

On 2026-11-01 the owner decided that the site drops Starlight and is built
with Astro alone and components of the repository's own. The owner's
words: 「サイトのドキュメントに既存のドキュメントライブラリ使うの微妙じゃない？あれは人が作る場合の便利ツールであっていまはcodexとかがデザインにあったドキュメントを自前で書いたほうが良さそう、starlightだっけ」.
Asked whether to keep Starlight, the owner chose 「やめる。構想を書いて Codex に (推奨)」:
drop it, write the plan here, and have a Codex session implement it. The
Codex session starts after step 5, after the six remaining translations are merged; the handoff page
remains English with a notice by the owner’s decision. This
replaces the tool of Q1 (section 7) and the recommendation of 5.1. The
place (`site/` on `next`), the generator, the `/v2/` build, the checks, the
design of section 4 and the deployment of 5.3 stay.

The change is meant to leave every page as it is today, for readers and
for search engines. Where the output may differ, this section says so;
any other difference is a defect of the change.

**Why.** Measured on `next` at 6bb35b241 on 2026-11-01:

- The visible design is the repository's own already. `astro.config.mjs`
  replaces 8 of Starlight's components with files of `site/src/components/`
  (Banner, FallbackContentNotice, Footer, Header, PageTitle,
  MobileMenuFooter, PageFrame, ThemeProvider), and that folder holds 16
  components. The header, the menu, the footer, the banner, the fallback
  notice, the page title, the theme order of 4.7, the home pages and the
  samples are the site's.
- What remains of Starlight is plumbing: the page route and its layout, the
  content collection, the en/ja routing with the English fallback, the
  sidebar from the configuration, the table of contents, the Pagefind
  search and its dialog, Expressive Code, the heading anchors, the `<head>`
  metadata, the sitemap, the 404 page, the last-updated date and the
  previous/next links, the Japanese UI strings, `text-autospace`, and its
  base stylesheets.
- Each design change goes through an override that has to keep Starlight's
  markup. `PageFrame.astro` keeps Starlight's custom element
  `sl-sidebar-pane`, the id `starlight__sidebar`, the class
  `sl-menu-button` and the cascade layer `starlight.core`, so that
  Starlight's scripts and styles still find them; 12 of the 16 components
  import from `@astrojs/starlight` or read `Astro.locals.starlightRoute`.
  The four stylesheets of `site/src/styles/` (tokens.css 402 lines,
  site.css 905, home.css 109, home-v3.css 109) have 168 lines that name
  Starlight (`grep -c 'sl-'` per file: 93, 71, 3, 1): 105 uses of 104
  distinct `--sl-*` custom properties, 93 of them in `tokens.css`, which
  maps Starlight's variables to the site's tokens; 72 `.sl-*` class
  selectors, 54 of them `.sl-markdown-content`; and 17 `starlight-*` names.
  `site/scripts/lib/postcss-theme-colors.mjs` deletes Starlight's and
  Pagefind's color variables from their stylesheets at build time, so
  that the built CSS holds only token colors (4.6). Eight check scripts
  and `lib/code-themes.mjs` select Starlight's markup or variables.
- What the site does not override still comes from Starlight's global
  stylesheets, 955 lines in 8 files at 0.42.6 (`reset`, `props`,
  `markdown`, `anchor-links`, `asides`, `util`, `print`, `layers`), and
  from the styles of its components. Nothing in the repository shows
  which of those rules a page relies on, so an update of Starlight can
  change a page without a change here (the cost named in 5.1).

**What replaces each piece.** File names are chosen here; the
implementation may choose others and says so in its pull request.

| Piece | Today, Starlight 0.42.6 | Replacement |
|---|---|---|
| Page route and layout | Starlight injects the route of every page and renders it with its `Page.astro`, into which the overrides plug | `src/pages/[...slug].astro` renders every entry of the collection through `src/layouts/DocPage.astro`: skip link, the header of 4.10, the frame of `PageFrame.astro` (its own element name and id, no `sl-` names), the content, the table of contents and the footer. The page title is an `h1` with the id `_top`, which the skip link and the first entry of the table of contents link, and which `home.css`, `home-v3.css`, `check-styles.mjs`, `check-japanese-lines.mjs` and `screenshots.mjs` select. The home pages use the same layout without the sidebar and the table of contents, as `template: splash` does today. |
| Content collection | `docsLoader()` and `docsSchema()`, with the field `headline` added | `glob()` of `astro/loaders` over `src/content/docs/`, and a schema of the fields that the generator of 5.2 and the home pages write today (in the 55 entries at 6bb35b241: `title` 55, `slug` 53, `lastUpdated` 53, `head` 49, the searchable `identifiers` metadata of "Complete API names in search", `sidebar` 25, `description` 2, `template` 2, `prev` 2, `next` 2, `headline` 1), and `banner`, which `Banner.astro` reads for the 3.x banner of 3.4. The schema is strict, so a field outside it stops the build. MDX for the home pages through `@astrojs/mdx` directly. The generator keeps its output and its front matter. |
| en/ja routing and the fallback | Starlight's locales `root` (English, unprefixed) and `ja`; under `/ja/`, a page without a Japanese source shows the English entry with `<html lang="ja">`, the English text in an element with `lang="en"`, and `FallbackContentNotice.astro` | Astro's `i18n` configuration (`en` default and unprefixed, `ja`) for the locale of each page and its URLs. The fallback pages are made by `getStaticPaths` of the page route, as Starlight makes them: for each English entry with no Japanese one, a `/ja/` path with the English entry, `<html lang="ja">`, the English text under `lang="en"`, the notice component and the Japanese UI. Not `i18n.fallback`: in Astro 7.3.8, its default `i18n.routing.fallbackType: "redirect"` writes redirect pages, and `"rewrite"` renders the English page as it is, without the notice or the Japanese UI (Astro's configuration reference in `astro/dist/types/public/config.d.ts`, read on 2026-11-01). The generated reference (Q2) and the 2.x pages under `/v2/ja/` keep their notices. |
| Sidebar | `sidebar` of `astro.config.mjs`: two links and six groups (one link and five groups for `/v2/`), each group `autogenerate`d from a folder, ordered by `sidebar.order`, labels translated in the configuration | `src/sidebar.mjs` holds the same groups and labels for each version, and builds the entries of each group from the collection by folder and `sidebar.order`, which the generator takes from `SIDEBAR_ORDER`; entries with the same order or none follow by id, compared as Starlight compares them (`sortDirEntries` in `utils/navigation.js`). `Sidebar.astro` renders each group as `<details open>`, with the current page marked `aria-current="page"`. Starlight's `SidebarPersister`, which keeps the sidebar's state in `sessionStorage` across pages, becomes a script that scrolls the current entry into view; this is one of the allowed differences of the acceptance below. |
| Table of contents | Starlight's `starlight-toc` from the h2 and h3 of the page (its defaults, levels 2 to 3), after a first entry "Overview" (「概要」) that links `#_top`, with the current section marked by a script, and `mobile-starlight-toc` above the content on narrow screens | `TableOfContents.astro` from the `headings` that `render()` returns, levels 2 and 3, after the same first entry "Overview" (「概要」) linking `#_top`, under the same heading as today ("On this page", 「目次」), linking the heading ids; a script that marks the current section, and the narrow-screen variant as a `<details>` that opens without JavaScript. |
| Search | Starlight's `Search.astro`: a button with the `magnifier` icon and a `<dialog>` whose `<div id="starlight__search">` holds Pagefind's UI, which loads `@pagefind/default-ui` 1.5.2 with `showSubResults: true`, `showImages: false` and its translations, and imports its `css/ui.css` into the layer `starlight.core`; the index is written in Starlight's `astro:build:done` hook by Pagefind's Node API over `dist/` | `Search.astro` of the site: the same button, dialog, mount element (its own id) and keyboard shortcut, and `@pagefind/default-ui` with the same options, its stylesheet, the Japanese strings, and `baseUrl` and `bundlePath` from `import.meta.env.BASE_URL`, so that `/v2/` keeps `/v2/pagefind/`. `pagefind` and `@pagefind/default-ui` 1.5.2 become direct dependencies. The index is written by the same Node API calls (`createIndex`, `addDirectory` over `dist/`, `writeFiles` into `dist/pagefind/`) in a script that `npm run build` runs right after `astro build` and before `mark-num-cells.mjs`; `build-v2.mjs` runs `npm run build` in its copy, so it needs no change of its own. Pagefind's own segmentation of Japanese follows `<html lang="ja">`, which stays; the `data-pagefind-body`, `data-pagefind-ignore` and `data-pagefind-meta` attributes stay where they are. |
| Code highlighting | Expressive Code through Starlight (`defineEcConfig` from `@astrojs/starlight/expressive-code`, `useStarlightUiThemeColors: true`), with what Starlight's preprocessor adds: the Japanese texts of the copy button, the locale of each block from the page's path, `defaultLocale: 'en'`, the class `not-content` on every block, `cascadeLayer: 'starlight.components'`, and default `styleOverrides` (`borderWidth: '1px'`, and in `textMarkers` `lineDiffIndicatorMarginLeft: '0.25rem'`, `defaultChroma: '45'`, `backgroundOpacity: '60%'`); `<Code>` from `@astrojs/starlight/components` in `Sample.astro`, `HomeV3.astro` and `AgentFlow.astro` | Expressive Code standalone: `astro-expressive-code` 0.44.2, a direct dependency already, with `ec.config.mjs` importing from it, the themes of `lib/code-themes.mjs`, and the frame colors that `useStarlightUiThemeColors` took from `--sl-color-*` given in `styleOverrides` from the tokens. `ec.config.mjs` also carries what the preprocessor added: `pluginFramesTexts.addLocale('ja', { copyButtonTooltip: 'クリップボードにコピー', copyButtonCopied: 'コピーしました！' })`, a `getBlockLocale` that returns `ja` for files under `src/content/docs/ja/` (the fallback pages keep the English texts of their English entry, as today), `defaultLocale: 'en'`, a plugin that adds `not-content` to every block, a `cascadeLayer` below the site's rules, and the four style values above. `expressiveCode()` comes before `mdx()` in `integrations`. `<Code>` from `astro-expressive-code/components`. Not Astro's built-in Shiki: it has no frames, titles, copy button or display-only wrap that keeps the copied source unwrapped, which the pages and `check-code-layout.mjs` rely on (Site design acceptance). |
| Heading anchors and the direction of code | Astro 7.3.8's default Markdown processor is Sätteri (`satteri()`), not unified, and Starlight registers its transforms as Sätteri `hastPlugins`: `satteriHeadingIdsPlugin()` of `@astrojs/markdown-satteri`, then a plugin that wraps each heading in `div.sl-heading-wrapper` with an `a.sl-anchor-link` and a `<span class="sr-only" data-pagefind-ignore>` with the label `Section titled “…”` (`heading.anchorLabel`, which Starlight's Japanese strings leave in English), and one that sets `dir="ltr"` on every `<pre>` and `dir="auto"` on inline `<code>` | A Sätteri hast plugin of the site, registered on the default `satteri()` processor after `satteriHeadingIdsPlugin()`, as Starlight registers its own, writes the same wrapper, link and screen-reader label with the site's class names, and the same `dir` attributes; the heading ids stay those of `satteriHeadingIdsPlugin()`. |
| `<head>` | Starlight's `Head.astro`: `title`, description, canonical, the three `hreflang` links, Open Graph and Twitter tags, `og:locale`, favicon, the sitemap link, the `head` entries of the configuration and of each page, and `<meta name="generator">` for Astro and for Starlight | `Head.astro` of the site writes the same elements with the same values; the Starlight generator tag goes. |
| Sitemap | Starlight adds `@astrojs/sitemap` 3.7.4 when `site` is set, with the option `i18n` (`defaultLocale: 'root'`, `locales: { root: 'en', ja: 'ja' }`), so each of the 64 URLs of `sitemap-0.xml` carries `xhtml:link` alternates with `hreflang="en"` and `hreflang="ja"` | `@astrojs/sitemap` 3.7.4 as a direct dependency, with the same `i18n` option, so that the URL list and the alternates of each URL stay the same. |
| 404 | Starlight's not-found page, in English only (`dist/404.html`): its hero with the h1 "404" (`#_top`) and the tagline "Page not found. Check the URL or try using the search bar.", without `data-pagefind-body` and left out of the sitemap | `src/pages/404.astro` with the same h1, text and exclusions, and the language link of `LanguageLink.astro`, which already treats this page apart. |
| Last updated, previous and next | `LastUpdated` and `Pagination` of Starlight, which `Footer.astro` imports: `<time datetime="{ISO date}">` with `toLocaleDateString(lang, { dateStyle: 'medium', timeZone: 'UTC' })` ("Oct 31, 2026", 「2026/10/31」), and links titled with the sidebar labels | Two components of the site that write the same, from `lastUpdated` and the order of the sidebar, honoring `prev: false` and `next: false`. |
| Japanese UI strings | Starlight's `translations/ja` (31 strings: skip link, search, menu, table of contents, last updated, previous and next, 404 and others) and Pagefind's own | The strings that the pages show today, moved into `strings()` of `src/site-nav.mjs` with the same Japanese text; Pagefind keeps its own translations. |
| `text-autospace` | Starlight's `reset.css`: `normal` on elements under `:lang(ja)`, `initial` under other languages, `no-autospace` on `pre`, `code`, `samp` and `kbd` | The same three rules in the site's stylesheet (3.4). |
| Base styles | Starlight's global stylesheets, the styles of its components and the page-level rules of its `Page.astro` (`--sl-content-width: 67.5rem` without a sidebar, `scroll-padding-top` from the header and the narrow table of contents); the site also selects Starlight's class names without `sl-` (`.content-panel`, `.right-sidebar`, `.sidebar-content`, `header.header`, `h1#_top`) in `home.css`, `home-v3.css`, `site.css`, `check-styles.mjs`, `check-japanese.mjs` and `check-focus.mjs`; the fonts, `tokens.css`, `site.css` and the diagram stylesheets load through `customCss` in that order | The rules that the pages rely on, copied into `site/src/styles/` with Starlight's MIT notice, renamed to the site's classes, then reduced to those a page uses; the print rules stay a separate `<link media="print">`; the class `not-content` keeps its name, because `scripts/lib/diagrams.mjs` writes it into every diagram figure; the layout imports the fonts and the stylesheets in the same order. The `--sl-*` mappings of `tokens.css`, the `@layer starlight.*` blocks and the Starlight part of `postcss-theme-colors.mjs` go; the Pagefind part of the plugin stays. |
| Icons | Starlight's `Icon` (bars, close, magnifier, GitHub and the theme icons) | Inline SVG in the components that use them. |
| Theme and the attributes of `<html>` | Starlight's `ThemeProvider.astro` (wrapped by the site's): an inline script before paint that sets `data-theme` from the `localStorage` key `starlight-theme`, else from `prefers-color-scheme`; `Page.astro` writes `dir="ltr"`, `data-theme="dark"`, `data-has-sidebar` and `data-has-toc` on `<html>`. `tokens.css`, `site.css`, the `themeCssSelector` of `ec.config.mjs` (`[data-theme='dark'][data-theme-script]`, 4.7), `ThemeToggle.astro` and `PageFrame.astro` key on them | The layout writes the same attributes on `<html>`, and `ThemeProvider.astro` of the site writes the same inline script followed by the `data-theme-script` marker. The storage key stays `starlight-theme`, so that a reader's saved choice survives the change; the `#theme-icons` template, which only Starlight's theme picker reads, goes (an allowed difference of item 2 of the acceptance). |
| Accessibility defaults | Starlight's skip link, landmark labels, `aria-current` in the sidebar, the focus trap and `inert` of the open menu (the latter already in `PageFrame.astro`) | The same, in the site's components, measured by the checks below. |
| The `/v2/` build | `build-v2.mjs` with `NGX_MRUBY_SITE_VERSION=2`: base `/v2/`, the 2.x sidebar, the 2.x banner, its own search index | Unchanged; `astro.config.mjs` keeps `base`, and `src/sidebar.mjs` the 2.x groups. |

**What stays.** Astro (7.3.8 today, pinned), the generator of 5.2
(`sync-docs.mjs`) and its tests, the diagrams and samples of 3.5, the
checks of `site/scripts/`, `tokens.css` and the design of section 4, the
fonts, `mark-num-cells.mjs` and `export-docs.mjs`, the workflows and the
deployment of 5.3, and the route of every page.

**Final mobile pattern (owner decision, 2026-11-01).** The first layer
compares against the existing 390px WebKit pattern. At the end of the
rebuild, change only `PHONE.width` in `site/scripts/lib/patterns.mjs` to
402px, the owner's iPhone 17 Pro Safari width. Keep 1440px Chromium.
The owner's words: 「じゃあ402にしよう」, 「キリがないからpcの幅を超えた画面で綺麗に見えたらよくて、あとは402に調整するぐらいの基準で良さそうね」.
If many one- or two-character last lines appear at 402px, adjust the font
size and characters per line first, then only the remaining fine cases by
a few characters of wording. Do not mechanically rewrite prose for the
checker or add more width/browser combinations. The parity baseline of
#708 was measured at 390px; 390px, decided in
[#707](https://github.com/matsumotory/ngx_mruby/pull/707), was the earlier baseline; this rebuild changes the pattern to 402px.

**Order.** After step 5. [#708](https://github.com/matsumotory/ngx_mruby/pull/708)
(Codex, the first layer of the site's own components) is merged into `next`.
The owner decided on 2026-11-01 that the rest is one pull request, not split
into stages (section 7). The final implementation removes the selector flag
and Starlight dependency together; parity compares the recorded base-commit
build with the head, not two modes in the same checkout. The parts below
record the migration order: the first was merged in #708, and the remaining
two are implemented together.

- The plumbing beside Starlight (merged in #708): the layout, the page route, the
  collection, the sidebar, the table of contents, the search, the head,
  the sitemap, the 404 page and the base styles, built when
  `NGX_MRUBY_SITE_SHELL=own` is set (the name is chosen here). With the
  flag, `astro.config.mjs` leaves out `starlight()` and adds a small
  integration of the site that injects the page route, as Starlight
  injects its own, and `content.config.mjs` uses `glob()` and the site's
  schema. The components that both shells use read the route (locale,
  entry, whether the page has a sidebar) through one helper instead of
  `Astro.locals.starlightRoute`. CI builds both shells from the same commit
  and runs the parity check of the acceptance.
- The pages: the home pages, the generated pages and `/v2/` use the
  site's shell. The originally planned temporary
  `NGX_MRUBY_SITE_SHELL=starlight` mode is not retained in the final PR;
  the comparison uses the base-commit build instead.
- The removal: `@astrojs/starlight`, the overrides as overrides, the
  flag, the `--sl-*` mappings, the Starlight part of the PostCSS plugin
  and the Starlight selectors of the checks go; the parity check then
  compares with the build of the base commit. The pull request states the
  number of packages of `package-lock.json` before and after (the keys of
  `packages` without the root: 466 in the migration base, 417 after removal).

The pull request updates the text that it makes untrue: in AGENTS.md
the repository layout ("Astro with Starlight") and "The site"; in this
proposal 3.4, 3.5 (the fallback), item 5 of 4.3, 4.4 (`PageTitle.astro`,
the Banner), 4.5 (Starlight's columns and CSS), 4.6 ("Starlight's own
colors", "Code blocks"), 4.7, 4.10 and 5.2, and "Measure two patterns" of "Site design acceptance" (the phone width); Pillar F of `v3-plan.md`; and the comments of `site/` that name
Starlight. `docs/HANDOFF.md` records the state of the pull request, as AGENTS.md says.

**Migration status (2026-11-01).** [#713](https://github.com/matsumotory/ngx_mruby/pull/713)
removes the remaining Starlight layers. Its acceptance below passes at
390 px against the build of the base commit, and the phone pattern then
moves to 402 px with the root size of 4.4; the pull request quotes the
commits and the results.

**Acceptance.** Each item is measured on both versions and both
languages, on every page unless it says otherwise. The phone pattern is
402px wide in WebKit, changed from the earlier 390px baseline by this rebuild.

1. Every existing check passes: `npm test`, `npm run check`,
   `npm run check:v2`, `npm run check:browser`, `npm run check:contrast`,
   `npm run check:offline` and `npm run check:japanese-lines`, and
   `screenshots.mjs` runs. A check may change only the selectors by which
   it finds an element whose role is unchanged (`.sl-markdown-content` to
   the class of the content, `#starlight__search` to the id of the
   element where Pagefind's UI mounts, for example), never its thresholds, pages, widths, engines or themes;
   each check whose selectors changed is shown failing on a planted fault
   again, as section 6 asks of every check. The replacement passes this
   acceptance at 390 px, in a commit of its own. The commit after it moves
   the phone pattern to 402 px; it sets the root size of 4.4 for narrow
   screens, and `check-styles.mjs` then compares the type scale, the
   spacing steps and the radii in rem of that root as well as in px. That
   change moves what the sizes are measured against to the root; it does
   not widen a threshold.
2. The HTML says the same. A new script, `check-parity.mjs` (chosen here),
   reads the recorded base-commit build and the head build and fails on any difference that is not on its list of allowed
   ones. It compares the set of built files, the URLs of the sitemaps and
   the `hreflang` alternates of each; and for each page the attributes of
   `<html>` (`lang`, `dir`, `data-theme`, `data-has-sidebar`,
   `data-has-toc`), `<title>`, the description, the
   canonical URL, the three `hreflang` links, the Open Graph and Twitter
   tags, the h1, the level, id and text of each heading, the text of the
   content, the `href` of each of its links, the sequence of its elements
   without the heading-anchor wrappers, the element with `lang="en"` on
   the fallback pages and its notice, and the `data-pagefind-*`
   attributes. Allowed: the Starlight generator tag, class names and
   custom element names, hashed asset names, the `#theme-icons`
   template, and the sidebar's scroll script.
3. The layout is the same. For every page in the two patterns of "Site
   design acceptance" (1440 by 900 px in Chromium, 402 by 664 px in
   WebKit), light, and for the three pages of `screenshots.mjs` also dark,
   with the menu closed and open at 402 px and the search dialog open at
   1440 px: the
   boxes of the header items, the sidebar entries, the table of contents
   entries, the headings, paragraphs, list items, code blocks, tables,
   figures and footer links differ by at most 1 CSS px, and their computed
   `font-family`, `font-size`, `font-weight`, `line-height`, `color` and
   `background-color` are equal. The rebuild also folds the widths of
   `check-code-layout.mjs`, `check-home-interaction.mjs`,
   `check-copy-idle.mjs`, `screenshots.mjs` (and `ci-screenshots.mjs`) and
   `check-focus.mjs` into
   the two patterns of "Site design acceptance", replacing the earlier
   320/390/768/1440 px combinations. The plan had no tolerance for screenshots
   before; this one is chosen here. The screenshots of both builds go
   side by side into the workflow artifact for the review.
4. Search returns the same. `check-search-identifiers.mjs` passes, and a
   fixed list of queries returns the same URLs in the same
   order from both builds, on both versions and both languages. The list
   is the identifiers that check uses, and in Japanese the first h2 of
   each of `/ja/start/`, `/ja/guides/install/`, `/ja/reference/build/`,
   `/ja/concepts/request-phases/` and `/ja/guides/agent-proxy/` (one page
   of each kind of 3.1, and the v3 guide; chosen here).
5. Reading needs no JavaScript (`check-no-js.mjs`), and Lighthouse
   accessibility has no failed audit (`check-lighthouse.mjs`).

The change is meant to show nothing new, so the independent first reading
of "Site design acceptance" covers only the places where items 2 and 3
list a difference.

**Risks, and how each is checked.**

| Risk | How it is checked |
|---|---|
| Japanese search gets worse: Pagefind segments by `<html lang>`, so a page that loses `lang="ja"` or its `data-pagefind-*` attributes is indexed differently, and a changed UI option changes the results | items 2 and 4; Pagefind indexes as many HTML files per build as today (66 for 3.x at 6bb35b241) |
| The fallback notice or its language goes missing: the generated reference under `/ja/` and every page under `/v2/ja/` still depend on it after step 5 | `check-japanese.mjs` (the `data-notice` of each fallback page, `hreflang`), `check-v2.mjs`, and item 2 (the `lang="en"` element and its notice) |
| The mobile menu breaks: the replacement must preserve the earlier popover behavior | `check-focus.mjs`, `check-home-interaction.mjs`, `check-styles.mjs` with the menu open in both engines, `check-no-js.mjs` (the menu opens through the `popover` attribute), and item 3 at 402 px |
| The 2.x pages break: they build from another tree with another base and sidebar | `build-v2.mjs` and `check-v2.mjs` (banner, version links, search isolation) in the site workflow, `site-v2.yml` on `master`, and items 2 to 4 on `/v2/` |
| A rule of Starlight's base stylesheets that a page relies on is lost | item 3, and `check-styles.mjs` and `check-css.mjs` on the built CSS |
| A front matter field is dropped without notice | the strict schema of the collection, and item 2 |

**What is not decided.** Nothing is left to the owner. The choices of this
section that no source fixes are marked "chosen here" or given with their
reason: Expressive Code standalone instead of Astro's Shiki, Pagefind's
default UI kept, the fallback pages from `getStaticPaths` instead of
`i18n.fallback`, the sidebar scrolling to the current entry instead of
restoring its state, the file names, the flag name and the tolerance of
item 3 of the acceptance. A pull request may change any of them with its
reason, inside the acceptance above.

## 6. Implementation plan

Each step ends with checks that pass or fail on measured values. Each check
script is first shown to fail on a planted fault; once it exists, CI runs it
on every pull request that touches `site/` or `docs/`. Each step is one or
more pull requests to `next` (steps 6 and 7 also change `master`), reviewed
and merged as AGENTS.md describes; the last column says what the owner
reviews besides that.

| Step | Work | What it produces | Check | The owner reviews |
|---|---|---|---|---|
| 1 | Starlight pinned in `site/`, the generator, today's `docs/` rendered without design; `check_links.py` moved into `site/scripts/`; AGENTS.md updated: `site/` in the repository layout, and in "Build and test" the Node 22.12 toolchain, `npm ci`, `npm run build` and the checks | `site/`, `site.yml` with the build and the checks (no deployment), the built site as a workflow artifact | a fresh clone builds with `npm ci` and `npm run build`; every internal link of the built HTML resolves; every page has a title and the last-updated date of its source; a test page from `docs/ja/` is served under `/ja/` with `lang="ja"`, and the `<wbr>` in its h2 is an element of the built h2 (4.4); pages read with JavaScript off | nothing |
| 2 | `tokens.css` from the inherited tokens of 4.2 and the changes of 4.3, both palettes of 4.6, the type of 4.4, the spacing and radii of 4.5, Starlight's colors and Expressive Code's themes and frames set from the tokens; `contrast.py` moved into `site/scripts/`, reading `tokens.css`; the specimens of 4.12 | `tokens.css`, and the specimens: the home page and a reference page with one diagram and one sample, light and dark, at 390 by 664 and 1440 by 900 px, in Chromium and WebKit, one set per choice of 4.12, as screenshots and one contact sheet per set in the workflow artifact `specimens` of the `site` run; after the owner's choice, the site builds only the chosen configuration | the contrast script passes for palette A (for both palettes while they were compared) and the code colors in both themes; computed font sizes equal the scale of each language; no `text-wrap: pretty` or `balance` in the built CSS, and no hex outside `tokens.css` and Expressive Code's stylesheet; every computed color a token value, code blocks included, the span colors of Expressive Code code colors, and no `is-terminal` frame (4.6); monospace only where item 2 of 4.3 puts it; no shadow, gradient or backdrop filter (item 5 of 4.3); margins, paddings, gaps and radii from the sets of 4.5; durations of 4.8; at most 90 characters per English body line at 1440 px; no external font URL in the built site, and the build succeeds with network access blocked after `npm ci` | the specimens of the workflow artifact, in a session: the four choices of 4.12 (decided on 2026-10-19) |
| 3 | home page with the example's test (3.3, item 8), header, footer, language and version links (4.10); the sample mechanism and the diagram mechanism of 3.5, with the request phases diagram | the home page; the first diagram, as the model for the others | the example's case passes in CI and the home page shows the files it compares, with their date; no benchmark image and no performance figure without its date and method (Q8); Chromium and WebKit screenshots at 320, 390 by 664 and 1440 by 900, light and dark; no horizontal scroll at 390 px; gutters of 20 px or more; the home page heading's line count (4.4); the right-edge measurement of 4.9 on Japanese blocks and the `text-wrap` check on English ones; Lighthouse accessibility with no failed audit on three page types in both languages; visible, uncovered focus; the shadow, gradient and backdrop check of item 5 of 4.3 with the search dialog and the menu open, in both engines; language links answer 200; no redirect for `Accept-Language: ja`; the generator stops on a sample whose file or case is missing; the diagram check fails on a missing file or line range and lists changed lines; the drawings hold no `<text>` element and no color outside the tokens; diagram labels are HTML text of 14 px or more at 390 and 1440 px; the generator stops on a diagram block whose keys differ from those of its drawing; the figure has `role="img"` and an `aria-label`, and the drawing is hidden from screen readers (3.5) | the definition (3.3, item 1) and the first diagram |
| 4 | Start; Guides with the samples of 3.5; Reference with the build diagram; Concepts with the phases, filter, async and lifetime diagrams; the agent proxy page with its three v3 diagrams and today's recipes, labeled as development content; Releases, Security, Contributing; the fixes of 2.2; `README.md` reduced to the definition, links and the branch table | the pages of 3.2 except the Japanese ones and `/v2/` | no broken relative link or anchor in `docs/` or the built site; every directive in the `ngx_command_t` tables of `src/` has a section in the directive reference; `mruby_output_filter` appears in `docs/` only in a removal note; the default gems listed in the docs equal the uncommented `conf.gem` lines of `build_config.rb`; every Ruby block in the docs compiles with the bundled mruby's `mrbc`; each `examples/<use>/` starts in CI and returns the output its README states; every sample on a page names a case that exists, and every use case of `docs/use_case/` is either a sample or marked untested with the reason of 3.5; every diagram names lines that exist; every v3 diagram and sample carries the development label | nothing |
| 5 | Japanese pages: every page written by hand translated, the generated reference in English under `/ja/` with a notice (Q2) | `docs/ja/` and the `/ja/` pages | every page written by hand except the handoff page has a file in `docs/ja/`, and every generated reference page and the handoff page under `/ja/` show the notice (Q2); `lang` and reciprocal absolute `hreflang` on every page; no space between Japanese and Latin characters in `docs/ja/` outside code and URLs; at most 40 characters per Japanese body line at 1440 px; line height 1.75 to 2.0; `keep-all` and `auto-phrase` only on `h2` and diagram labels; every h1 on one line at 390 px; no h1, `<title>`, sidebar entry, table-of-contents entry or heading `id` on `/ja/` contains the text `wbr` (4.4); the right-edge measurement on `/ja/` at 390 px in WebKit, with the h2 limit of 4.9; every diagram on `/ja/` takes its labels from `docs/ja/`, with the keys of the English block, and no label overflows its place at 390 and 1440 px | nothing |
| 6 | 2.x under `/v2/` (Q4); `site-v2.yml` and `site-dispatch.yml` on `master` (5.3) | `/v2/` and its banner; the two workflows on `master` | no broken link under `/v2/`; the banner on every 2.x page; 2.x and 3.x search results do not mix; a pull request to `master` that breaks a `/v2/` link fails `site-v2.yml`; a merge into `master` that changes `docs/` starts a `site.yml` run on `next` (`gh run list --workflow site.yml --branch next --event workflow_dispatch`) | nothing |
| 7 | switch ngx.mruby.org: settings 1 and 2 of 5.3 in that order, then the pull request that adds the deploy job; on `master`, the text that says `gh-pages` holds the site or that the switch is a pull request to it, all from #568: the branch paragraph of `README.md`, and in `docs/DEVELOPMENT.md` the last sentence of promotion step 7 and the open questions "Who gives the go for the promotion and changes the repository settings in steps 2 and 3" and "Which version the site shows after the promotion"; the move of 5.2 added to "Promoting v3 to master"; Google Analytics removed (Q6), the verification file kept (Q5); Discussions turned on and linked from Contributing, the wiki turned off after the launch (Q9) | the live site at https://ngx.mruby.org/ | `https://ngx.mruby.org/` answers 200 with the deployed `index.html`; `http://` redirects to `https://`; `/googleba3435e4002729b6.html` answers 200 with its 54 bytes unchanged; no analytics script in the built site; the `github-pages` environment read back with `gh api` has custom branch policies, and its deployment branch policies list only `next`; the first deployment, and the one after a `docs/` change merged into `master`, come from `next` (`gh api repos/matsumotory/ngx_mruby/deployments?environment=github-pages`); Lighthouse on the live home page | the date of the switch; the owner changes settings 1 and 2 of 5.3 and the custom domain, and gives the go for the session to turn on Discussions and turn off the wiki with `gh api` |
| 8 | agent proxy how-to with `examples/agent-proxy/` (v3-plan step 7, part (e)); the samples of each planned feature of 3.5 as it merges | the how-to page and its samples | the example starts in CI and answers the requests of its README; each new sample names its case; Claude Code and Codex named only after both have run against the reference proxy | nothing |

Steps 1 to 7 are Pillar F's site work, which
[the v3 plan's step 6](./v3-plan.md#6-order-of-work-decided-2026-10-03-the-priority-paragraph-and-steps-2-4-7-and-8-amended-2026-10-04)
runs in parallel from its step 4. Step 2 comes before the pages of step 4,
because the tokens and the four choices of 4.12 change every page. That plan
tags `v3.0.0-beta.1` when the migration guide and the examples exist, and
`v3.0.0-rc.1` when the site and the examples are complete. The switch of
step 7 can come before rc.1, with 3.x pages under the banner of 3.4.

After step 5, a Codex session moves the site from Starlight to Astro alone
and components of the repository's own, as 5.4 describes (the owner's
decision of 2026-11-01, section 7); 5.4 has its order and its acceptance.

Layer 1 of 5.4 was introduced in
[#708](https://github.com/matsumotory/ngx_mruby/pull/708) as an opt-in shell
beside Starlight. The final migration removes that temporary dual-shell
configuration: all routes use Astro and repository-owned components, with no
Starlight dependency or shell flag. Copied code retains its MIT attribution.
Acceptance compares a base-commit build with the head using identical 2.x
input, then checks browser behavior and layout in the two configured patterns.
The acceptance passes; #713 quotes the commits and the results.
The lockfile now has 417 package entries excluding the root, down from 466
in the migration base (49 fewer); this count is not a runtime performance claim.

## 7. Decisions (2026-10-15)

The owner decided each question of the first version of this proposal on
2026-10-15. The tool of Q1 was replaced on 2026-11-01 (the last entry of
this section).

- **Q1. Tool and place.** Starlight in `site/` on `next`, built and deployed
  from `next` (5.1, 5.2), as recommended. The place stands; the tool was
  replaced on 2026-11-01 (5.4). Step 7 replaces the text on
  `master` that prepares the switch as a pull request to `gh-pages`.
- **Q2. Japanese.** Every page written by hand is translated into Japanese;
  the reference generated from `src/` stays in English under `/ja/` with a
  notice, as recommended. On 2026-10-29 the owner chose, in a session's
  question, the option 「英語のまま注記つき (推奨)」 ("English, with a notice
  (recommended)") for the handoff page as well: `/ja/contributing/handoff/`
  shows the English text of `docs/HANDOFF.md` with a Japanese notice, as
  the generated reference does.
- **Q3. A live example on the home page.** No live endpoint: the home page
  shows the example that CI compares and its response, with the date of
  the last change to those files (3.3, item 8), as recommended.
- **Q4. URLs before v3.0.0.** 2.x under `/v2/` and 3.x at unprefixed paths,
  with the development banner of 3.4 from the launch, as recommended.
- **Q5. The Google verification file.** Kept in `site/public/`, as
  recommended.
- **Q6. Analytics.** The site launches without analytics, as recommended.
- **Q7. Accent, type and how cyber.** Not one of the offered options. The
  owner answered that the design starts from the design of the owner's
  corporate site and the owner's product landing page, which the owner
  likes, and tunes the colors and the atmosphere towards cyber, and that
  the owner likes the design of the owner's profile site as well. Section 4
  derives the design from the three sites. The means of 4.3 (the teal
  accent, the dark theme rules, monospace for code and numbers, the opaque
  header, no shadows, gradients or entrance animation) are chosen here; the
  owner chose them, with the other choices of 4.12, on the specimens of
  step 2 on 2026-10-19 (below).
- **Q8. The 2014 benchmark.** Removed with the TechEmpower link; performance
  appears only as perf lane measurements with their date and method, as
  recommended.
- **Q9. Discussions and the wiki.** Discussions on, the wiki off after the
  launch, as recommended.
- **Q10. The introduction video.** No place for it until it exists, as
  recommended.
- **Q11. A comparison with njs and OpenResty.** Not the recommendation: there
  is no comparison page. It is removed from the site map (3.2) and the
  writing plan (3.3).

With these decisions, the owner asked on 2026-10-15 for many diagrams and
samples, especially for the content towards v3; 3.5 plans them.

On 2026-10-19 the owner decided the four choices of 4.12 on the specimens
of step 2, each as recommended: palette A ("配色 A (推奨)"), Geist Mono
("Geist Mono (推奨)"), code blocks at 12 px ("12 px (推奨)") and the means of
4.3 ("4.3 の手段のまま (推奨)"); and that the specimens live in the workflow
artifact and the owner's review in a session ("CI の artifact とこの会話
(推奨)"), with no image committed or attached to the pull request (4.12).

On 2026-10-29 the owner reviewed what step 3 puts before the owner, the
definition (3.3 item 1) and the first diagram, the request phases diagram,
on the screenshots of #617 (the workflow artifact `screenshots`,
`review/`), and chose "小さな直しを入れて承認 (推奨)": approve with two small
fixes. The Japanese definition says 「ネットワークのI/O」 instead of
「ネットワークの入出力」, the term that engineers use, as the English says
"network I/O". The source lines under a diagram are set as a note under
the caption, a lead line and one item per file, at the caption size of
14 px, the floor of 4.4, so that at 390 px the Japanese caption does not
read as a long paragraph (3.5, "Keeping them true").

On 2026-11-01 the owner decided that the site drops Starlight and is built
with Astro alone and components of the repository's own, asking
「サイトのドキュメントに既存のドキュメントライブラリ使うの微妙じゃない？あれは人が作る場合の便利ツールであっていまはcodexとかがデザインにあったドキュメントを自前で書いたほうが良さそう、starlightだっけ」
and choosing 「やめる。構想を書いて Codex に (推奨)」. This replaces the tool
of Q1; its place, `site/` on `next`, stands. 5.4 says what replaces each
piece that Starlight provides, the order (one pull request from a Codex session, after step 5)
and the acceptance.

On 2026-11-01 the owner decided that the replacement of Starlight is one
pull request that a Codex session writes, not several stages: 「今後も分けなくてもできるなら無駄に分けず依頼は一回で終わるようにせよ」.
The same day the owner decided that the phone width of the layout checks
becomes 402px (Safari on an iPhone 17 Pro), in the replacement's pull request:
「じゃあ402にしよう」, 「キリがないからpcの幅を超えた画面で綺麗に見えたらよくて、あとは402に調整するぐらいの基準で良さそうね」.

On 2026-11-01 the owner decided that the project badges stand in a row
above the heading of the index pages, not in the footer:
「footerにおいても誰もみないからなぁ、開発プロセスちゃんとやって理という意味では見せるべきな気がするので」.
The row holds CI and CodeQL of the branch that the page describes,
OpenSSF Best Practices and the license (4.10).

On 2026-11-01 the owner decided that the home page heading takes one line
at the PC width, in both languages:
「pcビューのヒーロータイトルは1行に収まるフォントサイズがいいかな、日英ともに」.
4.4 gives the size from 801 px; up to 800 px, and at 402 px, the heading
keeps its two lines.

On 2026-11-01, step 5 added Japanese sources for Contributing, Development,
the test guide, the release-note guide, Security and the trust boundary.
The handoff page stays in English with a Japanese notice (Q2). On these pages, `check-japanese-lines.mjs`
(Noto Sans JP, Chromium and WebKit, 320, 390, 1000 and 1440 px) and
`check-styles.mjs` (both engines, light and dark) pass. `NOTES_ONLY` holds the four
release-note pages until the 2.x wording of #703 reaches `next` through a
merge of `master`.

## Appendix A. Where comparable projects put things

Read on 2026-10-04. These are facts about what each site contains, not
design references.

| Site | Languages | Install | Documentation | Releases | Security | Community | Doc versions |
|---|---|---|---|---|---|---|---|
| [nginx.org](https://nginx.org/en/docs/) | English, Russian (`/en/`, `/ru/`) | install page, Linux packages | Introduction, How-To, Development, Modules reference | news, CHANGES per version line | `security_advisories.html`; reporting through SECURITY.md on GitHub | community page, forum | one; each directive says the version it appeared in |
| [njs](https://nginx.org/en/docs/njs/) | English, Russian | `njs/install.html` | Getting started, Reference, Project | `njs/changes.html` | `njs/security.html` with a threat model: JavaScript code is trusted like `nginx.conf` | shared with nginx.org | one; per directive |
| [mruby.org](https://mruby.org/) | English (`/ja/` answers 404) | `/downloads/` | `/docs/`, API docs from YARD | an article per release | none on the site; SECURITY.md on GitHub | Team, Libraries | one |
| [openresty.org](https://openresty.org/en/) | English, Chinese (`/en/`, `/cn/`, `hreflang`) | installation and download pages | no documentation section; components link to GitHub READMEs | changes, announcements, upgrading | none found | community page, forum | no switch |
| [caddyserver.com](https://caddyserver.com/docs/) | English | `/docs/install`, `/download` | Get Caddy, Tutorials, Reference, Articles, Developers | GitHub releases | none on the site; SECURITY.md on GitHub | forum | one |
| [envoyproxy.io](https://www.envoyproxy.io/docs) | English | Getting Started in the docs | nine sections, from About the documentation to Version history | GitHub releases, Version history | from the community page to GitHub | community page | one URL per patch version; "latest" is the development version |
| [doc.traefik.io](https://doc.traefik.io/traefik/) | English | Getting Started, Setup | thirteen groups, several named by verbs (Expose, Secure, Observe) | support periods per minor version | a Security page under Contributing | forum, plugin catalog | one URL per minor version, with a menu |

On their home pages, Envoy describes itself for cloud native and AI native
applications, including LLM streams and agent traffic, and Traefik's
headline names agents. nginx 1.31.5 added `ngx_http_json_module`, which
extracts values from a JSON document held in a variable (nginx.org news,
2026-09-02).

## Appendix B. Static site tools compared

Read on 2026-10-04 from each tool's documentation, source repository and
package registry. Package counts come from `npm install --package-lock-only
--ignore-scripts`; nothing was built.

| Tool | Status on 2026-10-04 | Languages | Versions | Local search | Without JavaScript | Packages |
|---|---|---|---|---|---|---|
| Astro + Starlight | Starlight 0.42.5, Astro 7.3.5; six Starlight minors and two Astro majors in twelve months | built in, Japanese UI strings, fallback | community plugin in early development | Pagefind, one index per language | readable; theme and pickers need scripts | 376 (259 required) |
| Hugo + Hextra | Hugo 0.167.0 (41 releases in twelve months), Hextra 0.13.0 | built in, Hextra ships `i18n/ja.yaml` | Hugo versions dimension since 0.153.0; no switch in Hextra | FlexSearch, CDN by default; or Pagefind | static HTML | one 21 MB binary |
| Docusaurus | 3.10.2, last of 3.x before v4 | built in, one app per language | built in | community plugins only | single-page application | 1,275 |
| VitePress | 1.6.4 of 2025-08-05; v2 in alpha | built in | none | MiniSearch, no Japanese splitting | single-page application | 173 |
| MkDocs + Material | Material in maintenance mode since 2025-11-05 | one project per language | `mike` commits to `gh-pages` | lunr | static HTML | Python |
| Jekyll on GitHub Pages | Jekyll 3.10.0, `github-pages` gem of 2024-08-06 | none | none | theme dependent | static HTML | Ruby gems |
| Next.js static export | 16.3.8; 86 stable releases in twelve months | by hand; no locale detection in export | none | none built in | hydrated React | 54 alone, 482 with Nextra |

Further facts behind section 5: Starlight's `docsLoader` reads only
`src/content/docs`, and `collection.ts` relies on that folder for
last-updated dates and language detection; Starlight's language picker
navigates by script (`LanguageSelect.astro`) and its light theme needs the
script of `ThemeProvider.astro`; Shiki ships `nginx`, `ruby` and
`shellsession` grammars; Hugo module mounts accept an absolute `source`;
Hextra's documented workflow also installs Go, Dart Sass and Node.js.

Behind 4.3, 4.4 and 4.6, at Starlight 2d37fd6e8: `PageTitle.astro` renders
`<h1 id={PAGE_TITLE_ID}>{Astro.locals.starlightRoute.entry.data.title}</h1>`,
an expression that Astro escapes; `Search.astro` gives the search dialog
`box-shadow: var(--sl-shadow-lg)` and its `dialog::backdrop`
`backdrop-filter: blur(0.25rem)` (lines 223 and 229 to 232). Code blocks go
through Expressive Code (`astro-expressive-code` ^0.44.0 in
`package.json`), with the default themes `starlight-dark` and
`starlight-light`. On starlight.astro.build/getting-started/ on 2026-10-04,
its stylesheet `ec.v4551.css` held 37 distinct hex colors, each highlighted
span carried its colors as hex in a `style` attribute
(`--0:#82AAFF;--1:#3B61B0`, one variable per theme), and nine blocks
rendered as `frame is-terminal`. `minSyntaxHighlightingColorContrast`
defaults to 5.5. `useStarlightUiThemeColors` defaults to `false` once
`themes` is set; with it, `theming.ts` draws the frame with `--sl-color-*`
variables, but the border with a `color-mix()` with transparency, the
scrollbars and text markers with translucent hex, and the active tab with
an accent line, which the style settings `frames.editorTabBarBackground`,
`frames.editorActiveTabBackground` and
`frames.editorActiveTabIndicatorTopColor` override. The frames plugin draws
a terminal only for `frame` `terminal`, or `auto` with a shell language
(`@expressive-code/plugin-frames` 0.44.2, `src/index.ts` line 140), and
`defaultProps` sets a prop for every block. Starlight sets the radius to 0,
the border to 1 px and the frame shadow to `none` (`preprocessor.ts` lines
92 and 93, `theming.ts` line 94). Themes load from JSON with
`ExpressiveCodeTheme.fromJSONString`. GitHub's Markdown API renders
`## 設定を<wbr>読み込む` as an h2 without the `<wbr>` and without showing it.

Behind 5.3: the `actions/deploy-pages` README (Security considerations)
says in item 4, "If your Pages site is using a source branch, the
deployment must originate from this source branch unless your environment
is protected in which case the environment protection rules take
precedence over the source branch rule", and in item 5, with GitHub Actions
as the source, "we highly recommend you also protect your environment (we
will configure it by default for you)". GitHub's "Events that trigger
workflows" runs a `repository_dispatch` with `GITHUB_REF` set to the
default branch, "only if the workflow file exists on the default branch",
and a `workflow_dispatch` on the "Branch or tag that received dispatch"; it
says "Once a workflow has run at least once, you can dispatch it against
any branch or tag via the GitHub API or GitHub CLI", while its note and the
page on running a workflow manually say that the workflow must be in the
default branch. With the `GITHUB_TOKEN`, "workflow_dispatch and
repository_dispatch events always create workflow runs" (triggering a
workflow from a workflow). The REST endpoint "Create a workflow dispatch
event" needs the "Actions" repository permission (write), and
`gh workflow run --ref` names the ref "which contains the version of the
workflow file you'd like to run".

## Appendix C. Evidence for the visual rules

"Checked" means the statement used here was compared with the original
text; "summary" means it comes from a survey summary not compared with the
original.

| Rule | Owner's practice | Source | Status |
|---|---|---|---|
| Text 4.5:1, non-text 3:1 | measured on the owner's sites | WCAG 2.2, 1.4.3 and 1.4.11 | checked, 2026-10-04 |
| Ratios compared unrounded | | WCAG 2.2, Understanding 1.4.3 | checked, 2026-10-04 |
| Links underlined | | WCAG 2.2, 1.4.1 | checked |
| Reflow at 320 px, tables and diagrams excepted | | WCAG 2.2, 1.4.10, note 2 | checked, 2026-10-04 |
| Text spacing, 200% text | | WCAG 2.2, 1.4.12 and 1.4.4 | checked, 2026-10-04 |
| Not justified | | WCAG 2.2, 1.4.8 (AAA; note 1 asks for a mechanism, not these values) | checked, 2026-10-04 |
| Targets 24 px; focus not covered | | WCAG 2.2, 2.5.8 and 2.4.11 | checked, 2026-10-04 |
| Header buttons 44 by 44 | yes | Apple Human Interface Guidelines, Accessibility | summary |
| Motion from interaction can be turned off | no blur-in entrance, no fade over a second, no entrance animation on every element, no `transition: all`, no animation of `top`, `left`, `width` or `height`; about five entrance animations per page allowed, of 0.5 s, moving only `translateY` and `opacity` | WCAG 2.2, 2.3.3 | level checked; text summary |
| Language of page and parts; `hreflang` | | WCAG 2.2, 3.1.1, 3.1.2; W3C; Google Search Central | checked |
| About 40 Japanese characters per line | 720 px columns | JLREQ 2.4.2 (a guide for books, an upper limit, not an optimum); w3c/jlreq-d drafts | checked |
| Japanese line gap | | JLREQ 2.4.2, notes 3, 4 and 6 | checked |
| English measure 45 to 90, up to 75 | | U.S. Web Design System; GOV.UK Design System | checked |
| Body 16 px, nothing below 14 px; 4.5:1 at every size | | Digital Agency design system | summary |
| Gothic legible at smaller sizes than Mincho | | Sagawa and Kurakata 2013 | summary |
| No uppercase labels | yes | Tinker 1963 | summary |
| Heading spacing by proximity | | Wertheimer 1923; Digital Agency | checked |
| Spacing in multiples of an 8 px unit | | Digital Agency design system, spacing | checked, 2026-10-04 |
| Gutters of 16 px narrow and 32 px from desktop | | U.S. Web Design System, layout grid | checked, 2026-10-04 |
| Spacing that grows at 640 px, 20 to 30 px | | GOV.UK Design System, spacing | checked, 2026-10-04 |
| Type steps of a ratio of about 1.2; Japanese headings smaller than English, line height 1.3 to 1.4; home page heading at most two lines on desktop and three on phones | yes | no study found | |
| Sizes follow roles, not a fixed number of steps | | Material Design 3, typography | summary |
| `word-break: auto-phrase` only in Chromium | | MDN browser compatibility data | checked, 2026-10-04 |
| Light default, dark option | | Buchner and Baumgartner 2007; Piepenbrock et al. 2013; Budiu 2020 | checked |
| Dark background not pure black | | Material Design 2, dark theme | summary |
| Durations of 200 ms or less | | Material Design 3, easing and duration | summary |
| No `text-wrap: pretty` or `balance`; check in WebKit too | yes | WebKit blog; MDN | checked |
| Body wraps by character, phrases only in titles and section headings | yes | JLREQ: equal line lengths are the norm | checked |
| Japanese face first on Japanese pages | yes | no study found | |
| Table of contents moves into the content on narrow screens | | Nielsen Norman Group, 2023-10-06 | checked |
| In-page navigation for long pages | | U.S. Web Design System | checked |
| Two-language toggle at the top right, in the header | | U.S. Web Design System; the Digital Agency language selector (2025-01-09) puts it into the menu instead | checked |
| Cut-off content signals horizontal scrolling | | Nielsen Norman Group, 2017 and 2018 | checked |
| No shadows on bordered cards, no nested cards, no translucent panels | yes | Tuch et al. 2012; Reinecke et al. 2013 (complexity in general) | summary |
| No hover effects on surfaces that cannot be clicked | yes | no study found | |
| Tokens only; a fixed set of radii | yes | no study found | |
| No em dash, emoji, decorative symbols, purple-to-blue gradients, glows, framework grays | yes | no study found | |
| Even color steps | | Ottosson, OKLab | summary |

## Appendix D. Sources

Read on 2026-10-04 unless another date is given.

Standards and design systems:

- W3C, Web Content Accessibility Guidelines 2.2, Recommendation 12 December
  2024: https://www.w3.org/TR/WCAG22/ ; Understanding SC 1.4.3, Contrast
  (Minimum): https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html
- W3C, Requirements for Japanese Text Layout (JLREQ), 2020-08-11:
  https://www.w3.org/TR/jlreq/ ; working drafts:
  https://github.com/w3c/jlreq-d (2026-09-29)
- W3C, Declaring language in HTML:
  https://www.w3.org/International/questions/qa-html-language-declarations ;
  Indicating the language of a link destination:
  https://www.w3.org/International/questions/qa-link-lang
- Google Search Central, Tell Google about localized versions of your page:
  https://developers.google.com/search/docs/specialty/international/localized-versions
- Digital Agency design system (2026-09-29 and 2026-09-30): typography
  https://design.digital.go.jp/dads/foundations/typography/ , spacing
  https://design.digital.go.jp/dads/foundations/spacing/ , color
  accessibility https://design.digital.go.jp/dads/foundations/color/accessibility/
- U.S. Web Design System: typography
  https://designsystem.digital.gov/components/typography/ , layout grid
  https://designsystem.digital.gov/utilities/layout-grid/ , in-page
  navigation https://designsystem.digital.gov/components/in-page-navigation/ ,
  select between two languages
  https://designsystem.digital.gov/patterns/select-a-language/two-languages/
- GOV.UK Design System, layout: https://design-system.service.gov.uk/styles/layout/ ;
  spacing: https://design-system.service.gov.uk/styles/spacing/
- Material Design 2, dark theme:
  https://m2.material.io/design/color/dark-theme.html (2026-09-29)
- Material Design 3, typography and easing and duration (summaries, not
  compared with the original): https://m3.material.io/styles/typography/overview ,
  https://m3.material.io/styles/motion/easing-and-duration
- Apple, Human Interface Guidelines, Accessibility (summary; the page did
  not render without JavaScript):
  https://developer.apple.com/design/human-interface-guidelines/accessibility
- MDN, word-break: https://developer.mozilla.org/en-US/docs/Web/CSS/word-break ;
  its compatibility data:
  https://github.com/mdn/browser-compat-data/blob/main/css/properties/word-break.json
- GitHub logo guidelines: https://brand.github.com/foundations/logo (2026-09-30)

Research:

- Buchner, A. and Baumgartner, N. (2007). Text-background polarity affects
  performance irrespective of ambient illumination and colour contrast.
  Ergonomics 50(7), 1036-1063.
- Piepenbrock, C. et al. (2013). Positive display polarity is advantageous
  for both younger and older adults. Ergonomics 56(7), 1116-1124.
- Budiu, R. (2020-02-02). Dark Mode vs. Light Mode: Which Is Better?
  Nielsen Norman Group.
- Sagawa, K. and Kurakata, K. (2013). 高齢者でも読める文字サイズはどのように決定できるか
  (how to determine a character size that older adults can read).
  Synthesiology 6(1), 33-44.
- Tinker, M. A. (1963). Legibility of Print. Iowa State University Press.
- Wertheimer, M. (1923). Untersuchungen zur Lehre von der Gestalt II.
  Psychologische Forschung 4, 301-350.
- Tuch, A. N. et al. (2012). The role of visual complexity and
  prototypicality regarding first impression of websites. International
  Journal of Human-Computer Studies 70(11), 794-811.
- Reinecke, K. et al. (2013). Predicting users' first impressions of website
  aesthetics with a quantification of perceived visual complexity and
  colorfulness. CHI 2013.
- Nielsen Norman Group: Table of Contents: The Ultimate Design Guide
  (2023-10-06), https://www.nngroup.com/articles/table-of-contents/ ; Mobile
  Tables (Schade, 2017); Carousels on Mobile Devices (Budiu, 2018).
- WebKit, Better typography with text-wrap pretty:
  https://webkit.org/blog/16547/better-typography-with-text-wrap-pretty/ ;
  MDN, text-wrap-style:
  https://developer.mozilla.org/en-US/docs/Web/CSS/text-wrap-style
- Ottosson, B. A perceptual color space for image processing:
  https://bottosson.github.io/posts/oklab/

Tools and hosting:

- Starlight: https://starlight.astro.build/guides/i18n/ ,
  https://starlight.astro.build/guides/site-search/ ,
  https://starlight.astro.build/reference/frontmatter/ ,
  https://starlight.astro.build/guides/customization/ ; source
  https://github.com/withastro/starlight at `main` 2d37fd6e8, under
  `packages/starlight/src/`: `loaders.ts`, `utils/collection.ts`,
  `style/props.css`, `style/asides.css`, `user-components/Badge.astro`,
  `components/ThemeProvider.astro`, `components/LanguageSelect.astro`,
  `components/Banner.astro`, `components/PageTitle.astro`,
  `components/Search.astro`, `integrations/expressive-code/theming.ts` and
  `preprocessor.ts`; `packages/starlight/package.json`; and
  `packages/starlight/CHANGELOG.md` line 327. Configuration reference
  (`expressiveCode`): https://starlight.astro.build/reference/configuration/ ;
  the rendered page https://starlight.astro.build/getting-started/ and its
  stylesheet `ec.v4551.css`
- Expressive Code: frames https://expressive-code.com/key-features/frames/ ,
  configuration https://expressive-code.com/reference/configuration/ ,
  style overrides https://expressive-code.com/reference/style-overrides/ ,
  themes https://expressive-code.com/guides/themes/ ; source
  https://github.com/expressive-code/expressive-code ,
  `packages/@expressive-code/plugin-frames/src/index.ts` at the tag
  `@expressive-code/plugin-frames@0.44.2`
- starlight-versions: README ("still in early development")
  https://github.com/HiDeoo/starlight-versions ; folder-based versioning
  https://starlight-versions.vercel.app/guides/about-versioning/
- Pagefind, multilingual search: https://pagefind.app/docs/multilingual/
- Astro on GitHub Pages: https://docs.astro.build/en/guides/deploy/github/
- Hugo: https://gohugo.io/configuration/module/ ,
  https://gohugo.io/content-management/multilingual/ ,
  https://gohugo.io/host-and-deploy/host-on-github-pages/ ; Hextra:
  https://imfing.github.io/hextra/docs/ , https://github.com/imfing/hextra
- Docusaurus: https://docusaurus.io/docs/versioning ,
  https://docusaurus.io/docs/search , https://docusaurus.io/blog/releases/3.10
- VitePress: https://vitepress.dev/reference/default-theme-search
- Material for MkDocs, Zensical announcement (2025-11-05):
  https://squidfunk.github.io/mkdocs-material/blog/2025/11/05/zensical/
- GitHub Pages: https://pages.github.com/versions.json ; managing a custom
  domain:
  https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site ;
  publishing source:
  https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site
- actions/deploy-pages v5.0.1: https://github.com/actions/deploy-pages
  (`action.yml`; README, Security Considerations, at `main` 368f825)
- GitHub Actions: events that trigger workflows
  https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows ;
  triggering a workflow from a workflow
  https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow ;
  manually running a workflow
  https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow ;
  REST endpoints for workflows (create a workflow dispatch event)
  https://docs.github.com/en/rest/actions/workflows ; `gh workflow run`
  https://cli.github.com/manual/gh_workflow_run
- GitHub REST endpoint for Markdown, used to render a heading with `<wbr>`
  as GitHub does: https://docs.github.com/en/rest/markdown/markdown
- Next.js static exports: https://nextjs.org/docs/app/guides/static-exports
- Fontsource `@fontsource-variable/inter` 5.3.0,
  `@fontsource-variable/noto-sans-jp` 5.3.1,
  `@fontsource-variable/geist-mono` 5.3.0 and
  `@fontsource-variable/jetbrains-mono` 5.3.0, license OFL-1.1 (`npm view`,
  2026-10-15)
- Mermaid, theming (2026-10-15): https://mermaid.js.org/config/theming.html ,
  read as its source `packages/mermaid/src/docs/config/theming.md` on the
  `develop` branch of https://github.com/mermaid-js/mermaid
- `rehype-mermaid` 3.0.0 and `astro-mermaid` 2.1.0, their READMEs and
  dependencies (`npm view`, 2026-10-15)
- GitHub Docs (2026-10-15): creating diagrams
  https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/creating-diagrams ;
  quickstart for writing on GitHub, "Adding an image to suit your visitors"
  (`<picture>` with `prefers-color-scheme`):
  https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/quickstart-for-writing-on-github
- Google Analytics, end of Universal Analytics:
  https://support.google.com/analytics/answer/11583528

The owner's sites (2026-10-15):

- The source of the owner's corporate site, the owner's product landing
  page and the owner's profile site: the heads of their private
  repositories on 2026-10-15, read for 4.1 and 4.2 (token files,
  stylesheets, components, design system documents, the brand document,
  the Japanese typography checklist, the rules for procedure pages and the
  design notes). This document names no path in them.
- The profile site's published pages: https://research.matsumoto-r.jp/ and
  https://research.matsumoto-r.jp/en/ , with the stylesheets that their
  HTML links under `/_astro/`. The two other sites answered with a sign-in
  page and with 401 that day.

This repository: the files linked above, `gh-pages` at 59c923a
(`index.html`, `googleba3435e4002729b6.html`, `git ls-tree -r -l`), the
`ngx_command_t` tables of `src/` at ec227408d, `README.md` and
`docs/DEVELOPMENT.md` on `master` at b3df70fb6, `src/`, `config.in`,
`Makefile.in`, `build.sh`, `build_config.rb`, `docs/use_case/` and `test/`
on `next` at 73fc9098f for 3.5, and the GitHub API for the
Pages settings, the environments and the default branch
(`gh api repos/matsumotory/ngx_mruby/pages`, `.../environments`,
`repos/matsumotory/ngx_mruby`).

## Appendix E. Documentation files on `next`

| File | Lines | What it holds |
|---|---|---|
| [README.md](../../README.md) | 124 | badges, links to `tree/master/docs`, the branch table, a tagline, two samples, the 2014 benchmark, a paper abstract |
| [docs/README.md](../README.md) | 76 | a copy of the 2018 wiki home page, "Welcome to ngx_mruby Wiki", with a Travis badge |
| [docs/install](../install/README.md) | 521 | a Docker trial on a 2019 image; the build from source, with nginx 1.15.6 and OpenSSL 1.0.2g in the examples |
| [docs/directives](../directives/README.md) | 509 | the directive reference |
| [docs/class_and_method](../class_and_method/README.md) | 1,641 | the Ruby API reference |
| [docs/use_case](../use_case/README.md) | 311 | seven examples, three external articles |
| [docs/test](../test/README.md) | 1,066 | the test harness, sanitizers, mock LLM upstream, soak test, callgrind comparison; starts without a heading |
| [docs/DEVELOPMENT.md](../DEVELOPMENT.md) | 88 | Vagrant on Ubuntu 18.04, subtree updates |
| [SECURITY.md](../../SECURITY.md) | 56 | supported versions, private reporting |

### Rebrand family iteration, 2026-10-29

The owner requested different inset colors for HTTP and stream, with a
stronger v3 LLM proxy variant. The current design iteration maps HTTP to
gold, stream to purple, and LLM proxy to a gold/purple inset and stronger
metallic body. The color assignment is an implementation proposal, not an
additional owner decision. Names and availability text accompany every
feature mark; color never carries the distinction alone. The metallic
SVGs are external images with no external dependencies, keeping filter IDs
isolated. Flat marks remain small-size derivatives, not the primary style.

The owner also clarified the documentation scope: "v2.7系は現状をしっかり描きつつ、v3は完成予定の実装や機能をベースに書いていけばよさそう".
The agent-proxy guide therefore states the completed v3 target while labeling
current recipes and planned capabilities. The same status table is exported
as Markdown, and the JSON index defines implemented/planned/under-design.
Undecided details remain undecided; new art makes no performance claim.


### Local surface and mobile-spacing iteration, 2026-10-29

The homepage CTA now uses a deep red face with a narrow copper upper edge
and a darker lower edge. The runtime panel has a restrained silver upper
edge. These are solid color roles; the existing no-gradient, no-shadow,
no-animation checks remain intact. Links, code colors and reference-page
styles are unchanged. The four new homepage button tokens have explicit
OKLCH sources; contrast.py additionally checks button text against its face
(8.81:1 in both themes, above the existing 4.5:1 requirement).

Below 800px the title's top padding, lead/action/version gaps, runtime
padding and section gaps are smaller. In Chromium at 390 by 844 pixels,
the Japanese sample-section entry moved from y=950.70 to y=838.70;
the `.runtime-map` layout box moved from y=540.75 to y=500.75.
This box includes padding; these coordinates do not identify the visible
inner panel border. The runtime diagram is fully visible in the first viewport.
The desktop layout positions are unchanged. These are layout measurements,
not loading-performance results. Native and Noto checks cover 80 page loads
of the English/Japanese homepages in Chromium/WebKit, both themes and
320/390/1440px widths, including search/menu states. This local iteration
is separate from the shared-image work and has not been published.

### Remove decorative start-edge stripes, 2026-10-30

The owner requested removal of the decorative vertical line beside diagrams.
The homepage runtime container now uses an even thin neutral frame, with
nesting and surface contrast identifying nginx and the embedded VM. The
roadmap note has no accent rail or compensating left padding. Documentation
quotes/asides already use uniform frames; code-pane edges and diagram
connectors convey boundaries/relationships and are retained. This changes
presentation only, not the execution model or machine-readable source.

### v3 use-case homepage, 2026-10-30

The owner asked for v3 as the main subject, concrete first-user use cases,
large diagrams and less introductory text; stable 2.7 keeps a clear secondary
entry. The same request explicitly permits bold metal reflections, depth and
motion. This overrides the earlier flat/no-gradient/no-shadow direction for
this homepage, not for reference reading surfaces. Decorative start-edge
vertical rails remain prohibited.

`HomeV3.astro` composes the English/Japanese overview. `AgentFlow.astro` shows
actual tested model routing to configured LLM upstreams; selecting a fixture
model highlights that route without sending a request. Its 800ms finite
movement is user-triggered and absent under reduced motion. It never implies
API format conversion. `McpUseCase.astro` labels the document-service routing
as an unverified use-case design and links to the canonical bilingual guide.
`TryPath.astro` leads to source-built trial/edit/check steps and Linux integration.
The representative sample is read from the existing agent-proxy test files;
its complete configuration remains available in an expandable code block.

The owner's subsequent feedback requires a unified composition: the page
background, large planes, light direction, spacing, color and motion must work
together; isolated metallic buttons and diagrams are insufficient. After #669,
the owner also rejected the opening as a landing page: the audience, problem,
use and benefit were fragmented, and implementation labels dominated the figure.

The landing page therefore starts with developers using several LLM APIs and
the purpose of managing their routes and provider keys at one proxy. It defines
ngx_mruby as a module running Ruby inside nginx, rather than a ready-made hosted
product. The reading order is purpose and development status, a request-to-rule-
to-API diagram, the source-built Hello trial, then the real routing code. The
trial explicitly bridges Hello to the model-routing guide. MCP remains a
secondary, unverified architecture candidate, followed by planned capabilities,
HTTP/TCP examples and stable-version/reference entries. Technical fixture names
are available in a disclosure, not the main diagram labels. The real Ruby
handler is visible; checked mock output and the full configuration are
expandable with their original code and copy controls intact.

A broad navy plane carries the routing steps without a nested nginx enclosure
or Ruby card. The page and figure share the light direction; copper controls
and gold/violet route states use the existing palette. There are no diagonal
wallpaper stripes behind text. The v3 sharing image uses the same background,
mark and concrete routing purpose. Visual review must include a first-time
reader explaining the product, audience, benefit and next step; color checks
alone cannot establish that the landing page works.

Directional gradients and shadows are allowed on those named homepage planes
(main frame, route stage and trial band) as well as the
existing metal surfaces, CTA, file labels and planned-feature band. They remain
prohibited on reference pages. Text shadows, backdrop filters, decorative left
rails and permanent animation remain prohibited. The checks preserve tokens,
contrast on every reading-plane stop, focus, font, wrapping and reduced motion.
The finite 800ms route indication is user-triggered and does not imply a live
network request. Visual review must assess whole-page cohesion separately from
a passing mechanical check; this design is an iteration, not an owner acceptance.
Photos remain private references and are not committed. No benchmark result,
MCP conformance, formal v3 release or completed planned API is claimed.

### One local routing example across the homepage and trial, 2026-10-30

The homepage uses the mapping of `examples/start/route.rb`, not an integration
fixture with different upstream names. It starts with model A selected and
connects the request model, selected Ruby entry, upstream credential and mock
JSON response. Selecting a model in the browser is a simulation with no network
request. The nearby trial runs the same mapping and lets the reader change the
destination and key, repeat the request, restore the source and shut it down.
The complete mapping retains its canonical copy, while the selected entry is
shown next to the result so mobile readers do not traverse a full code wall.
The advanced integration recipe remains available separately with its original
case/date/commit evidence; mock routing does not demonstrate real providers,
LLM inference, API normalization or MCP interoperability.

The reference relationship is code beside an observable result (Astro and
Tailwind), with a substantial evidence area after the product definition
(Linear, Resend, Next.js and Vite), rather than a fictitious management UI.
Keep one coherent navy/metal surface for that example, fewer nested boxes and
shared heading/radius tokens. Source, machine checks and independent first
reading are separate gates. A source rewrite is not visual acceptance.

### Follow the request before expanding the reference, 2026-10-31

Keep the accepted homepage identity while making the LLM-proxy use case
legible to a first-time reader. Explain the application developer's task,
common proxy endpoint and client key, Ruby's model-to-upstream mapping,
nginx's credential replacement and relay, then the response received by the
application. The same local mock example connects the diagram to startup and
curl. Real-provider endpoint, authentication and TLS configuration still need
separate verification; the mock must not imply inference or API conversion.

The request journey uses three ordered, naturally sized rows on desktop and
mobile. Each row pairs its operation with the actual request, mapping or
response. The short canonical mapping is visible, not collapsed beside a tall
response whose grid height leaves empty space. Full integration-test details
remain a separate disclosure. This replaces the earlier two-column selected-
entry/disclosed-mapping arrangement, not its canonical-copy requirement.

Model selection triggers one finite sequence through request, rule and
response, with 180 ms emphasis at delays 0, 180 and 360 ms. No text fades or
moves out of reach, no request is sent, and reduced motion removes the effect
without removing the selected state or ordered meaning. Restrict this timing
exception to these three homepage steps; unrelated transitions retain their
existing limit. Review the real desktop/mobile layout and first-reader
comprehension before treating the iteration as accepted.

### Site design acceptance

Read this section when starting or resuming site work, before changing content
or layout, and before presenting or publishing the result. It applies to the
homepage, trial path, documentation navigation, examples and version entry
pages. These are the sessions' working procedures; they do not change the
repository's authorization, security, review or merge rules.

**Choose the references for the job.** Current Resend, Linear, Next.js,
Supabase, Astro, Tailwind CSS and Vite are the visual references for this
rebuild. Inspect their real desktop and mobile pages, recording the URL, date,
reading order and what the code, illustration or motion helps the reader
understand. Use the relevant observations, not a collage of their components.
Technical sources such as nginx, njs and OpenResty establish capabilities;
their documentation indexes are not the visual template for this landing page.
Do not infer a current design from memory or call an unviewed page inspected.
Reference observations belong in the scoped PR, so they can evolve without
duplicating this procedure.

**Establish the reader's task before styling.** Read the actual implementation,
tests and release state. Write a short content outline identifying the user,
their problem, the concrete input, the Ruby decision, observable output, useful
consequence and how to try it. Attach source/test evidence and distinguish
implemented, planned and unverified configurations. A heading must describe
the supported purpose or operation; reject slogans and claims whose meaning
only becomes clear in a later explanation. A test fixture is evidence, not
automatically a complete user recipe or a verified external integration.

**Make one use case intelligible.** The overview should connect purpose,
example, code/result and a matching trial action in one reading sequence.
Keep detailed contracts and evidence in canonical docs. A trial of a basic
handler must not imply that it exercises the LLM proxy. v3 is the main product
direction and remains in development; the released 2.7 entry must be easy to
find. MCP construction ideas must remain distinct from verified LLM recipes.
Do not invent API normalization, provider compatibility, OAuth, billing or
performance benefits. An interactive route example must expose its input,
decision and selected destination together, including an unambiguous selected
state. Arrows alone and disconnected nouns are not a diagram.

Use the shared metallic identity across the whole composition: dark navy and
black surfaces, coherent light and reflection, silver edges and purposeful
gold, purple, copper or metallic red accents. Judge the background, typography,
controls and diagrams together. Personal reference photographs are not public
assets. Motion must help explain a real state or flow and retain its meaning
when reduced motion is enabled. Do not add decorative left-edge lines.
Read [Layout and type hierarchy](#layout-and-type-hierarchy) for shared roles.

**Inspect the complete journey.** Follow the overview's main action into the
trial and docs, and check the stable-version entry when affected. Current entry
pages must describe current use; do not lead with an old wiki introduction or
historical benchmark. Preserve useful historical references and contracts when
moving old material. Group navigation by reader task, with a clear destination
per entry, instead of packing many links into a paragraph. A capability/status
ledger should normally use sections with nearby evidence; reserve tables for
comparisons that benefit from aligned columns. Do not force horizontal scrolling
to read examples, status explanations, paths or navigation. Verify each code
area, inline-code cell and affected table, not only the page's overall width;
wrap or restructure without clipping or tiny text. Code copies retain the full
canonical source, independent of visual wrapping.

**Require an independent first reading.** Give the reviewer actual rendered
pages or full-context screenshots, the routes and supported viewports, but not
the author's intended answers or an approving summary. Before reading the
implementation rationale, the reviewer writes what the page visibly tells them:
what the software does, who would use it and why, what changes in the example,
what is available now, and the next action. They identify where each answer
comes from and any point where the reading order or diagram leaves them
guessing. An answer supplied by the author or inferred only from source code
does not count. Missing or wrong answers block design acceptance; restructure
the relevant content rather than adding another label to explain the layout.

The reviewer then checks the source claims, shared type roles and every
secondary label/arrow for necessary meaning. Inspect desktop and mobile
overviews with adjacent sections in the two patterns below, plus zoom,
keyboard focus, code copies and reduced motion. For code width, use the
existing 320/390/768/1440 px checks in both languages and require each code
region's `scrollWidth <= clientWidth + 1`. A screenshot cannot establish copy
correctness or motion behavior. Automated checks and first-reader findings are
separate evidence, and neither replaces the other.

**Measure two patterns.** The layout and wrapping checks measure only PC
at 1440 by 900 px in Chromium and iPhone Safari at 402 by 664 px in WebKit.
No other widths, browsers or font combinations are added. The owner's words
(2026-11-01):
「pcビューは決められた幅の表示領域で全画面とかでもちゃんと表示されてたらいいし、モバイルはiPhone17とかのサファリの幅で十分。勝手に色々なパターンを用意して複雑にするな」.
The words name iPhone 17 as an example. The replacement of Starlight
(5.4) sets the phone pattern to 402 px, the width of the owner's iPhone 17
Pro in Safari; the Japanese lines that wrap differently at 402 px are fixed
in the same pull request, by the size of the type first and then by a few
characters of text. The content area has a fixed width, so a correct
rendering at full screen is what the PC pattern establishes. All Japanese
pages are validated with the served Noto Sans JP (`--ja-face noto` lets a
run on macOS see what CI sees), and the Japanese home page also with
Hiragino Sans where available. This does not change the runtime stack,
which prefers Hiragino Sans where installed and falls back to Noto Sans JP.
The Japanese home heading's two-line wording and responsive size from #697
remain unchanged. `site/scripts/lib/patterns.mjs` holds the two patterns;
the scripts measure each engine in its own pattern. 4.9 stays the design
guidance for writers at narrow widths; its measurement is the iPhone
pattern.

**Leave a reproducible checkpoint.** In the PR, record the rule sections read,
content outline and evidence, reference observations, tested head, actual URLs
and viewport sizes, contextual images, the reviewer's answers, issues resolved
and checks not run. A follow-up review can focus on changed or unresolved
areas; do not repeat unchanged successful tests just to increase a count.
Before handoff, confirm AGENTS/CLAUDE/DEVELOPMENT links still reach these rules
and update HANDOFF's state. Do not mark the whole design complete while known
reader-comprehension problems remain.

### Layout and type hierarchy

The shared design procedure applies to human, Claude and Codex contributions.
Relationships and reading order come first from alignment, proximity, whitespace
and the existing heading hierarchy. Do not add a repeated caption, number or
arrow to compensate for a layout that does not communicate them. A link does
not need a trailing arrow. Retain arrows only where their direction adds
necessary meaning; disclosure chevrons, state indicators and technical mappings
are functional content. On narrow screens, stack related content closely
instead of reserving a separate row for a downward arrow.

Typography uses roles from `site/src/styles/tokens.css`, applied by shared styles:

| Role | Token / shared selector |
|---|---|
| Homepage title | `--text-home` / `h1#_top` |
| Section heading | `--text-h2` / `h2` |
| Item or peer diagram heading | `--text-h3` / `h3` |
| Body and primary control | `--text-body` |
| Supporting note, provenance or availability | `--text-caption` |
| Code | `--text-code` (the existing `--text-nav` size) |
| Navigation | `--text-nav` |

The same role has the same size within each language and breakpoint. Keep
responsive title values in the token file, not in component styles. Establish
importance through placement, spacing and restrained font weight before adding
a size. A new role or size needs an explicit reason, a shared token and visual
review; no one-off component size. Removing redundant labels must not remove
version status, unimplemented limitations, code provenance or useful instructions.

Apply the independent first-reading and actual-page review in
[Site design acceptance](#site-design-acceptance). During the subsequent type
review, compare peer heading/control roles and their computed sizes. For every
arrow or secondary label, identify the information lost without it; remove it
or fix the layout when the answer is none.

### Sharing and README identity, 2026-10-29

The product-level sharing card uses the selected metallic C/gold mark and
“Ruby inside nginx. HTTP / STREAM.” It makes no release or planned-feature
claim; page-specific titles and canonical URLs remain separate. The README
uses the same image. Feature-specific HTTP/stream/LLM marks retain their
names and availability labels on the site. Header and favicon keep their
small-size monochrome derivatives; the favicon has an opaque dark tile.
Historical `misc/logo.png` and `site/public/favicon.png` remain in place so
existing external links are not broken, but new metadata does not use them.

`site/public/brand/ngx-mruby-http.svg` remains the mark source.
`site/scripts/render-brand.mjs` renders the sharing PNG using that SVG and
Inter from the existing Fontsource dependency (SIL Open Font License 1.1).
Run `node scripts/render-brand.mjs` from `site/` after installing the pinned
dependencies and Playwright Chromium. The renderer uses only embedded local
assets; the PNG is committed for offline builds. The 1200 by 630 canvas is
this card's design choice, not an Open Graph protocol requirement.
`site/scripts/lib/brand.mjs` defines its URL path, dimensions and alternative
text for both version builds. The built-site deployment check verifies the
PNG dimensions and the unique OG/X image metadata on every generated page.

The [Open Graph protocol](https://ogp.me/) was checked on 2026-10-29 for image
URL, type, dimensions and alt properties. Local review covers full size and
300/390-pixel card widths on light and dark surrounds. Actual SNS rendering
and cache refresh remain unverified; local and HTTPS asset checks do not
claim that an external service has fetched its preview.

The development sharing image now uses the gold/purple LLM mark with
“3.x · IN DEVELOPMENT” and “LLM agent gateways / nginx + Ruby”. Generate it
with `node scripts/render-brand.mjs --v3`; the original no-flag render and
`ngx-mruby-share-v1.png` remain the stable 2.x card. The metadata selector
uses the documentation version, and deployment checks inspect both PNGs and
require the appropriate absolute OG/X URL on every page. The next README
uses the development image. Both images are product cards; page titles,
English/Japanese descriptions and canonicals remain page-specific.


### Complete API names in search, 2026-10-30

Pagefind 1.5.2 segments Japanese body text and browser queries differently
for names such as `mruby_content_handler`. A successful search for an
unrelated prefix is not evidence that the reference is reachable. The
canonical-page generator therefore derives a deduplicated identifier list
from the title and complete Markdown body and emits one searchable
`identifiers` metadata field in the page head. No manually maintained
keyword list, visible duplicate text or query rewrite is used. The search UI
hides only this indexing field, preserving other result metadata. Code and
machine-readable Markdown remain unchanged.

This uses Pagefind's documented [searchable metadata](https://pagefind.app/docs/metadata/).
`check-search-identifiers.mjs` checks that English/Japanese searches on both
versions reach the appropriate directive and Ruby reference pages, and that
an unknown exact-phrase query returns no result. The existing search UI and
version-isolation checks remain in place. Generator fixtures check complete
names in metadata and unchanged canonical code/Markdown. CI runs both checks.

# Proposal: the ngx.mruby.org site and the documentation it is built from

Status: proposal. Nothing in it is decided. Written on 2026-10-04 from
`next` at ec227408d, `master` at 1ea47b0a6 and `gh-pages` at 59c923a, from
the live site and the repository's GitHub settings read that day, and from
primary sources on design, standards and tools (appendix D, with the date
each was read).

On 2026-10-04 the owner asked for the introduction site at
https://ngx.mruby.org, unchanged since 2020, to be rebuilt as part of the
documentation work of the v3 plan
([Pillar F](./v3-plan.md#pillar-f-documentation-site-examples-video)), with
a design tuned to look slightly cyber and to lean towards open source
software and technology, with the design quality of the owner's other sites
as the bar, and for the documentation to be reorganized. This document
proposes how; 4.1 says how the design answers "slightly cyber". Section 7
lists the questions the owner decides, each with a recommendation; section
6 says which step waits for which answer.

Rules marked "owner's practice" are rules that the owner's other sites
apply, stated here in general terms. The design documents and source of
those sites are not public, so this document does not cite them. Values
marked "chosen here" are choices of this proposal, with no source that
fixes them; the owner decides them with Q7, from the specimens of step 2.

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
[v3-plan section 7](./v3-plan.md#7-decisions-made-by-the-owner-on-2026-10-03-and-2026-10-04)).
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
   long Ruby state lives, the agent proxy for users, a comparison with njs
   and OpenResty, release notes on `next` (they reached `master` with #564),
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
| `/guides/<task>/` | one task per page: access control, routing, rate limit, observability with `ngx_otel_module`, certificate lookup, TCP and UDP | [docs/use_case](../use_case/README.md), `test/conf/` | rate limit, observability, certificate lookup |
| `/guides/agent-proxy/` | what Ruby decides and what nginx relays for LLM agent traffic | [v3-plan section 4](./v3-plan.md#agent-proxy-the-v30-use-case), [mock LLM upstream](../test/README.md#mock-llm-upstream) | the page; the how-to once `examples/agent-proxy/` exists |
| `/reference/directives/` | syntax, context, phase and version per directive | [docs/directives](../directives/README.md); later generated from `ngx_command_t` | missing and stream directives |
| `/reference/ruby/` | classes and methods | [docs/class_and_method](../class_and_method/README.md); later YARD | missing methods |
| `/reference/build/` | configure options, default gems, tested nginx, mruby and OpenSSL | docs/install, `build_config.rb`, [test.yml](../../.github/workflows/test.yml) | one version table |
| `/concepts/` | the mruby VM per configuration and what lives across requests, phases, async, the trust boundary, ngx_mruby next to njs and OpenResty | [v3-plan 2.1, 3.1, 3.5](./v3-plan.md#21-code) | all pages |
| `/releases/` | changes per release, behavior changes first; branches; support periods | `docs/releases/` (#564), [Branches and versions](../../README.md#branches-and-versions) | the page; the v3 migration guide |
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
   constants that persist in a worker; a comparison with njs and OpenResty
   taken from their documentation, with dates.
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
  current release is 2.7.0, its documentation is under `/v2/`. Then the
  banner moves to 2.x pages and gives the end of 2.x support.
- Items added or changed in 3.x say "New in 3.0" or "Changed in 3.0", as
  nginx.org and njs mark the version that introduced each directive.
- Japanese pages live under `/ja/`, from `docs/ja/<path>.md`. An
  untranslated page shows the English text with a notice (Starlight's
  fallback).
- `<html lang>` on every page, `lang="en"` on English passages in Japanese
  pages (WCAG 3.1.1, 3.1.2), and `hreflang` links to the page itself and
  the other language with absolute URLs, English as `x-default` (Google
  Search Central). Search keeps one index per version and language.
- Japanese copy has no space typed between Japanese and Latin characters;
  `text-autospace`, which Starlight enables on Japanese pages since 0.39.0,
  adds the gap. No em dashes or emoji; parentheses only for identifiers and
  first uses of abbreviations (owner's practice).

## 4. Visual direction

Each rule names its source and its check; section 6 runs the checks.
Appendix C gives the evidence rule by rule.

### 4.1 How the site leans towards technology

1. **Code that runs is the identity.** The home page's first example is real
   `nginx.conf` and Ruby from a test that CI runs (3.3, item 8), followed by
   the response that the test compares on every run. No mock terminal
   windows or decorative code.
2. **Monospace where the text is code**: the wordmark `ngx_mruby`,
   directive and method names, configuration, commands. Prose, headings and
   navigation stay proportional, because they are read rather than copied.
3. **One accent from the existing logo**: the teal `#40a798` of
   [misc/logo.png](../../misc/logo.png), hue 182 in OKLCH, with neutrals of
   the same hue (4.4).
4. **Flat surfaces**: 1 px borders separate regions; no shadows, gradients,
   glows or translucent panels.
5. **Little motion** (4.6), and **structure that shows the system**: the
   sidebar mirrors the four kinds of page, and headings name the directive,
   method or task.

Not used: decorative gradients, grids of emoji or icons, glowing or lifting
cards, rows of identical feature cards, uppercase labels above headings,
hero illustrations, mock application windows.

**Slightly cyber.** The site reads slightly cyber through rules 1 to 4: code
and a real response are the first content of the home page, the wordmark
and every identifier are monospace, the dark theme puts the teal on a
near-black background of the same hue (4.4), and flat surfaces are divided
by 1 px lines. It does not use neon glows or purple-to-blue gradients,
which the owner's practice forbids (4.9). Whether this is cyber enough is
part of Q7, judged on the specimens of step 2.

### 4.2 Type

**Families.** IBM Plex Sans, IBM Plex Sans JP and IBM Plex Mono (SIL Open
Font License 1.1), served by the site from the Fontsource packages (5.3.0),
the Japanese font split by `unicode-range`. One design across Latin,
Japanese and code keeps lines that mix them even. Japanese uses gothic
(sans-serif): in a calculation by Sagawa and Kurakata for a reader of 70,
the smallest legible kanji was 13.5 pt in gothic and 14.8 pt in Mincho.
English pages list Plex Sans first; Japanese pages list Plex Sans JP first,
so that digits, quotation marks and symbols inside Japanese text take the
Japanese design (owner's practice). The alternative is the system font
stack (Q7).

**Scale.** Seven sizes per language, one per role, and no others.

| Role | English | Japanese | Weight | Line height, English / Japanese |
|---|---|---|---|---|
| Home page heading | `clamp(2rem, 1.4rem + 2vw, 2.375rem)`, 32 to 38 px | `clamp(1.625rem, 1.2rem + 1.5vw, 2rem)`, 26 to 32 px | 600 | 1.2 / 1.4 |
| Page title (h1) | 2rem, 32 px | 1.625rem, 26 px | 600 | 1.25 / 1.4 |
| Section heading (h2) | 1.625rem, 26 px | 1.375rem, 22 px | 600 | 1.3 / 1.4 |
| Subsection heading (h3) | 1.375rem, 22 px | 1.125rem, 18 px | 600 | 1.35 / 1.4 |
| Body text | 1.0625rem, 17 px | the same | 400 | 1.6 / 1.85 |
| Navigation, tables, code blocks | 1rem, 16 px | the same | 400; 600 for the current item | 1.5 / 1.7 |
| Captions, footer, notes | 0.875rem, 14 px | the same | 400 | 1.5 / 1.7 |

- **Where the values come from.** Every size except 14 px is a step of the
  owner's reference scale for Japanese text, 38, 32, 26, 22, 18, 17, 16, 15
  and 13 px, a ratio of about 1.2 (owner's practice). The smallest size is
  14 px rather than 13 or 15: nothing below 14 px, body 16 px or more
  (Digital Agency design system). Japanese headings are one step smaller
  than English ones, with a line height of 1.4, because the owner's Japanese
  typography checklist sets Japanese headings smaller than English ones,
  with a line height of 1.3 to 1.4 (owner's practice). Chosen here: body
  text at 17 px rather
  than 16, weight 600, the English heading line heights, English body text
  at 1.6 (above the 1.5 that the Digital Agency asks for body text and that
  WCAG 1.4.12 tests), and 1.5 and 1.7 for navigation and captions.
- **Seven sizes.** A survey summary of Material Design 3 suggested three to
  six steps, but Material Design 3 itself names five roles in three sizes
  each (summary), so the number here follows the seven roles of the table,
  with one size per role and language and no size outside the table.
- Capitals only for acronyms (Tinker 1963: running capitals read slower).
- **Measure.** The text column is at most 38rem (608 px): 35 Japanese
  characters at 17 px, under the "about 40" of JLREQ 2.4.2 and at the top of
  the 30 to 35 of the JLReq Task Force's draft; an estimated 70 Latin
  characters, inside the U.S. Web Design System's 45 to 90 and GOV.UK's 75.
  Check at 1440 px: Japanese body lines hold at most 40 characters (step 5)
  and English body lines at most 90, counted line by line from the client
  rectangles of the text.
- **Line height.** JLREQ 2.4.2 puts the gap between Japanese lines between
  half and a full character, nearer a full one past 35 characters, and finds
  no gain beyond that: 1.85 for Japanese body text, 1.6 for English.
- The page keeps working with the text spacing of WCAG 1.4.12 and at 200%
  text (1.4.4). Text is left-aligned, never justified (1.4.8).
- **Wrapping.** Japanese text wraps by character (`word-break: normal`,
  `line-break: strict`). Only page titles (h1) and section headings (h2)
  may wrap by phrase (owner's practice: titles and section headings). The
  home page heading is a sentence, what ngx_mruby does, so it wraps by
  character; so do h3, captions, labels and table cells (chosen here, to
  keep the owner's exception as narrow as the owner stated it). Phrase
  wrapping uses `<wbr>` at the phrase boundaries in the Japanese source of
  those headings, with `word-break: keep-all` and `overflow-wrap: anywhere`
  on `h1` and `h2` of Japanese pages only. `word-break: auto-phrase` is not
  relied on: MDN's compatibility data lists it for Chrome 119 and later,
  for Safari only in Technology Preview and not for Firefox, so WebKit
  would wrap those headings by character.
- The home page heading takes at most two lines at 1440 px and at most
  three at 390 and 320 px (owner's practice).
- No `text-wrap: pretty` or `balance` anywhere: Safari applies `pretty` to
  every line and Chromium to the last four, so the same CSS wraps
  differently per engine (WebKit blog; MDN). Starlight's Banner sets
  `text-wrap: balance` (`Banner.astro` line 16); the site overrides it.
- Prose links are underlined (WCAG 1.4.1). Version tables use tabular
  figures.
- Checks: computed font sizes equal the scale of each language; no text
  below 14 px; the built CSS has no `text-wrap: pretty` or `balance`;
  `keep-all` and `auto-phrase` appear only on the `h1` and `h2` selectors
  of Japanese pages; the line count of the home page heading at 1440, 390
  and 320 px in both languages.

### 4.3 Spacing

- Values 4, 8, 12, 16, 24, 32, 48, 64, 96 px, and no others in layout CSS.
  They are multiples of the 8 CSS px base unit of the Digital Agency design
  system's spacing page, with 4 and 12 px as half steps inside components
  (chosen here).
- Space above a heading is at least twice the space below, so the heading
  groups with its text (proximity, Wertheimer 1923; Digital Agency design
  system): h2 48 and 16 px, h3 32 and 8 px (chosen here).
- Gutters: 16 px below 640 px, 24 px from 640, 32 px from 1024. The 16 and
  32 px ends are the U.S. Web Design System's `grid-container` padding: 2
  units at narrow widths and 4 units at desktop and wider, 8 px each
  (layout grid). The 24 px step at 640 px is chosen here, after GOV.UK's
  responsive spacing, which grows at 640 px (its spacing unit 6 is 20 px
  below and 30 px above). Check: at 320 and 390 px, every text block and
  any marker in the margin is at least 16 px from both edges.
- Radius 4 px for code and inputs, 6 px for buttons, no other (chosen here,
  for small elements on pages without cards; Starlight's badges also use
  4 px). The owner's practice is a fixed set of radii; the owner's sites
  use a set of larger radii for their cards. The owner decides the set
  with Q7.
- Checks: every length that the built CSS gives to a margin, padding or
  gap is 0 or a value of the set (`auto` and percentages excepted), and
  every border radius is 0, 4 or 6 px, Starlight's own CSS included; other
  values are listed by selector and overridden in step 2.

### 4.4 Color

Each token is an OKLCH source value at hue 182, converted to sRGB hex. The
ratios are WCAG 2.2 contrast ratios against `bg` and `surface`, truncated to
two decimals and never rounded, since WCAG's Understanding document for
1.4.3 says "4.499:1 would not meet the 4.5:1 threshold".
[contrast.py](./site/contrast.py) holds the source values, converts them,
compares the unrounded ratio of every pair a role needs with its threshold
(4.5:1 wherever a role puts text on or in the color, 3:1 for outlines and
the focus ring) and exits 1 on a failure. With the light `accent` planted
at `#157c70`, which is 4.4968:1 on `surface`, it prints 4.49 and exits 1.

| Token | Role | Light | Ratio bg / surface | Dark | Ratio bg / surface |
|---|---|---|---|---|---|
| `bg` | page | `#f7fbfa` oklch(0.985 0.004 182) | | `#0e1413` oklch(0.185 0.010 182) | |
| `surface` | header, sidebar, code blocks | `#ecf3f1` oklch(0.958 0.008 182) | | `#161e1c` oklch(0.225 0.012 182) | |
| `text` | body text | `#172522` oklch(0.250 0.020 182) | 15.20 / 14.08 | `#e2eae8` oklch(0.930 0.009 182) | 15.21 / 13.88 |
| `text-muted` | captions, code comments | `#4c5c59` oklch(0.460 0.020 182) | 6.75 / 6.25 | `#a6b1ae` oklch(0.750 0.013 182) | 8.43 / 7.69 |
| `accent-text` | links | `#0f695e` oklch(0.470 0.080 182) | 6.28 / 5.82 | `#81cfc1` oklch(0.800 0.080 182) | 10.30 / 9.40 |
| `accent` | focus ring, current navigation item, primary button | `#167b6f` oklch(0.527 0.089 182) | 4.91 / 4.55 | `#56b1a3` oklch(0.700 0.090 182) | 7.28 / 6.64 |
| `border-strong` | outlines of inputs and controls | `#748481` oklch(0.600 0.019 182) | 3.75 / 3.48 | `#6b7775` oklch(0.560 0.015 182) | 4.00 / 3.65 |
| `border` | separators, decorative | `#d4dddb` oklch(0.890 0.010 182) | 1.32 / 1.23 | `#2c3533` oklch(0.320 0.013 182) | 1.47 / 1.34 |

- All text reaches 4.5:1, large Japanese headings included: WCAG 1.4.3 gives
  no pixel threshold for large CJK text, and the Digital Agency design
  system asks for 4.5:1 at every size. Outlines that are a control's only
  cue, and the focus ring, reach 3:1 (WCAG 1.4.11).
- The logo's teal is 2.79:1 on the light background, so it stays inside the
  logo, as does its pink `#f5e1da`; there is no second accent.
- The accent hue has four roles: links (`accent-text`), and the focus ring,
  the current navigation item and the home page's one primary button
  (`accent`). The current item is `accent` text at weight 600 on `surface`
  (4.55:1 light, 6.64:1 dark); the button is `bg` text on an `accent` fill
  (4.91:1 light, 7.28:1 dark).
- Neutrals carry the hue of the page background, not a framework's gray
  scale, and component CSS uses tokens, not hex colors (owner's practice).
  Here that hue is the accent's, 182, and every neutral has an OKLCH chroma
  of at most 0.020 in its source value (chosen here). The hex values are
  rounded, so a chroma computed back from them can be slightly higher:
  0.0201 for light `text`, 0.0203 for light `text-muted`.
- **Starlight's own colors.** Starlight's `props.css` defines a gray scale
  at hue 224 (for example `hsl(224, 20%, 94%)`), its own accent, orange,
  green, blue, purple and red palettes, and three shadows. `asides.css`
  draws each aside with a 0.25rem colored border at the start edge on a
  tinted blue, purple, orange or red background, and `Badge.astro` sets
  badge text to `#fff` on the same hues. These would add a framework's
  grays and four more accents, and the `hsl()` values would pass a check
  that only looks for hex. So `tokens.css` sets every `--sl-color-*`
  variable that Starlight reads (grays, white, black, the hairlines,
  `accent-low`, `accent`, `accent-high` and the five hue palettes) and the
  `--sl-badge-*` variables from the site's tokens, and the shadows to
  `none`. Asides and badges have a 1 px `border-strong` border, `text` on
  `bg`, and a text label (Note, Tip, Caution, Danger) instead of a color
  (chosen here).
- Code highlighting uses at most four token colors besides `text` and
  `text-muted` (chosen here), each 4.5:1 on `surface` in both themes; step
  2 adds them to `CODE_COLORS` in the contrast script.
- Checks: the contrast script over tokens and code colors; no hex color in
  component CSS, and none in the built CSS outside `tokens.css` (Starlight's
  `#fff` in `Badge.astro` included); on three page types in both themes,
  every computed text, background and border color on the page is a token
  value or transparent; accent tokens used only by the four roles.

### 4.5 Light and dark

- The default follows `prefers-color-scheme`; light applies when the browser
  states no preference. Dark text on a light background gave better
  proofreading performance (Buchner and Baumgartner 2007), in younger and
  older adults (Piepenbrock et al. 2013); Nielsen Norman Group recommends
  offering dark mode for long reading (Budiu 2020).
- Starlight puts dark values on `:root` and needs a script for light, so
  without JavaScript every reader gets dark. The site defines light tokens
  on `:root`, dark ones in `@media (prefers-color-scheme: dark)` for
  `:root:not([data-theme="light"])` and on `:root[data-theme="dark"]`, so the
  OS setting works without JavaScript and the toggle overrides it.
- The dark background is not pure black (Material Design, dark theme).
- Check: three page types in both schemes, with JavaScript on and off, pass
  the contrast check on computed colors.

### 4.6 Motion

- Only interactive elements animate, only color, background, opacity and
  transform, for 200 ms or less (Material Design 3's short durations, 50 to
  200 ms).
- The owner's practice forbids blur-in entrances, fades longer than a
  second, entrance animation on every element, `transition: all`, and
  animation of `top`, `left`, `width` or `height`. It allows a few entrance
  animations per page: about five, of 0.5 s, moving only `translateY` and
  `opacity`.
- This proposal uses no entrance or scroll-triggered animation at all
  (chosen here, decided with Q7): documentation pages are read and searched
  more than they are presented, and the home page's first content is code.
- `prefers-reduced-motion: reduce` sets durations to 0 (WCAG 2.3.3).
- Checks: on three page types, every computed `transition-duration` and
  `animation-duration` is 200 ms or less, and 0 under the
  `prefers-reduced-motion: reduce` emulation; no `transition-property: all`
  and no animation of `top`, `left`, `width` or `height` in the built CSS.

### 4.7 Narrow screens

- One column below 768 px (the Digital Agency design system's layout
  example). The sidebar becomes a menu, and "On this page" moves to the top
  of the content as a plain list: a table of contents collapsed and pinned
  to the top went unnoticed by many participants of Nielsen Norman Group's
  tests (2023).
- No horizontal page scroll at 320 px (WCAG 1.4.10). Code blocks and tables
  scroll in their own box and show content cut at the right edge, which
  tells readers there is more (Nielsen Norman Group, 2017).
- **Right edge.** At 390 px, in Chromium and in WebKit, the longest line of
  every Japanese text block (`lang="ja"`) of two or more lines ends less
  than 2 em of the block's font size from the block's right edge; failing
  blocks are listed by selector. The rule comes from the owner's practice
  for Japanese text, which can wrap between any two characters. English wraps
  only between words, so a line can end a long identifier's width from the
  edge; for English blocks the check is only that no `text-wrap: pretty`
  or `balance` applies. Chromium alone does not count, because the engines
  wrap differently.
- Targets at least 24 by 24 CSS px (WCAG 2.5.8), header buttons 44 by 44
  (owner's practice; Apple's Human Interface Guidelines give 44 by 44
  points). The fixed header never covers the focused element (WCAG 2.4.11),
  checked by tabbing through each page in both engines.

### 4.8 Header and the language link

- **Wide screens**: logo and wordmark (home), the five section links,
  search, the version link, the language link, the theme toggle, and GitHub
  with a text label and its mark in black or white only (GitHub's logo
  guidelines). 56 to 64 px high (chosen here, to fit the 44 px buttons and
  the 16 px navigation text), opaque `surface`, 1 px bottom border.
- **Narrow screens**: logo, wordmark, search, language link and the menu
  button stay; the rest moves into the menu.
- **The language link** follows the U.S. Web Design System's pattern for two
  languages: one control at the top right, separate from the navigation,
  naming the other language in that language: "日本語" on English pages,
  "English" on Japanese pages. It leads to the same page in the other
  language. No language is picked from `Accept-Language` or location; no
  flags. Starlight's picker is a `<select>` that navigates by script, so a
  component override replaces it with a plain link.
- Check: each page's language link answers 200 with the same path under the
  other prefix; `/` with `Accept-Language: ja` returns English without a
  redirect.

### 4.9 What the owner's practice forbids and what research supports

The owner's practice forbids `text-wrap: pretty` and `balance`, phrase
wrapping in body text, a Latin face first on Japanese pages, uppercase
labels above headings, shadows on bordered cards, nested cards, translucent
panels, hover effects on surfaces that cannot be clicked, blur-in entrances,
fades over a second, entrance animation on every element,
`transition: all`, animation of `top`, `left`, `width` or `height`, hex
colors outside the tokens, radii outside a fixed set, em dashes, emoji,
decorative symbols, purple-to-blue gradients, glows and framework default
grays, and checking narrow screens in Chromium only. The values that this
proposal adds inside those rules, the radii of 4 and 6 px, the chroma limit
of 0.020 and the absence of entrance animation, are its own choices, decided
with Q7.

Research and standards support 4.5:1 for all text, light by default with a
dark option, body text of 16 px or more, at most about 40 Japanese
characters per line, underlined links, few capitals, lower visual
complexity and typical layouts for first impressions (Tuch et al. 2012,
Reinecke et al. 2013), and the engine differences behind the `text-wrap`
rule. No study tests gradients, glows, emoji, radii or hover effects one by
one; those rules rest on the owner's practice and on keeping the site close
to the documentation layout readers know.

## 5. Tooling

### 5.1 Requirements and recommendation

The tool must render `docs/` without committed copies, plus a home page;
serve English and Japanese; hold 2.x and 3.x; search without a hosted
service; offer light and dark themes; highlight nginx configuration and
Ruby; serve its own fonts; deploy to GitHub Pages from GitHub Actions under
ngx.mruby.org; read without JavaScript; and be maintainable by one person.
Of seven tools (appendix B), Astro with Starlight and Hugo with Hextra
remain. **Recommendation: Starlight.**

1. It does the most for Japanese without code of ours: Japanese UI strings,
   `text-autospace` on Japanese pages, Pagefind search that segments
   Japanese, and a fallback for untranslated pages.
2. Reading needs no JavaScript. The two places that do, the language picker
   and the light theme, are fixed by one component override and the token
   order of 4.5.
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
  `ja/index.mdx`, component overrides, `src/styles/tokens.css`, `public/`
  (logo, favicon, the verification file of Q5) and `scripts/` (generator and
  checks).
- `docs/` stays the English source, `docs/ja/` the Japanese one, both
  readable on GitHub.
- **The generator** (`site/scripts/sync-docs.mjs`) runs before
  `astro build`. For each Markdown file under `docs/` except `proposals/`, it
  writes a page into a gitignored folder under `site/src/content/docs/`: the
  title from the first heading, `lastUpdated` from
  `git log -1 --format=%cs -- <file>` (Starlight's front matter accepts a
  date that overrides Git's), `README.md` as the folder index, relative
  links rewritten to site routes, links into `src/` or `test/` turned into
  GitHub URLs. The generated reference of Pillar F goes the same way.
  Nothing generated is committed.
- **Why `next`, not a separate branch**: a documentation change and its
  rendering are reviewed in one pull request, and CI builds the site on
  every pull request. `gh-pages` shows what a separate branch does over
  time: no content change since 2016.
- **2.x**: the deploy workflow checks out `docs/` of `master` and builds it
  with the base `/v2/`.
- **At the promotion** (the procedure is "Promoting v3 to master" in
  `docs/DEVELOPMENT.md` on `master`), the unprefixed 3.x build moves from
  `next` to `master` and the `/v2/` build from `master` to `v2.x`, whatever
  `next` becomes afterwards, so that pages of an unreleased 3.1 never become
  the current version. The environment rule of 5.3 moves with them.
- **Check scripts that exist today**:
  [check_links.py](./site/check_links.py) resolves the relative links and
  heading anchors of Markdown files, and [contrast.py](./site/contrast.py)
  checks the tokens of 4.4. Both run with Python 3 and no packages. Step 1
  moves `check_links.py` into `site/scripts/`, and step 2 moves
  `contrast.py` there and makes it read `tokens.css`.

### 5.3 Deployment and previews

- `.github/workflows/site.yml` on `next` runs on pushes to `next` touching
  `site/` or `docs/`, on `workflow_dispatch`, and on a dispatch from a small
  workflow on `master` when its `docs/` change. The build job checks out
  `next` with full history and `master`, runs `npm ci`, the generator, both
  builds, Pagefind and the checks of section 6, and uploads the result; the
  deploy job runs `actions/deploy-pages` (v5.0.1) with `pages: write` and
  `id-token: write`, one deployment at a time, actions pinned by commit SHA
  (Pillar G).
- **The 2.x documentation before it merges.** `.github/workflows/site-v2.yml`
  on `master` runs on pull requests to `master` that touch `docs/`: it
  checks out `site/` from `next`, builds `/v2/` alone and runs the checks of
  step 6, so a change to the 2.x documentation sees them before it merges.
  Pull requests to `next` build both parts, with `docs/` of `master`, so a
  change to `site/` that breaks `/v2/` fails there. The deploy job then
  meets a `/v2/` failure only if `master` and `next` changed in ways that
  each passed alone.
- Settings, for the owner:
  1. Switch the Pages source from "Deploy from a branch" to "GitHub
     Actions" and keep ngx.mruby.org as the custom domain in the settings,
     since under a custom workflow "no CNAME file is created, and any
     existing CNAME file is ignored" (GitHub Docs); then enforce HTTPS.
     `gh-pages` stays as history.
  2. Give the `github-pages` environment a deployment branch rule that
     allows only `next` (only `master` after the promotion). Today the
     environment has none (`deployment_branch_policy: null`). Without a
     rule, a workflow pushed on any branch, including the `claude/<topic>`
     branches that agents push, can publish ngx.mruby.org without the
     review and the merge conditions of AGENTS.md. The GitHub Pages
     documentation recommends "a deployment protection rule so that only
     the default branch can deploy to this environment", but the default
     branch is `master`, so that rule as written would refuse the
     deployment from `next`.
- **Previews.** GitHub Pages has no public per-pull-request preview:
  `actions/deploy-pages` calls its `preview` input "only in alpha currently
  and is not available to the public". Each pull request that touches
  `site/` or `docs/` builds the site, runs the checks and uploads the built
  site and the step 3 screenshots as a workflow artifact, with the measured
  values in the run summary. A preview on another host needs a token that
  pull requests from forks cannot use, so it is not proposed now.

## 6. Implementation plan

Each step ends with checks that pass or fail on measured values. Each check
script is first shown to fail on a planted fault; once it exists, CI runs it
on every pull request that touches `site/` or `docs/`.

| Step | Work | Check | Owner decides first |
|---|---|---|---|
| 1 | Starlight pinned in `site/`, the generator, today's `docs/` rendered without design; `check_links.py` moved into `site/scripts/`; AGENTS.md updated: `site/` in the repository layout, and in "Build and test" the Node 22.12 toolchain, `npm ci`, `npm run build` and the checks | a fresh clone builds with `npm ci` and `npm run build`; every internal link of the built HTML resolves; every page has a title and the last-updated date of its source; a test page from `docs/ja/` is served under `/ja/` with `lang="ja"`; pages read with JavaScript off | Q1 |
| 2 | tokens, type scale, code colors, Starlight's colors set from the tokens; `contrast.py` moved into `site/scripts/`, reading `tokens.css` | the contrast script passes for all token pairs and code colors in both themes; computed font sizes equal the scale of each language; no `text-wrap: pretty` or `balance` and no hex outside `tokens.css` in the built CSS; every computed color a token value (4.4); margins, paddings, gaps and radii from the sets of 4.3; durations of 4.6; at most 90 characters per English body line at 1440 px; no external font URL in the built site, and the build succeeds with network access blocked after `npm ci` | Q7 |
| 3 | home page with the example's test (3.3, item 8), header, footer, language and version links | the example's case passes in CI and the home page shows the files it compares; Chromium and WebKit screenshots at 320, 390 by 664 and 1440 by 900, light and dark; no horizontal scroll at 320; gutters of 16 px or more; the home page heading's line count (4.2); the right-edge measurement of 4.7 on Japanese blocks and the `text-wrap` check on English ones; Lighthouse accessibility with no failed audit on three page types in both languages; visible, uncovered focus; language links answer 200; no redirect for `Accept-Language: ja` | Q3, Q8, the definition |
| 4 | Start, Guides, Reference, Concepts, Releases, Security, Contributing; the fixes of 2.2; `README.md` reduced to the definition, links and the branch table | no broken relative link or anchor in `docs/` or the built site; every directive in the `ngx_command_t` tables of `src/` has a section in the directive reference; `mruby_output_filter` appears in `docs/` only in a removal note; the default gems listed in the docs equal the uncommented `conf.gem` lines of `build_config.rb`; every Ruby block in the docs compiles with the bundled mruby's `mrbc`; each `examples/<use>/` starts in CI and returns the output its README states | Q11 |
| 5 | Japanese pages | `lang` and reciprocal absolute `hreflang` on every page; no space between Japanese and Latin characters in `docs/ja/` outside code and URLs; at most 40 characters per Japanese body line at 1440 px; line height 1.75 to 2.0; `keep-all` and `auto-phrase` only on `h1` and `h2` (4.2); the right-edge measurement on `/ja/` in both engines | Q2 |
| 6 | 2.x under `/v2/`; `site-v2.yml` on `master` (5.3) | no broken link under `/v2/`; the banner on every 2.x page; 2.x and 3.x search results do not mix; a pull request to `master` that breaks a `/v2/` link fails `site-v2.yml` | Q4 |
| 7 | switch ngx.mruby.org: the settings of 5.3; on `master`, the branch paragraph of `README.md` and the open question "Which version the site shows after the promotion" in `docs/DEVELOPMENT.md` (both from #568) updated, since they say `gh-pages` holds the site and the switch is a pull request to it | `https://ngx.mruby.org/` answers 200 with the deployed `index.html`; `http://` redirects to `https://`; `/googleba3435e4002729b6.html` answers 200 with its 54 bytes unchanged, if Q5 keeps it; the `github-pages` environment read back with `gh api` has custom branch policies, and its deployment branch policies list only `next`; Lighthouse on the live home page | Q5, Q6, the date |
| 8 | agent proxy how-to with `examples/agent-proxy/` (v3-plan step 7, part (e)) | the example starts in CI and answers the requests of its README; Claude Code and Codex named only after both have run against it | none |

Steps 1 to 7 are Pillar F's site work, which
[the v3 plan's step 6](./v3-plan.md#6-order-of-work-decided-2026-10-03-the-priority-paragraph-and-steps-2-4-7-and-8-amended-2026-10-04)
runs in parallel from its step 4. That plan tags `v3.0.0-beta.1` when the
migration guide and the examples exist, and `v3.0.0-rc.1` when the site and
the examples are complete. The switch of step 7 can come before rc.1, with
3.x pages under the banner of 3.4.

## 7. Open questions

**Q1. Tool and place.** Starlight, in `site/` on `next` (5.1, 5.2). The
open question on the site in `docs/DEVELOPMENT.md` on `master` recommends
preparing the switch as a pull request to `gh-pages`; building from `next`
replaces that, and step 7 updates the text.

**Q2. Japanese: a translation or a shorter guide?** A translation of every
page written by hand, with the generated reference left in English under
`/ja/` with a notice: the reference is regenerated from `src/`, and a
translated copy would fall behind at every regeneration. Decision 9 says
"English primary, Japanese translation"; that every page written by hand is
translated is this proposal's recommendation.

**Q3. A live example on the home page?** No live endpoint. Show the example
of 3.3, item 8, and the response that its test compares on every CI run,
with the date of the last change to those files: GitHub Pages serves static
files, a live endpoint would be a server to run and secure, and the shown
response is the one CI checks.

**Q4. URLs before v3.0.0.** 2.x under `/v2/` from the launch and 3.x at
unprefixed paths under the banner of 3.4. Putting 2.x at the root until
v3.0.0 would change every URL at promotion.

**Q5. Keep the Google verification file?** Keep
`googleba3435e4002729b6.html` (54 bytes, added 2014-03-08) in `site/public/`
until the owner confirms Google Search Console is not used for the domain;
removing it can end the verification of the property.

**Q6. Analytics.** Remove the Google Analytics script and launch without
analytics; it has collected nothing since July 2023. If numbers are wanted
later, choose a tool then, with its privacy and consent requirements.

**Q7. Accent, type and how cyber.** The logo teal with the tokens of 4.4
and the IBM Plex families of 4.2, chosen from specimens rendered in step 2
(home and reference pages, light and dark) against the system font stack.
The same specimens decide the values marked "chosen here" in section 4,
among them the radii of 4 and 6 px, the chroma limit of 0.020 and the
absence of entrance animation, and whether the look is slightly cyber
enough. Recommendation for that last point: the means of 4.1 only. If the
owner wants more within the rules of 4.9, the next steps are IBM Plex Mono
for headings, or a dark first screen on the home page in both themes.

**Q8. The 2014 benchmark.** Remove the benchmark image and the TechEmpower
Round 10 link from the home page and `README.md`; show performance only as
perf lane measurements with their date and method.

**Q9. Discussions and the wiki.** Turn on GitHub Discussions for questions,
which decision 7 already assumes, and link them from Contributing; turn off
the wiki after the launch, since its one page points to `docs/`.

**Q10. The introduction video.** No place for it on the home page until it
exists; Pillar F decides its form with the owner first.

**Q11. A comparison with njs and OpenResty.** A Concepts page built from
their documentation with dates: what each runs (QuickJS, LuaJIT, mruby),
where code attaches to nginx and how state is shared, with no performance
comparison unless the measurement can be repeated.

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
| Motion from interaction can be turned off | no blur-in entrance, no fade over a second, no entrance animation on every element, no `transition: all`, no animation of `top`, `left`, `width` or `height` | WCAG 2.2, 2.3.3 | level checked; text summary |
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
  `components/Banner.astro`; and `packages/starlight/CHANGELOG.md` line 327
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
  (`action.yml`)
- Next.js static exports: https://nextjs.org/docs/app/guides/static-exports
- Fontsource `@fontsource/ibm-plex-sans`, `@fontsource/ibm-plex-sans-jp`,
  `@fontsource/ibm-plex-mono` 5.3.0, license OFL-1.1 (`npm view`)
- Google Analytics, end of Universal Analytics:
  https://support.google.com/analytics/answer/11583528

This repository: the files linked above, `gh-pages` at 59c923a
(`index.html`, `googleba3435e4002729b6.html`, `git ls-tree -r -l`), the
`ngx_command_t` tables of `src/` at ec227408d, and the GitHub API for the
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

# Handoff: the state of the work

## Site publication and handoff, 2026-10-31

- [Site rebuild #672](https://github.com/matsumotory/ngx_mruby/pull/672)
  merged into `next` as `f9baa5ef70cca7cc556209ed01cd7e19a572da0d`.
  [Maintenance entry #673](https://github.com/matsumotory/ngx_mruby/pull/673)
  merged into `master` as `263bd10e47da1273e2f6e6c88029ab0f9d988169`.
  The actual master tree equals the tested `452ad7ef` candidate; the next
  merge tree equals the tested `e8ab1175` head. No runtime release was made.
- The homepage, local routing trial and documentation now share the selected
  request, Ruby mapping, upstream credential and observed mock JSON. English
  and Japanese guides cover both routes, key replacement, editing/restoring,
  reload, shutdown and rejected requests. v3 development, current 2.7,
  historical material and unverified provider/MCP work remain distinct.
- Both PRs passed current-base CI and normal independent source/pixel review.
  The separate Copy and maintenance-entry regression pairs have independent
  red/green evidence; the earlier five-commit exception and its limits remain
  in #672. Final review records:
  [#672 source](https://github.com/matsumotory/ngx_mruby/pull/672#issuecomment-6539490814),
  [focused green](https://github.com/matsumotory/ngx_mruby/pull/672#issuecomment-6539535109),
  [#673 source/pixels](https://github.com/matsumotory/ngx_mruby/pull/673#issuecomment-6539365290)
  and [closed review gates](https://github.com/matsumotory/ngx_mruby/pull/673#issuecomment-6539579257).
  No GitHub approval review is represented.
- Production [run 41173076141](https://github.com/matsumotory/ngx_mruby/actions/runs/41173076141)
  passed build, maintenance-entry, deployment and live verification. Deployment
  `7454954421` published `next@f9baa5ef`, with the 2.x documentation of
  `master@263bd10e`; later runs of `site.yml` on `next` deploy again. The live verifier matched the deployment SHA, same-run
  artifact evidence and exact HTML on twelve read-only page visits. Desktop
  and mobile pixels were checked separately. Public entries:
  [English](https://ngx.mruby.org/) and [Japanese](https://ngx.mruby.org/ja/).
  The run retains the `live-screenshots` artifact (`13031774147`) and its
  completed source-revision evidence.
- The site CI scope and parallel browser lanes are
  [#677](https://github.com/matsumotory/ngx_mruby/pull/677), open. The runtime
  CI policy merged into `next` with
  [#676](https://github.com/matsumotory/ngx_mruby/pull/676) (`48c04d43e`); its
  `master` side, [#679](https://github.com/matsumotory/ngx_mruby/pull/679), is
  open. Neither was needed for this publication.
- The merged topic branches of #672 and #673 are deleted on GitHub. The public
  record of this work is the two PRs, their review comments above and the runs
  and artifacts they link.

## How to use this file

This file records where the work on ngx_mruby stands, so that any session,
clone or contributor can continue it: the open pull requests, the decisions
that are not written down elsewhere yet, the work in progress and the queue.

- It records state, not rules. The rules are in [AGENTS.md](../AGENTS.md).
  The plan for v3 and the owner's decisions about it are in
  [docs/proposals/v3-plan.md](proposals/v3-plan.md). Where this file
  disagrees with them, they win, with the one exception that AGENTS.md
  "Session handoff" sets: a dated row under "Decisions" holds over their
  older text until a pull request writes it there, but only when the row
  links the owner's comment or quotes the owner's words. A row with neither
  is a proposal of the sessions and changes no rule.
- A decision of the owner that is not written there yet is recorded under
  "Decisions", in short, with its date, the link or the quotation, and the
  place where it will be written. Where the sessions apply a decision with
  a procedure of their own, the row names that procedure separately.
- A pull request on `next` updates this file in the same pull request when
  it changes what the file records, its own row and the queue item that it
  finishes included. A pull request on `master` cannot, because the file is
  only on `next`: the session that merged it into `master` opens a small
  pull request on `next` that updates the file, or updates the file in the
  merge of `master` into `next` if that comes first. A release is recorded
  in the same way by the first session that finds its tag missing here.
  Link pull requests and issues instead of copying their text.
- Remove an item when its pull request is merged or closed, when its issue
  is closed, or when it is written in the place that its row names. The
  pull requests and issues keep the history (see the `gh` commands below).
- The file lives on `next`. From a checkout of another branch, read it with
  `git fetch origin next` and `git show origin/next:docs/HANDOFF.md`.
- The statements about branches, pull requests and issues were checked with
  `gh` and `git` at the time in the next heading. Check them again before
  you act on them: other sessions merge pull requests all the time.

## Site CI scope and parallel lanes, 2026-10-31

- [#677](https://github.com/matsumotory/ngx_mruby/pull/677) splits the browser
  checks of `site.yml` into six lanes and a maintenance lane that read one
  artifact of the same run; the deploy job needs `site-ok`, which needs all of
  them. A pull request that only edits the prose or links of pages under
  `docs/` checks those pages, in both languages; every other change, and every
  push or dispatch, which deploys, checks all pages. `test.yml` is unchanged
  (the runtime CI policy is #676 on `next` and #679 on `master`). See
  [Site CI change scope](test/README.md#site-ci-change-scope) for the lanes
  and the timing of run 41173244320.
- The review and the re-review of its must fix items are comments on #677.

## Landing-page hierarchy, 2026-10-30

- #670 merged as `0982d877f`; production run [41056532525](https://github.com/matsumotory/ngx_mruby/actions/runs/41056532525)
  succeeded. All 628 shipped files matched HTTPS. [Publication evidence](https://github.com/matsumotory/ngx_mruby/pull/670#issuecomment-6523552378)
  records live code, interaction, search and sharing checks.
- [#671](https://github.com/matsumotory/ngx_mruby/pull/671)
  (`codex/site-layout-hierarchy`), based on that merge, removes generic link arrows,
  repeated figure numbering and standalone narrow-screen arrows. Related items
  use proximity and shared text roles. The existing routing behavior, source
  copies, development status and MCP limitations remain intact.
- Shared layout/typography rules and independent visual-review criteria are in
  [the site plan](proposals/site.md#layout-and-type-hierarchy), referenced by
  AGENTS.md. Scope is presentation and its checks; runtime and CI policy do not
  change. Current-head validation, review and publication are recorded on the PR.

## Landing-page narrative rebuild, 2026-10-30

- #669 merged as `10297d1e2`; production run
  [41042885039](https://github.com/matsumotory/ngx_mruby/actions/runs/41042885039)
  and deployment `7436631611` succeeded. All 626 shipped files matched HTTPS;
  live code checks covered 340 conditions, interaction checks 64, and English /
  Japanese search in both versions passed. Its visual design was subsequently
  rejected as insufficient; successful checks do not imply design acceptance.
- [#670](https://github.com/matsumotory/ngx_mruby/pull/670)
  (`codex/home-use-case-lp`) rebuilds the v3 overview around developers managing
  several LLM APIs: purpose, module definition, model routing, first local
  handler, then the real proxy example. Nested illustration boxes and repeated
  introductory claims are removed. MCP remains an unverified architecture
  candidate; v3 remains in development, with a stable 2.7 entry. The v3 sharing
  image follows the same concrete purpose and composition.
- Scope is the bilingual landing page, its sharing asset and these records.
  Runtime fixes, v3 setter decisions, stable README work, and software releases
  remain separate. Personal references and local QA files are not public assets.
- The owner asked on 2026-10-30: “ngx_mrubyは本番二デプロイしてから見せて。
  こっちは個人のサイトなんやから” (deploy the personal site before presenting it).
  Follow the existing review/CI/merge gates, then verify the production artifact,
  code copies, OG delivery and desktop/mobile pages. This does not authorize a
  software release or a GitHub approval review. Current-head checks, independent
  first-reader/technical reviews and publication evidence belong on the PR.

## Whole-page material integration, 2026-10-30

- #668 merged as `252018d86`; production run
  [41023287679](https://github.com/matsumotory/ngx_mruby/actions/runs/41023287679)
  succeeded. Its 626 shipped files matched production; live code-layout
  verification covered 340 conditions and interaction verification 32.
  The earlier pending-publication entries below are historical checkpoints.
- The owner found that metallic components looked detached from the remaining
  page: background, composition, light, material, color and motion need one
  system. [#669](https://github.com/matsumotory/ngx_mruby/pull/669)
  (`codex/home-material-system`) addresses that feedback on the v3
  overview, preserving tested routing, version states and canonical code copies.
  The [site plan](proposals/site.md#v3-use-case-homepage-2026-10-30) records the
  scope. Visual approval is separate from passing automated checks.
- This iteration changes homepage styling and its material checks only. No
  runtime change, MCP interoperability claim, stable README migration, new OG
  artwork or software release is included. Personal photos remain unpublished.
- Local preview checks passed: 40 homepage style loads, 500 code conditions,
  32 interaction conditions, 69 complete exports and English/Japanese
  accessibility 100. An independent visual review found no must-fix and one
  arrow-placement improvement; the MCP entry arrow now points at Ruby's column.
  A technical review also found transient text fading during route motion.
  Test-only commit `52cb29ce7` reproduces it (opacity 0.6 at animation start);
  the correction keeps text opaque, and the interaction check now covers both
  themes and four points of the animation. The narrow MCP diagram retains the
  Ruby-to-backend branch layout. Final-head CI and re-review are recorded on
  the draft PR. A further visual review removed diagonals that crossed content
  and the nested outer/Ruby cards, retaining a single nginx enclosure and a
  section-aligned light field. The new visual diff needs final-head verification.
  Publication
  remains separate; #668's individual merge approval is not reused here.

## Final site validation follow-up, 2026-10-30

- #668 head `77f3161ad` passed test/examples CI, but site CI found an overly
  wide sample caption and a Japanese identifier-search failure. Publication
  remains held until the follow-up head passes all checks.
- The caption now uses a character-based width. Search metadata is generated
  from canonical API names; visible prose/code and exported Markdown stay
  unchanged. At regression-test commit `3ec909597`, the exact-reference
  check fails only for Japanese `mruby_content_handler` (11/12 pass).
  The new test also requires the target reference, not merely any result.
  Final-head execution and independent review are recorded on #668.
- #667 production run 41011744554 and deployment 7432116276 succeeded;
  80 changed/new shipped files matched HTTPS, and the live policy/redirect
  checks and all five Lighthouse categories (100) passed.
- Work continues in the existing repository checkout. Previous worktrees and
  branches remain preserved; local folder inventories are not public artifacts.
- The owner's 2026-10-30 correction requires code to be readable without
  horizontal scrolling and a modern code presentation. #668 now applies
  soft wrapping to both versions and all documentation, names sample files,
  and highlights the model-routing assignment. Full configuration remains
  expandable; syntax and original clipboard bytes are preserved.
  Regression commit `d88c1e573` fails on the old homepage at 320px.
  `check-code-layout.mjs` checks every generated page at 320px and required
  English/Japanese reference and entry pages at 320/390/768/1440, with 200%
  code text, unbroken URLs, keyboard activation and canonical sample copies.
  Local code-layout checks pass in 500 page conditions in Chromium/WebKit,
  including canonical clipboard and keyboard checks; homepage computed-style
  checks pass in 40 light/dark page loads. Publication remains pending
  final-head CI, independent review and live QA.
- Site CI at `d005d45f3` passed the complete computed-style, Japanese,
  focus, search and accessibility gates. Its interaction check counted
  Starlight's idle-loaded Pagefind UI module as illustration traffic.
  The check now waits for the search input to be attached before measuring
  route controls, retaining the zero-request assertion. A delayed-idle
  diagnostic reproduces the old failure; normal and delayed initialization
  each pass all 32 interaction conditions with the wait. Final CI is required.

## v3 homepage redesign checkpoint, 2026-10-30 06:04 UTC

- The owner prioritized site expression over further internal C work: v3 as
  the main entry, concrete users and purposes, large diagrams, metallic
  surfaces and deliberate motion. The [site plan](proposals/site.md#v3-use-case-homepage-2026-10-30)
  records the revised visual scope and bounded exceptions. Stable 2.7 keeps
  its own entry and sharing card. Personal photos remain references only.
- [#668](https://github.com/matsumotory/ngx_mruby/pull/668) owns this work.
  The new homepage shows tested model routing, an explicitly unverified MCP
  document-service design, and trial/edit/check entry points. English and
  Japanese canonical guides feed HTML and machine-readable Markdown.
- #663 production run 41005252954 completed: 117 changed/new shipped files
  matched over HTTPS; deployment 7431188963, redirects and site policy checks
  passed, with all five live Lighthouse categories at 100.
- #665 merged as `2677db219` after current-head CI and independent review;
  production run 41008268601 passed, with 165 changed/new shipped files
  matching HTTPS. #666 merged as `d2827d72c` and production run 41009919981
  passed. #667 merged as `79d7e3933` after final-head CI and independent
  review; production verification is pending. This branch includes both.
- A fresh linux/arm64 trial of examples/start stopped at Ubuntu image-metadata
  retrieval before compilation. No startup/edit/reload success is claimed for
  that attempt. The updated example adds executable configuration validation
  and reload checks. Examples CI 41009377947 executed the nine commands
  successfully on the Linux runner, including build, response changes, validation,
  reload and cleanup. Final-head CI remains required before publication.
- Internal fixes remain separate in #664 and the existing local checkpoints.
  The owner accepted the v3 setter choices D/E on 2026-10-30 with
  「すごい！両方進めて！」 in response to the explicit proposal: invalid Strings
  raise ArgumentError and the HTTP setter refuses hostnames without resolving
  them; non-String TypeError remains. The owner also answered the two open
  questions of the [setter proposal](proposals/archive/upstream-server-setters.md)
  that day in a session's question. [#680](https://github.com/matsumotory/ngx_mruby/pull/680)
  implements D/E. These decisions do not apply to 2.7 or authorize a software
  release.
- Local validation includes 24 Chromium/WebKit route-control and reduced-motion
  loads, Chromium clipboard checks, 120 Noto style loads, 1044 focus stops,
  six Lighthouse pages (all categories 100), and native/Noto Japanese trial
  and MCP typography checks. Final-head CI and live artifact/OG checks are
  recorded on #668; these local results do not claim production verification.
  MCP execution, actual social-network card fetches and the failed arm64
  container trial remain unverified.

## Standalone routing recipe, 2026-10-30

- This independent documentation unit includes next `490ea459c` after
  the installation integration #663; runtime inputs are unchanged from the
  originally tested `6d65a12ec`. The English and Japanese
  [routing guide](guides/routing.md#run-it-independently) now contain a
  complete loopback configuration, Ruby table, executable checks and
  failure diagnostics. No module or existing integration fixture changed.
- The exact shell block was extracted from the guides and executed on
  Ubuntu 22.04 aarch64 as an unprivileged user, using nginx 1.31.8 built
  from `6d65a12ec` and its default gem lock. Five requests passed: known
  tenants a/b, absent header, unknown key and an address-shaped key.
  Each checks HTTP status, content type and every body byte, including the
  path/query and trailing newline. The instance stops using its own prefix.
- An external negative-check copy with a deliberately wrong expected
  backend returned 1 and removed the instance's PID file. That altered
  expectation is not in the guide. The source/code review found no open
  must-fix or should-fix item. Browser and export validation are recorded
  with the completed local commit; no remote CI or publication is claimed.
- The tested executable is a development build, not a v3 release. This
  recipe was not run on v2.7.2, with dynamic module loading or on non-Linux
  systems. No performance measurement or full module-suite rerun was
  performed for this documentation-only unit. The owner authorized the
  normal PR/CI/publication process on 2026-10-30; final-head CI and
  deployment verification are pending.

## Surface continuation, 2026-10-30

- This homepage-only change adjusts the copper-red CTA and mobile spacing.
  The [site plan](proposals/site.md#local-surface-and-mobile-spacing-iteration-2026-10-29)
  records color roles, contrast and measured viewport differences. Existing
  style expectations are preserved; the new contrast assertion is additive.
- Independent source review has no must-fix or should-fix findings.
  Local checks cover 80 native/Noto style loads, 1032 focus stops and no
  contrast failures. Those preview builds were dirty; final-head CI and
  production verification remain required.
- [#665](https://github.com/matsumotory/ngx_mruby/pull/665) contains the
  separate README/OG change. [#663](https://github.com/matsumotory/ngx_mruby/pull/663)
  merged as `490ea459c`; this branch includes that integration. Publication
  resumed with the owner's authorization on 2026-10-30; software releases
  and personal reference photo publication remain excluded.

## Sharing image continuation, 2026-10-30

- The initial site/rebrand in [#661](https://github.com/matsumotory/ngx_mruby/pull/661)
  is published at next `6d65a12ec`; its completion record links the deployed
  artifact and live checks. [#662](https://github.com/matsumotory/ngx_mruby/pull/662)
  aligned maintenance process docs at master `967b61cc6` (mirrored to v2.x).
- [#663](https://github.com/matsumotory/ngx_mruby/pull/663) integrates the
  maintenance docs and verifies the development installation walkthrough.
  It merged as `490ea459c` after final-head CI and independent review;
  production run 41005252954 is in progress.
- This sharing-image change uses the selected metallic mark in one
  product sharing image for the README and both site versions. The public
  source, render command, metadata checks and limits are in the
  [site plan](proposals/site.md#sharing-and-readme-identity-2026-10-29).
  Existing header/favicon derivatives remain; old image URLs are preserved.
  Local static checks and full-size/300/390-pixel visual checks pass. Final
  independent source/visual review has no must-fix or should-fix findings.
  Current-head PR CI and deployment remain pending; this is not a release change.
- The later site work remains distinct: restrained surface/CTA refinements,
  deeper verified HTTP/stream examples and contextual performance records.
  The v3 setter work follows those site units under its existing plan.

## Installation and process continuation, 2026-10-29

- The first rebrand and versioned-documentation iteration is published.
  [#661](https://github.com/matsumotory/ngx_mruby/pull/661) merged as
  `6d65a12ec`. Production run 40959681713 and deployment 7425112363
  succeeded. All 614 shipped files match the live site; four versioned
  English/Japanese searches, mobile/desktop views, code interaction and
  HTTPS checks pass. Final evidence is in the
  [completion record](https://github.com/matsumotory/ngx_mruby/pull/661#issuecomment-6509229800).
- The common continuation procedure from #659 reached master as `967b61cc6`
  in [#662](https://github.com/matsumotory/ngx_mruby/pull/662), after all CI
  and independent review passed. The v2.x mirror succeeded. HANDOFF
  remains on next, and master links that source. Branch-specific test
  process/port handling is preserved; a common workflow does not imply
  identical harness capabilities.
- [#663](https://github.com/matsumotory/ngx_mruby/pull/663), branch
  `codex/integrate-stable-install`, merges the installation correction
  of [#660](https://github.com/matsumotory/ngx_mruby/pull/660) from master
  `967b61cc6` into next `6d65a12ec`. The conflict resolution selects next
  development source and preserves the v3 core-gem, lock and removed
  auto-ssl contracts. English/Japanese commands are identical. A fresh
  clone of `6d65a12ec` built and installed nginx 1.31.8 on Ubuntu 22.04
  aarch64; the exact documented HTTP trial passed both response assertions,
  configuration validation, reload and quit. These are documentation
  changes, with no measured binary input changed. Current head, final CI
  and independent review belong in the integration PR.
- Next site work: shared README/social branding and controlled metallic
  surface/CTA refinements, then deeper executable HTTP/stream examples
  and reproducible performance records. Keep human and agent output on
  the same sources; retain implementation/planned/under-design distinctions.
  The upstream setter D/E work and stable empty-filter follow-up remain
  separate runtime items. No new runtime contract or software release was
  decided by this documentation integration.

## Site continuation checkpoint, 2026-10-29 20:25 UTC

- `next` is `2588cfd26`, the merge of shared-process PR
  [#659](https://github.com/matsumotory/ngx_mruby/pull/659). Its final head
  `71d136799` passed test run 40946099772 and site run 40946099800 against
  the current base. The independent review has no unresolved findings.
- Integration [#658](https://github.com/matsumotory/ngx_mruby/pull/658)
  is merged. Production run 40945526052 deployed `258c852fa`; the live
  home matches its artifact, HTTPS and the verification file pass, the
  environment permits only next, and Lighthouse categories score 100.
- `master` is `da0d1172d`, the merge of installation-guide
  [#660](https://github.com/matsumotory/ngx_mruby/pull/660). All final-head
  CI passed against master `7d81d417a`. Its released v2.7.2 / explicit
  nginx 1.31.8 static build and HTTP lifecycle passed. Its documentation
  still needs the normal master-to-next integration; do not reimplement
  stable changes on next. The v2 site build reads the merged master source.
- This PR, branch `codex/site-technical-design`, introduces the technical
  home pages, shared navy/graphite palette, metallic C logo family and
  versioned Markdown/JSON exports. Its design and source rules are in
  [the site proposal](proposals/site.md#working-design-reading-implementation-and-agent-use-2026-10-29).
  The owner authorized iterative publication on 2026-10-29; this does not
  authorize a software release or publication of the reference photos.
  HTTP gold / stream purple is the current design assignment, with labels;
  LLM proxy is explicitly development with implemented/planned features.
- Generator fixtures, 67 complete Markdown bodies and source metadata,
  contrast, 26 v2 HTML pages and four version-specific searches pass.
  Independent retrieval reconstructed the upstream contract and the stable
  installation steps without confusing versions. Independent source and
  representative desktop/mobile/favicon image review has no open findings.
  The first logo-family browser run found a body-font mismatch and a short
  Japanese line; implementation fixes are committed. The corrected full
  browser run and final PR CI are in progress; consult the PR for final
  results, current head and the deployment record.
- Next site steps: complete that validation, merge under the normal gates,
  verify the live artifact and search, then iterate on deeper examples,
  README brand adoption and a dedicated social-sharing image. Runtime
  upstream setter D/E and the stable empty-filter follow-up remain separate
  queue items. No runtime implementation changed in this site PR.

## Continuation checkpoint, 2026-10-29 20:05 UTC

This supplements the integration snapshot below. Verify branch and PR state
again before acting; the PRs hold final-head CI and review evidence.

- `master` and its `v2.x` mirror are `7d81d417a`. Site cutover PRs #655,
  #657, #656 and #654 are merged. Production run 40928646131 was verified
  against its artifact, including all 26 `/v2/` pages, version-specific
  English/Japanese search and mobile rendering.
- [#658](https://github.com/matsumotory/ngx_mruby/pull/658) merged into
  `next` as `258c852fa` at 20:02 UTC after explicit owner authorization.
  Its final head `ee0025f5d` passed CI on merge ref `7c0c9ee0a`, including
  matrix, sanitizer, valgrind, soak, nginx tests, examples and site build.
  The performance run 40934491055 has 15 `ok` rows, largest increase
  +0.21%; the final numeric review is
  [recorded on the PR](https://github.com/matsumotory/ngx_mruby/pull/658#issuecomment-6507034713).
  Post-merge site publication still needs its own verification.
- [#659](https://github.com/matsumotory/ngx_mruby/pull/659),
  `codex/shared-handoff-process`, records the common Claude/Codex/human
  continuation procedure. Head `cb3d35164` passed CI (the first OpenSSL
  download failure was resolved by a rerun). This update includes the new
  `next` base, so CI must pass again on the updated head. Its only conflict
  was this dated state record; the integration snapshot is retained below.
- `codex/site-technical-design` holds the rebrand and machine-readable
  documentation preview, still uncommitted at this checkpoint. Preserve
  its task worktree. The export has 51 development and 16 stable source
  pages, complete-body/source/metadata checks and independent retrieval
  review. The pre-logo revision passed 440 browser loads and 1,008 focus
  stops; new global colors and the metallic C logo need final browser QA.
  No reference photograph is a public asset. The owner authorized iterative
  site publication on 2026-10-29: "ossのサイトはデプロイしまくっていいのでどんどんやろう".
  This does not authorize a v3 software release or publication of private
  materials. The latest design and source-state details are in the site
  proposal and the forthcoming design PR.
- [#660](https://github.com/matsumotory/ngx_mruby/pull/660), head
  `4723905ef`, fixes the stable installation guide. A released v2.7.2
  checkout with explicit nginx 1.31.8 passed the documented static build,
  install and loopback HTTP lifecycle. Custom/dynamic alternatives are
  explicitly not additional executed results. CI and final review remain
  on that PR; this is separate from site styling and v3 runtime work.
- Upstream setter D/E and the stable empty-filter follow-up remain queued.
  The integration prerequisite is now merged. Existing v3 planning decisions
  hold; the site's future-facing description must distinguish implemented,
  planned and still-undecided behavior.

## State as of 2026-10-30 (03:49 JST)

Before this integration, `next` is `e469b259c`, the merge of
[#657](https://github.com/matsumotory/ngx_mruby/pull/657), and `master` is
`7d81d417a`, the merge of
[#654](https://github.com/matsumotory/ngx_mruby/pull/654); `v2.x` mirrors
that commit. This integration brings that `master` into `next`. It carries
#646 (HTTP content sleep and
redirect exception handling), #648 (setter documentation), #650 (release
note guidance), #651 (stream sleep outcomes), #652 (setter type, zone and
whole-name checks), #642, #655, #656 and #654. The 2.7.3 behavior entries come
with their English and Japanese files; these fixes are not reimplemented.

The conflicts were documentation only: retain the removal of auto-ssl and
of the old API-reference sorting TODO, keep the `next` valgrind and test
lifecycle rules, add the new test ports and the still-blocking HTTP setter
DNS lookup. The mruby 4 initializer arity stays `MRB_ARGS_REQ(1)`. The new
HTTP ports 18133–18135 and stream ports 12374–12378 do not collide with
`next` and work with its offset staging. The readiness check now probes 57
HTTP ports. The Linux static suite on nginx 1.31.8 passed at `6bc885fd4`,
both with the ordinary ports and with `TEST_SH_PORT_OFFSET=240`: 40 suite
reports and 467 assertions each, no failure or crash. The later commits
change documentation only. The integration PR records its final-head
review, matrix, sanitizer, valgrind, soak, nginx-tests, site and performance
results; the merge conditions of AGENTS.md apply to it.

The site cutover is live. #653 added deployment from `next`; #655 fixed
`master`'s documentation links; #657 added `/v2/`; #656 added the `master`
validation and dispatch workflows. The first deployment with `/v2/` is
[run 40923881194](https://github.com/matsumotory/ngx_mruby/actions/runs/40923881194),
from `next` at `e469b259c` (deployment 7420103202). Its full site checks
passed. The live home page matches its artifact, HTTP redirects to HTTPS,
the verification file is unchanged, the deployment environment permits
only `next`, and live Lighthouse categories score 100. Every `/v2/` HTML
page answers 200 with the artifact's bytes. Four live Chromium searches
(2.x and 3.x, English and Japanese) use only their own version's index and
results; the English and Japanese `/v2/` pages have their banner and fit
at 390 px. #656's dispatch started
[run 40924294520](https://github.com/matsumotory/ngx_mruby/actions/runs/40924294520),
which passed and was checked against the live artifact as well. #654
merged at `7d81d417a` after all final-head checks and independent review.
Its dispatch started
[run 40928646131](https://github.com/matsumotory/ngx_mruby/actions/runs/40928646131),
which passed and published deployment 7420858976 from `next`, with the
2.x pages from `master` at `7d81d417a`. All 26 live `/v2/` HTML files again
matched that artifact; all four live searches, the two mobile checks and
`check-live.mjs` passed. The master push checks and the `v2.x` mirror also
passed.
The 3.x development banner and the owner's go for Q9 remain outstanding;
no Discussions/wiki setting was changed by this continuation.

Earlier completed work is listed below for context. For current branch
heads and pending work use this snapshot and the queue, then fetch again.

2.7.2 was released on 2026-10-29: the tag `v2.7.2` is on `d5ae75547`, the
merge of #624 into `master`, and the release was published at 13:26 JST.
Its release notes are `docs/releases/v2.7.2.md` and
`docs/releases/v2.7.2.ja.md`, on `next` with the same content since #628. 2.7.1 was released on 2026-10-19: the tag `v2.7.1` is on
`ce5eb11`, the merge of the 2.7.1 changes into `master`. Its release notes
are `docs/releases/v2.7.1.md` and `docs/releases/v2.7.1.ja.md`. The release
notes of the next 2.x release are `docs/releases/v2.7.3.md` and
`docs/releases/v2.7.3.ja.md`, created on `master` by #636 and on `next`
with the same content by the merge of `master` at `c6d3b3b9b`.

Merged on 2026-10-29 (JST) after 14:40, into `next`: #633 (this file and
the comparison of the 3.0.0 release notes with 2.7.2; merged at 14:51,
`2c96302b7`), #635 (`test.sh` stops
only the nginx that it started, by its pid; merged at 16:09, `c4e6ac6cc`),
#634 (valgrind fails the cell; one cell runs under valgrind on pull
requests and every cell except the sanitizer cell nightly; 16:51, `8bff5fbd7`), #626 (the agent
proxy endpoints diagram without a line in its narrow arrangement; 18:11,
`a9792b82f`), site step 5, #629 to #632 (18:39 to 19:31, `12202b8c4` to
`5e9d50663`; the site row of "Queue" lists them) and #637 (the v3 plan,
the archive of two proposals and this file; 19:50, `c0df45534`) and #641
(`TEST_SH_PORT_OFFSET`; 20:31, `be559a017`) and #640 (the auto-ssl mrbgem
and `NGX_MRUBY_AUTO_SSL` removed from `next`; 21:33, `67ad9b919`). Into `master`: #636
(the auto-ssl gem tested with Redis, Pebble and dehydrated; 16:40,
`22f13686f`), #639 (`CONTRIBUTING.md` and other documentation fixes;
17:59, `eb9055584`), #638 (nginx 1.31.8 and 1.30.6; 18:31,
`9acb75949`) and #645 (the stream `Async.sleep` timer cancelled when the
session's pool is freed, and the fiber registered with the GC once per
fiber; 20:06, `c6d3b3b9b`).

Merged on 2026-10-29 (JST) after 13:20, into `master`: #624 (the 2.7.2
release: #594 and the other changes of the release; merged at 13:25,
`d5ae75547`; GitHub marks #594 merged with it) and #627 (the two sentences
of `README.md` "Branch strategy" in the present; 13:52, `93432cf69`). Into
`next`: #625 (this file; 13:40, `2969426f6`) and #628 (`master` at
`93432cf69` into `next`; 14:26, `c9c49023e`; its description lists the
conflicts, how they were resolved, and the test ports of `master` that it
moved on `next`).

Merged on 2026-10-29 (JST) after 01:20, into `next`: #615 (`master` at
`6b27f08da` into `next`; merged at 01:46, `216df0ceb`), #606 (mruby-redis in the default build of `next` again,
pinned in `build_config.rb.lock` at `8d9391049`; 02:11, `5ca7c955b`), #614
(the Pagefind result titles at a size of the scale, and the search check
with the results loading and loaded; 03:38, `571212d58`), #600
(the OpenAI Responses API in the mock LLM upstream; 05:30, `0d1b3d756`),
#617 (site step 3; 05:58, `dbe4acf5b`) and the six parts of site step 4,
#618 to #623 (12:02 to 13:13, `d5548db41` to `69b245bdb`; the site row of
"Queue" lists them). Into `master`: #616 (the check of the 2.7.2 release
notes against every pull request since 2.7.1, and the performance
comparison with 2.7.1; 02:35, `f70b24031`).

Merged on 2026-10-29 (JST), into `next`: #607 (site step 2: the design
tokens, the checks of step 2 and the specimens of 4.12; merged at 00:12,
`0e7fba441`) and #605 (`Nginx::Debug.stats` and `Nginx::Debug.gc` tested in
the soak; merged at 00:46, `5999a0cc7`). Into `master`: #612 (the entry of
the 2.7.2 release notes for `Redis.connect_set_udptr` and `Redis.new`
without arguments, matsumotory/mruby-redis#109; merged at 00:10,
`cfe77a506`), #603 (tests of the directives and Ruby methods that had none;
merged at 00:46, `baea78cd7`) and #613 (actions/upload-artifact 7.0.2;
merged at 01:08, `6b27f08da`). In matsumotory/mruby-redis: #109 (the
connection of `Redis.connect_set_udptr` kept in the `mrb_state`, not in
`mrb->ud`; merged at 00:12, `8d9391049` on the gem's `master`). Merged on
2026-10-28, into `next`: #610 (`Nginx::Var` accessors defined at their
first use, and the variables of `Connection`, `Server` and `Request` read
in C; merged at 06:02, `a0f4b97a2`). Merged on 2026-10-20, into `next`:
#608 (this file, the state as of 00:10; merged at 00:16, `39e870c9f`); into
`master`: #604 (mruby-redis in the default build again for 2.7.2; merged
at 00:29, `e77f9a705`).

Merged on 2026-10-19, into `next`: #602 (the `nginx-tests` workflow: nginx's own test suite on nginx with and without ngx_mruby; merged at 23:03 JST, `620e65718`), #597 (the bundled ngx_devel_kit v0.3.4 with `./update-devkit-subtree v0.3.4`; merged at 22:08 JST, `2de1626`), #595 (`master` at `36f4c82` into `next`,
with #589; its description lists the conflicts in
`src/http/ngx_http_mruby_var.c` and `AGENTS.md` and how they were
resolved), #574 (200 with `Content-Length: 0` when a content handler
sends no body, #200, and an output body filter that ends with an empty
body sends the response; its entries are in `docs/releases/v3.0.0.md` and
`.ja.md` and the migration guide, `7b5a0c4`), #591 (site step 1:
`site/` with Starlight, the generator of `docs/`, the checks and
`.github/workflows/site.yml`, `a466688`), #590 (`master` into `next` in
two merge
commits: `master` at `4091cbd`, with the 2.7.1 changes, #581, #586 and
#587, and then `master` at `03aad70`, with #588; its description lists the
conflicts and how they were resolved, and it makes the texts of #584 and
#586 on a `return` inside a block one text for 3.0.0 and 2.x) and #585 (the
owner's decisions of 2026-10-15 on the site proposal: section 7 of
`docs/proposals/site.md` records them, section 4 derives the design from
the source of three of the owner's sites, 3.5 plans the diagrams and
samples, section 6 says what each step produces and what the owner reviews,
and `contrast.py` checks a second palette, `75bfa6f`). Into `master`: the
2.7.1 changes (`ce5eb11`), #581 (the test harness runs `nginx -s quit` with
`detect_leaks=0`, `edc85f0`), #586 (the note on a `return` inside a block
of handler code in 2.x, `5e7d57e`), #587 (a change of the 2.7.1 release
notes, `4091cbd`), #588 (tests: the request body that a log handler or a
filter sees after nginx ended a body read, and the status 500 after an
exception in an output header filter; and two sentences of
`docs/directives/README.md` on such a handler, `03aad70`), #589
(`Nginx::Var` rejects names and setter calls that name no variable, and
leaves the name passed to `set` unchanged; it creates
`docs/releases/v2.7.2.md` and `docs/releases/v2.7.2.ja.md` and the test
fragment `test/conf/conf.d/67-var-input.conf`; merged at 16:35 JST,
`36f4c82`), #593 (`test.sh` waits until the test nginx listens instead
of sleeping `NGINX_HEATTIME`, with `test/t/cases/_wait_for_listen.rb` and
an entry in `docs/releases/v2.7.2.md`; merged at 17:16 JST, `188d324`),
#592 (`README.md` and `docs/README.md` say next to the abstract of the
paper what a worker keeps between requests; merged at 19:10 JST,
`a6c32a4`), #596 (the entry of `docs/releases/v2.7.2.md` and `.ja.md`
for the builds that enable mruby-redis, which get hiredis v1.5.0 since
matsumotory/mruby-redis#108; `a500846`), #599 (the supply chain checks
in CI: zizmor, OpenSSF Scorecard and the heads of the GitHub gems; merged
at 20:43 JST, `ee0a57f`), #598 (the trust boundary of the docs: trusted configuration code, untrusted client input; merged at 21:35 JST, `5eec909`), #601 (the callgrind performance lane and wider sanitizer log checks on `master`; merged at 22:33 JST, `68032bb6a`), #609 (the `Nginx::SSL` examples of the docs look the SNI name up in a table; merged at 23:20 JST, `2135d68a4`) and #611 (no checkout token kept in the `test.yml` jobs, and zizmor audits `test.yml` again; merged at 23:58 JST, `0d09b5054`). Issue #200 was closed at 19:42 JST, after #574.
#563 was closed
on 2026-10-19: its change is part of 2.7.1 (its last comment). #502 was
closed on 2026-10-19 after #586; its test and its entry in the 3.0.0
release notes came with #584. Merged on
2026-10-15, into `next`: #584
(the regression test of #502,
`test/t/cases/return_in_block.rb` on 18117, its entry in the 3.0.0 release
notes and the migration guide, and the owner's decision on the frame of
handler code as item 14 of section 7 of the plan), #583 (the proposal
`docs/proposals/handler-code-frame.md` for #502, and one sentence in the
`private` entry of the 3.0.0 release notes and in the migration guide: a
top-level `def` in handler code stays public, `982a20e`) and #582 (the
release notes for 3.0.0 of the pull requests merged before
`docs/releases/v3.0.0.md` existed, `Set#flatten_merge`, the migration guide
and `docs/releases/v3.0.0.ja.md`, `acdc82f`).
Merged on 2026-10-14, into `next`: #572 (the fixed symbol names interned
once, `bc2488a`), #571 (the site proposal `docs/proposals/site.md`,
`570cdab`), #569 (this file, `e0dfdc6`), #561 (mruby 4.0.0, `0b76bfa`),
#577 (the proposal `docs/proposals/nginx-var-method-lookup.md`, `53e8d39`),
#579 (`master` at `b017496` into `next`, `7696e1c`) and #580 (`master` at
`0a1e8ac` into `next`, `dcd3103`); into `master`:
#576 (`.gitignore` and `CLAUDE.md`, `9be7f02`), #575 (the "Why it changed"
lines and the Japanese file of the release notes, `b017496`) and #578 (the
`files` job of CI, `test/check_added_files.sh`, `0a1e8ac`). Merged on
2026-10-04: into `next` #560, #565 and #573 (`master` into `next`); into
`master` #562, #564, #566, #568 and #570. The full lists: `gh pr list
--state merged --base next --search 'merged:>=2026-10-03' --limit 200`, and
the same with `--base master`. Each pull request says what it changed.

Open pull requests checked at 03:49 JST: none. This integration is on
`codex/merge-master-site-continuation`; its PR targets `next` and is kept
draft until the final checks and independent review pass. #654, #656 and
#657 are merged. Check again before starting another row. Added on
2026-10-31: [#676](https://github.com/matsumotory/ngx_mruby/pull/676)
(`claude/ci-skip-docs-next`, the CI row of the queue) is open as a draft,
and its `master` side
[#679](https://github.com/matsumotory/ngx_mruby/pull/679)
(`claude/ci-skip-docs-master`) as well.


## Decisions

Decisions of the owner that are not yet written in the place their row
names: (a) and (b) of 2026-10-04 in the next paragraph. The owner's choice of 2026-10-29 at 05:34 JST, in a session's
question on who merges the pull request of the 2.7.2 release, tags
`v2.7.2` and publishes the release ("セッションが進める (推奨)", "the session
goes ahead"), covered 2.7.2 only, and it is carried out: the session that
prepared the release merged #624 at 13:25 JST, tagged `v2.7.2` on
`d5ae75547` and published the release at 13:26 JST. AGENTS.md keeps the
rule that agents never create tags and never publish releases; nothing is
written there unless the owner keeps the choice for later releases. The choices among the options of 4.12 of the site proposal
are written in `docs/proposals/site.md` (#607). The decision of 2026-10-19
on the perf lane of `master` (port the tests and the CI only, without
`Nginx::Debug`) is written in #601 (its description and
`docs/test/README.md`, which `next` has since the merge of `master` at
`6b27f08da`). The decision on the method lookup of `Nginx::Var` accessors
(the owner's answer of 2026-10-15 to the question of section 4 of
[the proposal](proposals/archive/nginx-var-method-lookup.md), in a session's
question: the change to introspection is accepted as a behavior change of
3.0.0; and the confirmation of 2026-10-19, in a session's question, with
the option "その内容で合っている (推奨)" ("that content is right"): (a) with the
rule (a2), (d), and accessors in introspection) is written in the Status
line of the proposal and in the entries of `docs/releases/v3.0.0.md` and
`.ja.md` (#610).

On 2026-10-04 the owner answered the recommendations of the analysis of the
control flow of `Nginx::Async` with 「全部推奨通りでいこう、安全網から始めて」
("go with all the recommendations, starting from the safety net"). Two of
its decisions, (a) and (b), are not written in the plan or in the release notes yet,
and a third, (c), is amended below:
(a) `Nginx::Async.sleep` in a content handler is supported, so it does not
raise and nginx waits for the timer; (b) a rewrite handler that ends with no
output and no `Nginx.return` keeps the 2.x behavior on `master`, and on
`next` the request goes on to the next phase as with `NGX_DECLINED`; (c)
the rewrite of how resumed handlers end goes into `master` after 2.7.1. On
2026-10-29 the owner amended (c), in a session's question, with the option
"master は最小の直し、書き直しは next (推奨)": the rewrite lands on `next`,
in the core stabilization of 3.0.0, and `master` gets only the minimal fix
for the content handler sleep. The amendment of (c) is written in item 15 of
section 7 and in the Pillar B row "One fiber lifecycle for HTTP and
stream"; (a) and (b) are written in the plan when their work lands, under
that row and under the row "Redesign response finalization per phase".

The other owner decisions of 2026-10-29, all in session's questions, are
written in the plan: items 1 and 6 and 15 of section 7 (mruby 4.1.0-rc2 now,
`auto-ssl` out of `next`, the agent proxy rows in `v3.0.0-alpha.1`, the
parallel start of parts (a) and (c) of step 7, the subrequest 500, the fix of
the empty output body filter in 2.7.3). Two are not written in the plan: the
rule on the gems that the owner maintains is in AGENTS.md, "Other
repositories", with the owner's words (#637 on `next`, #639 on `master`);
and the body of the GitHub release v2.7.2 gets the section "Behavior
changes: read before upgrading" in English and then in Japanese, option
"足す (推奨)" (the session that prepared the release edits it with `gh release edit`).

The two decisions of 2026-10-04 that were recorded here before are written
where their rows said: the mruby steps in item 1 of section 7 of
[the plan](proposals/v3-plan.md) (#561), and the "Why it changed" lines and
the Japanese release notes in [docs/releases/README.md](releases/README.md)
(#575).

## Work in progress

### mruby update on `next`

- #561 (merged, `0b76bfa`) bundles mruby 4.0.0. Its lock pins
  matsumotory/mruby-uname to `50031c8` on the gem's `master` (the merge of
  matsumotory/mruby-uname#1), so no build depends on the gem's branch
  `mruby-4`. The owner accepted the `perf` FAIL rows that remained after
  #572:
  [the record on #561](https://github.com/matsumotory/ngx_mruby/pull/561#issuecomment-6165028832).
  #577 (merged) is the proposal for the `var` and `auth` rows; #610
  (merged) implements it.
- `next` bundles mruby 4.0.0 and moves to `4.1.0-rc2` (the newest mruby tag
  on 2026-10-29, `gh api repos/mruby/mruby/tags`), then to 4.1.0 when it is
  tagged (the owner's decision of 2026-10-29). The choices for that step
  are in item 1 of section 7 of the plan, and the row "mruby 4.1.0" of
  "Queue" lists what the step changes.

### Issue triage of 2026-10-04

The closed issues (21 on 2026-10-29, among them #225 closed by #566, #320
by #565 and #519 by #562, and #206, #321, #502 and #200, closed on
2026-10-19; #200 after #574):
`gh issue list --state closed --search
'closed:>=2026-10-04' --limit 200`. The reason is in the last comment of
each issue, or in the pull request that closed it.

Taken up and still open: none.

## Queue

| Follow-up | Target branch | Waits for |
|---|---|---|
| Merge `master` into `next` after each merge into `master`. Model: #573. | `next` | This integration brings `master` at `7d81d417a`, including #654, as listed in the snapshot. Its PR records the final validation. The integration adds no behavior changes beyond the imported 2.7.3 fixes. |
| The output body filter that ends with an empty body sends a zero size buffer marked as memory, and the client gets no byte (`Nginx::Filter#output ""`, pinned by `test/t/cases/filter_connection.rb` on `master`). Decided on 2026-10-29 (option "入れる (推奨)"): 2.7.3 gets the same change to `ngx_mrb_finalize_body_filter` as #574 on `next`, so that the response is sent with its status and `Content-Length: 0`, and the owner approved changing the expectation "an empty String closes the connection without a response" of that file. To do: a pull request to `master` with the test commit, then the fix commit, and the entry in `docs/releases/v2.7.3.md` and `.ja.md` | `master` (reaches `next` by the merge) | Ready to start |
| Subrequests: the content handler of a subrequest that returns `Nginx::HTTP_OK` without output sets status 500, where nginx's `return 200;` gives 200. Decided on 2026-10-29 (option "500 のまま (推奨)"): 3.0.0 keeps the 500, so that `auth_request` fails closed (#574 keeps it). To do: the entry of #574 in `docs/releases/v3.0.0.md` and `.ja.md` already says that the status stays 500; add that nginx's own `return 200;` gives 200 and that the 500 keeps `auth_request` from allowing the request | `next` | Ready to start |
| After a HEAD request to a location with an mruby output body filter, nginx sends the header and closes the keep-alive connection: the mruby body filter returns `NGX_ERROR` after it passed on the header of a header-only response (`ngx_mrb_finalize_body_filter`), and `ngx_http_output_filter` then sets `c->error`. The same with output, on 2.7.1, and on the merge of 2.7.2 into `next` (#628, which ran HEAD and then GET on one connection to such a location); `docs/releases/v3.0.0.md` (#574) names it as an exception ([the review of #574](https://github.com/matsumotory/ngx_mruby/pull/574#issuecomment-6166201549), should fix 1). To do: a test commit (HEAD, then GET on one connection), then a fix commit | `master` (reaches `next` by the merge) | Ready to start |
| A rewrite handler that ends without `Nginx.return` (for example `mruby_rewrite_handler_code 'x = 1'` before a content handler, or before nginx's `return 200`) sends no response, and `error.log` has no line at the `error` level: with keep-alive the connection stays open until `keepalive_timeout`, with `Connection: close` it is closed with nothing sent. `ngx_mrb_finalize_rputs` (`src/http/ngx_http_mruby_core.c`; the `rc = NGX_OK` after the log line "rputs_chain is null and return NGX_OK") returns `NGX_OK` when nothing was sent and no status was set, and the rewrite phase of nginx 1.31.6 finalizes the request on `NGX_OK` (`ngx_http_core_rewrite_phase`), where the access phase goes on to the next handler. Found and measured on `next` and `master` while #583 was written and reviewed; no issue tracks it. To do: for v3, a test commit and a fix under the Pillar B row "Redesign response finalization per phase" of the plan, so that the request goes on to the next phase as with `NGX_DECLINED`; for 2.x, the behavior stays (both are the decisions of 2026-10-04), and a line under "Known limitations" in the release notes of the next 2.x release can document it | `next` | v3: waits for the row on step 4 below (the fix belongs to the Pillar B work that step 4 holds until the safety net is done); 2.x: nothing |
| An end-to-end benchmark scenario: throughput and p50 and p99 latency with `oha` or `h2load`, planned in AGENTS.md "Design principles" and in section 8 of the plan, which also records the reference proxy end to end | `next` | Ready to start; where the results are recorded is decided when it is added (AGENTS.md) |
| Site: steps 1–5 and the `/v2/` implementation and workflows of step 6 are merged (#591, #607, #614, #617–#623, #626, #629–#632, #655, #657, #656). Step 7 deployment (#653) is live; see the verified deployment in the snapshot. #654 corrected the remaining `master` text after the switch, and its dispatched site build was verified live. | `next` for `site/`; `master` for 2.x sources | Cutover and master dispatch verified. Still open: the 3.x development banner of 3.4; the observability and certificate-lookup sample prerequisites of #619; the Japanese release-note line rewrites currently reported as NOTES_ONLY; and the owner's go for Q9 (Discussions on, wiki off). New visual design is a separate follow-up, not part of this cutover. |
| nginx-tests with the modules that its skipped files need: a build with the options of `test.sh` and `--with-http_v2_module`, `--with-http_v3_module`, `--with-stream_ssl_module`, `--with-mail` and the other modules that "Results of nginx-tests" in `docs/test/README.md` lists (in the CI run of #602, 189 of the 209 skipped files need a module that `test.sh` does not build), with and without ngx_mruby, in the `nginx-tests` workflow | `next` | Ready to start: #602 is merged |
| nginx-tests with ngx_mruby code configured: runs that add handlers or filters with code for every request through `TEST_NGINX_GLOBALS_HTTP` (the Pillar E row of the plan), compared with the run without code. The pull request decides which code: a rewrite handler that ends without `Nginx.return` sends no response (the row on it above), so that handler would fail most files for a known reason | `next` | Ready to start: #602 is merged |
| Test harness rewrite (step 2 of section 6 of the plan; Pillar E): [#635](https://github.com/matsumotory/ngx_mruby/pull/635) (merged, `c4e6ac6cc`) made `test.sh` stop only the nginx that it started, by its pid, with no `killall` or `pkill`, and send SIGTERM again while the single nginx process still runs, because that process can miss a SIGTERM that arrives right before it waits for events (the run at `7926f72`, where nginx stayed in `epoll_wait()` for 20 minutes after it logged the SIGTERM: "Stopping nginx" in `docs/test/README.md` has the cause and the measurements). [#641](https://github.com/matsumotory/ngx_mruby/pull/641) (merged, `be559a017`) added `TEST_SH_PORT_OFFSET`, which moves every port of the suite, so that two checkouts can run `test.sh` at the same time ("Ports" in `docs/test/README.md`). Still to do, in pull requests of their own: `master_process on` with several workers and reload cases, requests from CRuby instead of the client built into the test mruby, and HTTP/2 and HTTP/3 clients. A should fix of the review of #635 waits for the pull request that next changes `test/build_release.sh`, an input of the `perf` job: its comment still says that `test.sh` kills every running nginx. The readiness wait of #593 is the first part, on `next` since the merge of `master` at `6b27f08da` | `next` | Ready to start: `master_process on` with several workers, on top of #641; no pull request yet |
| valgrind in CI: done on `next` by [#634](https://github.com/matsumotory/ngx_mruby/pull/634) (`8bff5fbd7`): valgrind errors fail the cell, one cell runs under valgrind on pull requests and pushes, and `.github/workflows/valgrind-nightly.yml` runs every cell except the sanitizer cell under valgrind nightly. GitHub runs a schedule only from the workflow file on the default branch, so the nightly run starts once a copy of the file is on `master` ("valgrind in CI" in `docs/test/README.md`). To do: a follow-up PR to `master` that adds `valgrind-nightly.yml` as it is on `next`; to run the cells of `master` under valgrind as well, the same PR gives the `test.yml` of `master` the input `valgrind`, the valgrind options, `test/valgrind.supp` and the step "Check the valgrind reports" of #634, and adds `master` to the matrix of the file | `master` | A decision that `master`, the 2.x line, takes this change of CI |
| CI runs only the jobs that a change needs: the owner's decision of 2026-10-29 at 23:25 JST, in a session's question, with the option "1と2をリセット後に (推奨)": (1) a pull request whose files are not inputs of the binary or the tests skips the `build` matrix, the sanitizer and valgrind cells, `soak` and `perf`, and `ci-ok` still passes; (2) a push to `master` or `next` does not run the matrix again. On 2026-10-29, the 20 jobs that the account runs at a time and the about 20 jobs of a run of `test.yml` made runs wait 30 to 45 minutes, where a run alone takes 5 to 6 minutes. [#676](https://github.com/matsumotory/ngx_mruby/pull/676) does it on `next` with the job `changes` of `test.yml` ("Which jobs a run starts" in `docs/test/README.md`). The same change on `master`: [#679](https://github.com/matsumotory/ngx_mruby/pull/679). Both rulesets require `ci-ok` but not an up-to-date branch, so the push skip relies on condition 2 of "Review and merge"; whether to require it is the owner's call | `next`, then `master` | #676 and #679 are drafts under review. #679 overlaps #674 in `test.yml` and the docs: the one merged second takes the other in |
| nginx floor for v3 (item 2 of section 7 of the plan): drop the cells for nginx 1.26.3 and 1.28.3 from the `build` matrix of `.github/workflows/test.yml` and document the floor of 1.30 stable and 1.31 mainline | `next` | Ready to start: #601's change to `.github/workflows/test.yml` is on `next` since the merge of `master` at `6b27f08da` |
| OpenSSL 3.5 and 4.0 (item 3 of section 7 of the plan): cells for OpenSSL 3.5 as the baseline and 4.0 in `.github/workflows/test.yml`, which builds `1.1.1w` today; drop 1.1.1 and 3.0, and check ENGINE and the removed APIs in ngx_mruby and the gems | `next` | Ready to start: #601's change to `.github/workflows/test.yml` is on `next` since the merge of `master` at `6b27f08da` |
| `build_config.rb` rewrite with explicit gems (step 3 of section 6; Pillar A): `iij/mruby-env` and `iij/mruby-process` replaced by core gems, the choice between core `mruby-regexp` and `mruby-onig-regexp` (item 1 of section 7 keeps onig-regexp for 3.0), `monochromegane/mruby-secure-random` and `iij/mruby-digest` replaced, and `mruby-vedis` and `mruby-localmemcache` out of the default build | `next` | Ready to start: #606, which edits the same file, is merged. The part that replaces `env` and `process` with the core gems needs the subtree at 4.1.0-rc2 (the row "mruby 4.1.0"); the other parts do not |
| mruby 4.1.0 (step 3 of section 6; item 1 of section 7). The step changes: the mruby subtree updated to the tag with Prism vendored (the tag's tarball has an empty `mrbgems/mruby-compiler/lib/prism`, a submodule upstream), the three HAL gem names (`hal-posix-dir`, `hal-posix-io`, `hal-posix-socket`) removed from `NGX_MRUBY_CORE_GEMS` and its comment, the core `env`, `process` and `regexp` gems of 4.1 decided on (see the row above), `build_config.rb.lock` regenerated, the build with `NGX_MRUBY_DEBUG_STATS` run with its tests (4.1 keeps the roots in `mrb->gc.root`), the stream path of the counted GC registrations audited, a release notes entry, and the callgrind comparison against `next`, which includes the measurement of `var` and `auth` on mruby 4.1 (step 4 of the archived proposal for the method lookup of `Nginx::Var`). The owner decided on 2026-10-29 that `next` bundles `4.1.0-rc2` now and moves to 4.1.0 in a small subtree pull request when it is tagged | `next` | Nothing: the pull request for 4.1.0-rc2 is not opened yet |
| Build each bundled gem on mruby 4 (step 3 of section 6): #561 builds the default gem set on mruby 4.0.0; the rest is the build of all of them on 4.1.0-rc2 (the row "mruby 4.1.0"). `auto-ssl` is not built: the owner decided on 2026-10-29 to remove it from `next` | `next` | The pull request of the row "mruby 4.1.0" (not opened yet) |
| OpenSSF Best Practices badge (Pillar G of the plan) | `master` (README) | The owner registers the project on bestpractices.dev and gives the project id; then a session adds the badge |
| Step 4 of section 6 of the plan, the core stability work of Pillar B (execution context, response finalization, fiber lifecycle, common layer, headers and variables, and the two agent proxy rows), then `v3.0.0-alpha.1` | `next` | Held until the safety net of step 2 is done; what is left of it is the row above for the test harness rewrite (#641 is merged; `master_process on` with several workers comes next): valgrind in CI (#634) and the auto-ssl tests (#636 on `master`) are done. #600, #603 and #605 are merged (#603 on `next` since the merge of `master` at `6b27f08da`, with the sanitizer log check of #601). The plan: nothing in the core is refactored before it exists |
| nginx-tests required: the `nginx-tests` workflow records its results and fails only when a build, the fetch of the suite or `prove` fails. In the runs of 2026-10-28 and 2026-10-29 the build with ngx_mruby and the build without it have the same counts (511 files, 302 passed, 0 failed, 209 skipped). To do: the job fails when the build with ngx_mruby fails a file that the build without it passes, and the job joins the `needs` of `ci-ok` | `next` | Ready to start: the counts are the same in every run since #602 |
| The `perf` job in the `needs` of `ci-ok`, and the "In CI" text of `docs/test/README.md` (the sentences that call the job advisory and say that a `FAIL` does not block a merge, under "Performance comparison with callgrind") aligned with the rule of AGENTS.md "Design principles", under which a session does not merge while the job reports `FAIL` or `ERROR` | `next`, then `master` | Ready to start |
| Soak: record `Pss` and `Private_Dirty` from `/proc/<pid>/smaps_rollup` beside `VmRSS`, then bound their slope over more windows, set after measuring (the Pillar E row on memory accounting). Today `test/soak/soak.rb` bounds `VmRSS` by a step and a total and checks the counters of `Nginx::Debug.stats` | `next` | Ready to start |
| The ASan cell with `-DNGX_DEBUG_PALLOC -DNGX_DEBUG_MALLOC` (3.7 of the plan; the cell of `test.yml` sets only `-fsanitize` and `-fno-omit-frame-pointer`), so that ASan sees an access that runs from one pool allocation into the next. To do: a run of the suite with these flags, whose findings follow [SECURITY.md](../SECURITY.md), then the cell | `next`, `master` | Ready to start |
| A test build with `ngx_otel_module` (nginx/nginx-otel, built with CMake against the nginx source of `test.sh`) and an OTLP receiver for the case of the observability sample of 3.2 of the site proposal | `next` | The harness rewrite (the row above) |
| Step 7 of section 6 of the plan, the agent proxy, parts (a) to (e); none exists on `next` | `next` | Parts (a) and (c) wait, as step 4 does, for what is left of the safety net of step 2: the row above for the test harness rewrite ([#641](https://github.com/matsumotory/ngx_mruby/pull/641) is merged; valgrind in CI, #634, and the auto-ssl tests, #636 on `master`, are done); then they start beside step 4 (decision of 2026-10-29). (b) and (d) also wait for step 4. The order inside the step is a proposal of the 2026-10-04 amendment until the owner decides it |
| Remove `example/` (`README.md`, `nginx.conf`, `proxy.rb`, `set.rb`, `set2.rb`, `unified_hello.rb`): no CI job starts it, no page links it, and its `/proxy` location picks among `test1.example.com` to `test3.example.com`, which are unreachable; `examples/start/` is checked by `examples.yml` | `next` | Ready to start |
| When a rewrite handler of the location that `Nginx.redirect` runs sleeps and the handler that called `Nginx.redirect` then answers the request, with a status or an exception, the response is followed by the output of the sleeping handler when its timer fires. The request ends and nothing leaks. After an exception nginx closes the connection; for a status, see [the review of #646](https://github.com/matsumotory/ngx_mruby/pull/646#issuecomment-6497236767), item 1. Not a 2.x fix: it needs the rewrite of the row "The async resume rewrite" (#646 leaves it out) | `next`, in the core stabilization of 3.0.0 | The row "The async resume rewrite" |
| A content handler of the location that `Nginx.redirect` runs from Ruby code ends the request at `Nginx::Async.sleep`, without its output ("Not changed by this release" in entry 2 of [the 2.7.3 release notes](releases/v2.7.3.md)). Not a 2.x fix: the handler that called `Nginx.redirect` goes on after the call and may answer the request itself | `next`, in the core stabilization of 3.0.0 | The row "The async resume rewrite" |
| A content handler that sleeps in `Nginx::Async.sleep` and then calls `Nginx.redirect` with a local URI: the client gets 200 and the body of the target, and the access log has 500. Run on 2026-10-31 on `next` with [#680](https://github.com/matsumotory/ngx_mruby/pull/680), nginx 1.31.8 with ASan and UBSan: `"GET /sleep_redirect HTTP/1.0" 500 6`. The same with a URL that nginx answers with 302 logs 302. A rewrite handler goes through the same code in `ngx_mrb_post_fiber` (read from the source, not run here), and `master` has the same code; [#646](https://github.com/matsumotory/ngx_mruby/pull/646) records this in its body. No test holds this yet. Not a 2.x fix: it is neither a stability nor a security fix, and `master` gets only the minimal fix of the amended decision (c) | `next`, in the core stabilization of 3.0.0 | The row "The async resume rewrite" |
| A proposal of the sessions for the rewrite, not a decision: let `Nginx::Async::HTTP.sub_request` work in a content handler after `Nginx::Async.sleep`, where it raises `RuntimeError` since 2.7.3 because nginx would not finish the request after the subrequest | `next`, in the core stabilization of 3.0.0 | The row "The async resume rewrite" |
| The async resume rewrite (decision (c) of 2026-10-04, amended on 2026-10-29: the rewrite of how resumed handlers end in `src/http/ngx_http_mruby_async.c`, which includes the resume of a handler after `Nginx::Async::HTTP.sub_request` from its own request). No pull request exists | `next`, in the core stabilization of 3.0.0 | Step 4, held as in the row on step 4 above |
| Change the path of the setter proposal in `docs/releases/v2.7.3.md` and `.ja.md` to `docs/proposals/archive/upstream-server-setters.md`, where #680 moves it | `master` | The merge of #680 |
| The generated reference of the site (Pillar F of the plan): the directives from the `ngx_command_t` tables, the Ruby API with YARD and yard-mruby, the C API with Doxygen. `site/scripts/check-reference.mjs` checks, among other things, that each directive name has a heading in `docs/directives/README.md`; the pages are written by hand | `next` | Ready to start; no step of section 6 of the site proposal produces it yet |

## How a session continues

Use [Continuing shared work](DEVELOPMENT.md#continuing-shared-work) for
startup, ownership, checkpoints, temporary files and resumption. The rules
are in [AGENTS.md](../AGENTS.md#session-handoff); this file records the
queue and decisions, while each PR records its current head and evidence.
The procedure applies to Claude, Codex and human contributors alike.

## Private material

Vulnerability reports and their fixes are handled privately as
[SECURITY.md](../SECURITY.md) describes; this file does not record them.

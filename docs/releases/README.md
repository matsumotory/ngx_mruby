# Release notes

Each release of ngx_mruby has a file in this directory, `vX.Y.Z.md`, that says
what changed in it. Its first section, "Behavior changes: read before
upgrading", lists every change that makes the same `nginx.conf`, Ruby script
or build behave differently from the previous release, who is affected, and
what to do. Before you upgrade, read that section in every file newer than the
version you run.

Releases up to v2.7.0 have no file here: their
[GitHub release pages](https://github.com/matsumotory/ngx_mruby/releases) list
the merged pull requests.

## What counts as a behavior change

A behavior change is a difference from the previous release that a
configuration, a Ruby script or a build can observe, and that someone may have
built on. The list below gives examples and is not complete: any difference
that can be observed counts.

- the status, headers or body of a response;
- the data that an `mruby_stream` handler sends, and when it closes the
  connection;
- what a Ruby method returns or raises, and which classes and methods exist;
- which handler runs, in which phase and order, and what its return value does;
- the value of an nginx variable set by `mruby_set`, `mruby_set_code` or
  `Nginx::Var`, as other directives and `log_format` read it;
- whether `nginx -t` accepts a configuration, and what a directive's arguments mean;
- lines in `error.log` at level `notice` and above that are added, removed or
  logged at another level, because operators alert on them;
- a build requirement that is raised (for example a newer minimum OpenSSL), a
  platform or nginx version that is no longer supported, a build option that
  is removed or changes meaning, and a change of the bundled mruby or of the
  mrbgems that the default `build_config.rb` includes.

A bug fix is a behavior change when a working configuration or script could
see the old behavior: for example, a response whose status or headers differ
after the fix, or a method that returned a value and now raises. A fix of a
crash or a leak alone is not one, because no configuration relies on a worker
crashing. When in doubt, record it as a behavior change.

"Previous release" means the last release tag `vX.Y.Z`, not the previous
commit. Pre-release tags (`-alpha.N`, `-beta.N`, `-rc.N`) are not releases in
this sense: `v3.0.0.md` compares 3.0.0 with the latest 2.x release. A behavior
that was added and then changed again between two releases was never
released: edit its entry instead of adding a second one.

Changes to tests, CI or documentation only, and refactoring with no observable
difference, need no entry.

## Who writes the entries, and when

- The pull request that makes a change also records it, in the same pull
  request:
  - a behavior change goes under "Behavior changes: read before upgrading".
    This includes the build changes in the last item of the list above; they
    may also be listed under "Build and test changes";
  - other fixes go under "Fixes";
  - additive build changes (a newly supported nginx version, a new build
    option), and test or CI changes that contributors or packagers need to
    know (for example new test ports), go under "Build and test changes".
- The first pull request of a release cycle that has something to record
  creates the file from the template below. Later pull requests of the cycle
  add to it, so the file always describes the version that will be tagged next.
- The same pull request updates [`docs/directives/`](../directives/),
  [`docs/class_and_method/`](../class_and_method/) or
  [`docs/install/`](../install/) so that they describe the new behavior. The
  release notes say what changed; those docs say how it works now.
- In review ([AGENTS.md](../../AGENTS.md#review-and-merge)), a behavior change
  without its entry under "Behavior changes: read before upgrading" is a
  "must fix" and blocks the merge. A missing "Fixes" or "Build and test
  changes" entry is a "should fix".
- Before each tag, a pull request checks the file against every pull request
  merged since the previous release (see "Before the tag" below).

## File names

The file is named after the version that will be tagged. If the owner tags a
different version, rename the file with `git mv` before the tag.

- `master`, before v3 is promoted: the next 2.x patch release. After the tag
  `v2.<minor>.<patch>`, the file is `v2.<minor>.<patch+1>.md`.
- `next`: one file, `v3.0.0.md`, for the whole 3.0.0 cycle, including its
  alpha, beta and rc pre-releases. It compares 3.0.0 with the latest 2.x
  release. Changes that reach `next` by merging `master` are recorded in the
  2.x file of the release that ships them, not again in `v3.0.0.md` (if 3.0.0
  is tagged before that 2.x release, copy the entry into `v3.0.0.md`).
- After v3 is promoted, `master` names its file after the next 3.x release,
  and `v2.x` after the next 2.x release.

Users who upgrade from 2.x to 3.0.0 read the 2.x files newer than their
version, then `v3.0.0.md`.

The v3 migration guide (planned in `docs/proposals/v3-plan.md` on `next`) is
built on the "Behavior changes" section of `v3.0.0.md`: it covers every entry
of that section, links to it, and adds the steps and examples. It does not
keep a second list, so each behavior change of 3.0.0 is recorded once, in
`v3.0.0.md`.

## Template

Copy this into `docs/releases/vX.Y.Z.md`. Keep every section, and write
"None." in a section that has no entries.

```markdown
# ngx_mruby vX.Y.Z

## Behavior changes: read before upgrading

### <The change, in one line> (#<pull request>)

- Before: <what a configuration, script or build observed on the previous release>
- Now: <what it observes on this release>
- Affected: <the directives, handlers, methods, configurations or builds that see the difference>
- What to do: <the change to make, or "nothing", with the reason>

## Fixes

- <The fix, in one line> (#<pull request>)

## Build and test changes

- <A newly supported nginx version, a new build option, a test or CI change> (#<pull request>)

## Upgrading

<Supported nginx versions, whether rebuilding the module is enough, and the
"What to do" lines above in one list.>
```

A raised build requirement, a dropped nginx version, a removed build option and
a change of the bundled mruby or of the default mrbgems go under "Behavior
changes: read before upgrading", not only under "Build and test changes".

## Before the tag

Before the owner tags a release, a pull request checks the file against what
was merged. It lists every pull request merged into the branch since the
previous release (`git log --first-parent --merges <previous tag>..origin/<branch>`;
on `next`, since the previous pre-release tag), confirms for each one that it
has its entry or changes nothing that a configuration, script or build can
observe, and adds the entries that are missing. Its body lists each pull
request with the section of its entry, or "no entry" and the reason. This
catches pull requests merged before this convention, pull requests whose
author did not follow it, and entries that a review missed. The same pull
request renames the file if the owner will tag a different version. The owner
tags after it is merged.

## The GitHub release

When the owner publishes a release, its body starts with the "Behavior
changes: read before upgrading" section copied from the file ("None." when
there are none), then a link to the file, then the list of pull requests that
GitHub generates. A pre-release on `next` copies the entries added or changed
since the previous pre-release;
`git diff <previous pre-release tag> <new tag> -- docs/releases/v3.0.0.md`
shows them. Agents prepare the file; they do not publish releases (see
[AGENTS.md](../../AGENTS.md#branches-and-pull-requests)).

## Security fixes

A security fix is prepared in the advisory's private fork and released as a
new version (see [SECURITY.md](../../SECURITY.md)). Its entries are written in
the same private pull request as the fix, so that the tagged file and the
release body have them:

- The entries are neutral: they name the affected component and say what is
  observable now. Nothing in them tells how to exploit or reproduce the
  problem, or says that it is a vulnerability.
- If the fix changes behavior, its "Behavior changes" entry says before, now,
  what is affected and what to do, in the same neutral terms.
- When the owner publishes the advisory, a pull request adds the advisory id
  (`GHSA-xxxx-xxxx-xxxx`) to the entries, and the owner adds it to the release
  body.

Until the advisory is published, nothing in the public repository mentions
the vulnerability (see [AGENTS.md "Security"](../../AGENTS.md#security)).

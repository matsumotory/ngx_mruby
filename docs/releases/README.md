# Release notes

Each release of ngx_mruby has a file in this directory, `vX.Y.Z.md`, that says
what changed in it. Its first section, "Behavior changes: read before
upgrading", lists every change that makes the same `nginx.conf` or Ruby script
behave differently from the previous release, who is affected, and what to do.
Before you upgrade, read that section in every file newer than the version you
run.

Releases up to v2.7.0 have no file here: their
[GitHub release pages](https://github.com/matsumotory/ngx_mruby/releases) list
the merged pull requests.

## What counts as a behavior change

A behavior change is a difference from the previous release that a
configuration or a Ruby script can observe, and that someone may have built on:

- the status, headers or body of a response;
- what a Ruby method returns or raises, and which classes and methods exist;
- which handler runs, in which phase and order, and what its return value does;
- whether `nginx -t` accepts a configuration, and what a directive's arguments mean;
- build requirements and options, the bundled mruby and mrbgems, and the
  supported nginx versions.

A bug fix is a behavior change when a working configuration or script could
see the old behavior: for example, a response whose status or headers differ
after the fix, or a method that returned a value and now raises. A fix of a
crash or a leak alone is not one, because no configuration relies on a worker
crashing. When in doubt, record it as a behavior change.

"Previous release" means the last tag, not the previous commit. A behavior
that was added and then changed again between two releases was never
released: edit its entry instead of adding a second one.

## Who writes the entries, and when

- The pull request that makes a change also records it, in the same pull
  request. A behavior change goes under "Behavior changes: read before
  upgrading"; other fixes go under "Fixes"; changes to the build or the test
  harness go under "Build and test changes".
- The first pull request of a release cycle that has something to record
  creates the file from the template below. Later pull requests of the cycle
  add to it, so the file always describes the version that will be tagged next.
- The same pull request updates [`docs/directives/`](../directives/),
  [`docs/class_and_method/`](../class_and_method/) or
  [`docs/install/`](../install/) so that they describe the new behavior. The
  release notes say what changed; those docs say how it works now.
- The review checklist and the merge conditions in
  [AGENTS.md](../../AGENTS.md#review-and-merge) treat a behavior change
  without its entry as "must fix".

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

## Template

Copy this into `docs/releases/vX.Y.Z.md`. Keep every section, and write
"None." in a section that has no entries.

```markdown
# ngx_mruby vX.Y.Z

## Behavior changes: read before upgrading

### <The change, in one line> (#<pull request>)

- Before: <what a configuration or script observed on the previous release>
- Now: <what it observes on this release>
- Affected: <the directives, handlers, methods or configurations that see the difference>
- What to do: <the change to make, or "nothing", with the reason>

## Fixes

- <The fix, in one line> (#<pull request>)

## Build and test changes

- <Build requirements, bundled mruby or mrbgems, supported nginx versions, test harness> (#<pull request>)

## Upgrading

<Supported nginx versions, whether rebuilding the module is enough, and the
"What to do" lines above in one list.>
```

## The GitHub release

When the owner publishes a release, its body starts with the "Behavior
changes: read before upgrading" section copied from the file ("None." when
there are none), then a link to the file, then the list of pull requests that
GitHub generates. A pre-release on `next` copies the entries added since the
previous pre-release; `git diff <previous tag> <new tag> -- docs/releases/v3.0.0.md`
shows them. Agents prepare the file; they do not publish releases (see
[AGENTS.md](../../AGENTS.md#branches-and-pull-requests)).

## Security fixes

A security fix is described neutrally: the affected component, the advisory
id (`GHSA-xxxx-xxxx-xxxx`) and the version that fixes it. Never describe how
to exploit or reproduce the problem. The entry is added when the owner
publishes the advisory, not before; until then nothing in the repository
mentions the vulnerability (see [AGENTS.md "Security"](../../AGENTS.md#security)
and [SECURITY.md](../../SECURITY.md)). If the fix also changes behavior, its
"Behavior changes" entry says what is observable now and what to do, in the
same neutral terms.

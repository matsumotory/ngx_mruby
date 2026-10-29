# Contributing

ngx_mruby takes changes as pull requests on GitHub, from people and from
coding agents alike. This page says where a change goes and what a pull
request needs. [AGENTS.md](AGENTS.md) holds the full rules; agents read it
first, and it is the reference for people as well.

## Where a change goes

| Change | Base branch |
|---|---|
| A fix of a crash, a hang, a leak or a build failure of 2.x | `master`, until v3 is promoted to it at v3.0.0 |
| New behavior, a new directive or method, an API cleanup, any work for v3 | `next` |

The 2.x line puts compatibility first: it changes behavior a
configuration, script or build can observe only as far as the fix of a
defect requires. A fix that also applies to v3 goes to `master`, which is
merged into `next`. [Branch strategy](README.md#branch-strategy) describes
the branches.

A security vulnerability does not go into an issue or a pull request:
[SECURITY.md](SECURITY.md) says how to report it privately, and its fix is
prepared privately too.

## What a pull request needs

- Every section of the
  [pull request template](.github/PULL_REQUEST_TEMPLATE.md), with "n/a"
  where one does not apply.
- For a change of the code, tests in `test/` that assert on the actual
  response, preferably a server fragment in `test/conf/conf.d/`, its
  scripts in `test/html/` and a case in `test/t/cases/`
  ([Testing](docs/test/README.md)). Run the suite with `sh test.sh`. A
  change of the documentation alone needs no test.
- For a bug fix, two commits: the first adds the regression test, which
  fails, and the second adds the fix, which makes it pass. The pull
  request quotes the result of the suite at each commit.
- For a change that a configuration, script or build can observe, an
  entry under "Behavior changes: read before upgrading" in
  `docs/releases/<version>.md` and the same entry in Japanese in
  `docs/releases/<version>.ja.md` ([Release notes](docs/releases/README.md)).
- The docs of `docs/` updated when a directive, a Ruby method, a build
  option or the test harness changes.
- For a change of `src/`, `mrbgems/` or the build, the performance
  comparison that "Design principles" in AGENTS.md describes.

## Review and merge

Someone who did not write the pull request reviews it with the checklist
of "Review and merge" in AGENTS.md and posts the findings as a comment.
The pull request merges, with a merge commit, when CI passes on its head,
no "must fix" item of the review is open, and the other conditions listed
there hold. The owner keeps the tags, the releases and the security
advisories.

## Where to ask

Open an issue on GitHub for a question, a bug that is not a security
vulnerability, or a proposal. Larger plans for v3 are in
[docs/proposals/](docs/proposals/), and the state of the work is in
[docs/HANDOFF.md](docs/HANDOFF.md).

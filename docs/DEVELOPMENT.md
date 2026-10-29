# Developing ngx_mruby

This is a collection of random tips to help ngx_mruby developers.

Before you change the C module (`src/`), the gems in `mrbgems/` or the
build, read [Design principles](../AGENTS.md#design-principles) in
AGENTS.md: the owner's decisions (one `mrb_state` per worker, no blocking,
keep the existing performance and measure it) and how sessions apply them,
including which changes are measured and how.

## Recommended development environment

We use vagrant for development of ngx_mruby.

You may want to develop in same development environment.

### Setup development environment

```
cd ngx_mruby
vagrant up       # run provisioner automatically
vagrant ssh
```

### Test in development environment using ubuntu 18.04

```
cd ngx_mruby/
sh test.sh
```

### Format C source code

Run apply-clang-format script.

```
cd ngx_mruby
sh apply-clang-format
```

## Adding newer version nginx support

Edit [nginx_version](../nginx_version) and [.travis.yml](../.travis.yml).
See https://github.com/matsumotory/ngx_mruby/commit/02ddb38b68702d9abe8fb0a8c172ee1d80ad2b2d for example.

TODO: retirement policy

## Updating mruby

If you want to update [in-tree mruby](../mruby) to latest version, you can use [update-mruby-subtree](../update-mruby-subtree) script. It adds the mruby upstream repo as dep-mruby and pull all changes to the current branch.

```
git checkout -b BRANCH
sh update-mruby-subtree
```

If you want to update to a specific commit, you can specify a ref.

```
sh update-mruby-subtree REF
```

The script runs `git subtree pull --prefix=mruby --squash dep-mruby REF`, so
the merge starts from the last subtree squash in the history of `mruby/`.
When that squash is old, or when `mruby/` was changed by commits that were
not subtree pulls, the pull stops with conflicts under `mruby/`. Do not
resolve them by hand (files under `mruby/` are never edited by hand).
Instead, inside the merge that stopped, replace the subtree with the exact
tree of the ref, and commit the merge:

```
git rm -r -q --cached mruby
rm -rf mruby
git read-tree --prefix=mruby/ -u REF^{tree}
```

Use the commit id for `REF` here if the tag was not fetched as a local tag;
`update-mruby-subtree` fetches the ref only into `FETCH_HEAD`. `git read-tree`
writes every file of the tree, also the ones that `.gitignore` of this
repository would keep out of a `git add` (for example `mruby/Makefile` and
files under `mruby/lib/mruby/build/`). Before you commit, check that the
index holds the tree of the ref under `mruby/`; the two commands must print
the same id:

```
git write-tree --prefix=mruby/
git rev-parse REF^{tree}
```

Then commit the merge, and put the two ids in the commit message:

```
git commit
```

After the commit, `git rev-parse HEAD:mruby` prints the same id.

The squash commit that `git subtree` made is the second parent of the merge
and records `git-subtree-split: <commit of REF>`, so the next update merges
from that commit instead of the older squash. Commit the merge alone, with
nothing outside `mruby/`, and make the build changes in the commits that
follow.

`NGX_MRUBY_CORE_GEMS` in [build_config.rb](../build_config.rb) names the mruby
core gems that ngx_mruby builds, so an update does not change them by itself.
The mruby build stops when a listed gem is not in the new `mruby/mrbgems`:
remove it from the list, or replace it, as a decision of its own. To build
anyway while you work on the update, set `NGX_MRUBY_ALLOW_MISSING_CORE_GEMS=1`;
the build then skips the missing gems with a notice. Gems that the new mruby
adds are not built until you add them to the list.

After the update, remove `mruby/build`, build with `sh test.sh`, and commit the
`build_config.rb.lock` that rake wrote with the update: the lock records the
version of mruby. rake writes the lock at the end of a build, and the check of
`NGX_MRUBY_CORE_GEMS` stops the build while rake loads `build_config.rb`, so
rake writes no new lock until every listed gem is found or
`NGX_MRUBY_ALLOW_MISSING_CORE_GEMS=1` is set. A dependency that the new mruby
provides as one of its own gems is no longer cloned, but rake keeps its entry
in the lock, so delete that entry (see "Gem commits" in
[docs/install/README.md](install/README.md)).

## Updating ngx_devel_kit

If you want to update [in-tree ngx_devel_kit](../dependence/ngx_devel_kit) to latest version, you can use [update-devkit-subtree](../update-devkit-subtree) script. It adds the ngx_devel_kit upstream repo as dep-ngx_devel_kit and pull all changes to the current branch.

```
git checkout -b BRANCH
sh update-devkit-subtree
```

If you want to update to a specific commit, you can specify a ref.

```
sh update-devkit-subtree REF
```

## Promoting v3 to master

Until v3 is promoted, `master` is the 2.x line, v3 is developed on `next`, and
`v2.x` is an automatic copy of `master`: on every push to `master`, the
workflow [mirror-v2x.yml](../.github/workflows/mirror-v2x.yml) fast-forwards
`v2.x` to it. The promotion merges `next` into `master` at v3.0.0, so that
`master` becomes the 3.x line and `v2.x` keeps the 2.x line (see
[Branch strategy](../README.md#branch-strategy)). This section is the
procedure.

Agents prepare the pull requests and run the checks. The owner creates the
tags and publishes the releases, as
[AGENTS.md](../AGENTS.md#branches-and-pull-requests) says. The steps below
also give the owner the go for the promotion and the repository settings of
steps 2 and 3; those parts are recommendations (see "Open questions" below).

The repository has four rulesets (as of 2026-10-04). Step 3 changes the first
two:

- `protected-lines`, on `master` and `next`: changes only through pull
  requests, the `ci-ok` check must pass, no deletion, no force push.
- `v2x-mirror`, on `v2.x`: no deletion, no force push. It has no pull request
  rule, because that rule would reject the pushes of the mirror workflow.
- `release-tags`, on `v*` tags: only repository admins create, move or delete
  them.
- `no-branch-shaped-tags`, on the tags `v*.x`, `next`, `master` and `main`:
  nobody can create them, so that a name such as `v2.x` always means the
  branch.

### Conditions

The owner checks that all of these hold and gives the go before step 1:

1. A `v3.0.0-rc.N` pre-release is tagged on `next`, CI passed on it, and no
   defect reported against it blocks the release. How long the last release
   candidate stays out is open (see "Open questions" below).
2. The v3 migration guide and the release notes of v3.0.0 are complete.
3. The last 2.x release before the promotion is tagged on `master`, and the
   entries of its release notes are recorded. 2.x fixes merged after that tag
   go out in the next 2.x release from `v2.x`.
4. The open questions below are decided and recorded, in the v3 plan or in
   this section. Step 4 describes the branches as they are after the
   promotion, and that text depends on what `next` becomes, how fixes travel
   between the lines and which version the site shows.

### Steps

1. **Final merge-up (agent).** Merge `master` into `next` with a pull request,
   as for every merge-up, so that `next` has every 2.x fix. From here until
   step 5, merge nothing else into `master`. If a 2.x fix cannot wait, merge it
   before step 2 and repeat this step.
2. **Stop the mirror (owner).** Check that `v2.x` and `master` point at the
   same commit: `git ls-remote origin refs/heads/master refs/heads/v2.x`
   prints one id twice. If the ids differ, run the workflow on `master`
   (`gh workflow run mirror-v2x.yml --ref master`), wait until the run has
   finished (`gh run list --workflow=mirror-v2x.yml`), and check again. If the
   run fails, its job log says how to repair `v2.x`, for example when `v2.x`
   has commits that are not on `master` or when the push was rejected for the
   `workflows` permission. Do not disable the workflow until the ids match.
   Then disable it with `gh workflow disable mirror-v2x.yml`. From here on,
   `v2.x` stays at the last 2.x commit. Do this before step 5: the merge
   commit of step 5 has the tip of `v2.x` as its first parent, so the
   workflow, if it ran for that push, would fast-forward `v2.x` to 3.x. Step 4
   removes the workflow file from the merge commit of step 5, which also keeps
   it from running; disabling it here protects `v2.x` without relying on
   step 4.
3. **Protect `v2.x` like the other lines (owner).** Add `refs/heads/v2.x` to
   the targets of `protected-lines` and delete `v2x-mirror`. From then on,
   `v2.x` changes only through pull requests that passed `ci-ok`. CI needs no
   change: [test.yml](../.github/workflows/test.yml) already runs on pushes and
   pull requests to `v*.x`.
4. **Prepare `next` (agent).** Two pull requests to `next`, merged in this
   order:
   - A pull request that deletes `.github/workflows/mirror-v2x.yml` and
     describes the branches as they are after the promotion: the branch
     strategy in README.md, the branch table and rules in AGENTS.md, the
     supported versions in SECURITY.md, and "Target branch" in
     `.github/PULL_REQUEST_TEMPLATE.md` (2.x fixes target `v2.x`, v3 fixes
     target `master`). It also adds to `.github/dependabot.yml` a second
     `github-actions` entry with `target-branch: "v2.x"`, so that the file
     has it on `master` from step 5 on. Dependabot reads that file only from
     the default branch, and an entry without `target-branch` updates only the
     default branch, so without the new entry nothing would update the
     SHA-pinned actions in the workflows of `v2.x` while 2.x is supported.
     It also moves the site with the lines, so that pages of an unreleased
     3.1 never become the current version (5.2 of
     [the site proposal](https://github.com/matsumotory/ngx_mruby/blob/next/docs/proposals/site.md#52-repository-layout)):
     `.github/workflows/site.yml` runs on and deploys from `master` and
     builds `/v2/` from `docs/` of `v2.x`, and `site-v2.yml` and
     `site-dispatch.yml` are removed.
   - The check pull request of
     ["Before the tag"](releases/README.md#before-the-tag) for
     `docs/releases/v3.0.0.md`. As that section says for `next`, its range
     starts at the last `v3.0.0-rc.N` tag, it confirms that the 2.x pull
     requests brought by the merges of `master` into `next` since that tag
     (including step 1) have their entries in the 2.x file, and it copies
     into `v3.0.0.md` the entries of the 2.x release that is not tagged yet
     (the 2.x fixes merged after the last 2.x release of condition 3), because
     v3.0.0 ships them first. After this pull request, merge nothing else into
     `next` until step 5.
5. **Promote (agent, on the owner's go that day).** A pull request with head
   `next` and base `master`, merged with a merge commit when the conditions of
   "Review and merge" in [AGENTS.md](../AGENTS.md#review-and-merge) hold, as
   for every pull request, and only after the owner has confirmed that day
   that they tag it in step 6 right away, so that `master` is not an untagged
   3.x line in between. It has no conflicts, because step 1 merged `master`
   into `next`. `master` stays the default branch; nothing about the default
   branch changes. Right before the merge, the owner changes the deployment
   branch rule of the `github-pages` environment from `next` to `master`
   (Settings, Environments, `github-pages`, "Deployment branches"), so that
   the push of the merge deploys the site from `master`.
6. **Tag and release (owner), right after step 5.** Tag `v3.0.0` on the merge
   commit of step 5 and publish its GitHub release, not marked as a
   pre-release, with the release notes. Tagging that commit instead of the
   merge commit of the check pull request is the "later commit" case of
   ["Before the tag"](releases/README.md#before-the-tag): the check is
   repeated for the pull requests merged after the check pull request. The
   only one is the promotion of step 5, and it needs no entry: `master` is an
   ancestor of `next` after step 1, so the merge commit of step 5 has the same
   tree as `next` and changes nothing that a configuration, script or build can
   observe.
7. **Announce (agent).** A pull request to `master` that adds the release date
   of v3.0.0 and the end of 2.x support (twelve months later) to README.md and
   SECURITY.md. A pull request to `v2.x` that:
   - describes `v2.x` as the 2.x line in its README.md, AGENTS.md, SECURITY.md
     and pull request template;
   - deletes its copy of `mirror-v2x.yml` (that copy never runs, because only
     pushes to `master` trigger it);
   - points the absolute links to `master` in its files at `v2.x`, because on
     `v2.x` they would lead to the 3.x files: the `tree/master` and
     `blob/master` URLs of this repository (24 on 2026-10-04, in README.md,
     `docs/` and the pull request template), the CI badge
     `badge.svg?branch=master` in README.md and the download link
     `archive/master.zip` in `docs/install/README.md`;
   - adds `-b v2.x` to the clones of the default branch
     (`git clone https://github.com/matsumotory/ngx_mruby.git` without `-b`)
     in `docs/install/README.md`, `Dockerfile` and `misc/provision.sh`.
     Without it, a 2.x user who follows the install guide on `v2.x`, or builds
     the Dockerfile from a `v2.x` checkout, gets 3.x;
   - points its copies of `site-v2.yml` and `site-dispatch.yml`, which run
     only for `master`, at `v2.x`, and makes the dispatch start `site.yml`
     with `--ref master`, so that a change to the 2.x documentation still
     reaches `/v2/`.

   This command lists the links, the badge and the clones:
   `git grep -n -E 'ngx_mruby/(tree|blob|archive)/master|branch=master|clone https://github\.com/matsumotory/ngx_mruby'`.
8. **Afterwards.** 2.x fixes target `v2.x`, and v3 fixes target `master`. The
   owner publishes each 2.x release so that it does not become the
   repository's latest release, which stays with 3.x:
   `gh release create <tag> --latest=false`. Through the REST API,
   `make_latest` defaults to `true` for a published release; in the web form,
   leave "Set as latest release" unselected.

### Open questions

The v3 plan does not decide these yet. Each has a recommendation. Condition 4
requires them to be decided before step 1.

- **What `next` becomes after the promotion.** Recommendation: keep it as the
  development branch of the next minor release (3.1), with pre-release tags, so
  that `master` stays the released 3.x line that users of the default branch
  build, as it is the released 2.x line today. The other choice is to retire
  `next` and develop 3.1 on `master`.
- **How long the last release candidate stays out before v3.0.0.**
  Recommendation: at least two weeks without a new report that blocks the
  release.
- **How a fix that both lines need travels after the promotion.**
  Recommendation: fix `master` first and backport the fix to `v2.x` on a
  `backport/v2.x/<topic>` branch, the name AGENTS.md already gives backports.
  Merging `v2.x` into `master` would also bring changes made only for 2.x.
- **Who gives the go for the promotion and changes the repository settings
  in steps 2 and 3.** Recommendation: the owner. Whether condition 1 holds is
  a judgment, the tag of step 6 is the owner's, and the settings need admin
  rights; a mistake there lets `v2.x` move to 3.x. AGENTS.md does not cover
  the go or the repository settings yet.

The site proposal decides which version the site shows after the
promotion (Q1 and Q4, decided by the owner on 2026-10-15, in section 7 of
[`docs/proposals/site.md`](https://github.com/matsumotory/ngx_mruby/blob/next/docs/proposals/site.md#7-decisions-2026-10-15)
on `next`). The site, ngx.mruby.org, is built from `docs/` by
`.github/workflows/site.yml` on `next` and deployed by GitHub Actions:
3.x from `next` at the unprefixed paths, and
2.x from `master` under `/v2/`. From the promotion on, the unprefixed
paths show the released 3.x from `master` and `/v2/` shows 2.x from
`v2.x`: steps 4, 5 and 7 move the workflows and the deployment branch
rule.

# Developing ngx_mruby

This is a collection of random tips to help ngx_mruby developers.

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

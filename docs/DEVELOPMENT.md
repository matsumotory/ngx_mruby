# Developing ngx_mruby

This is a collection of random tips to help ngx_mruby developers.

## Adding newer version nginx support

Edit [nginx_version](../nginx_version) and [.travis.yml](../.travis.yml).

TODO: retirement policy

## Updating mruby

If you want to update [in-tree mruby](../mruby) to latest version, you can use [update-mruby-subtree](../update-mruby-subtree) script. It adds the mruby upstream repo as dep-mruby and pull all changes to the current branch.

```
% git checkout -b BRANCH
% update-mruby-subtree
```

If you want to update to a specific commit, you should use 'git subtree pull'.

TODO: more specific

## Updating ngx_devel_kit

TODO: To be written


# Developing ngx_mruby

This is a collection of random tips to help ngx_mruby developers.

## Recommended development environment

We use vagrant for development of ngx_mruby.

You may want to develop in same development environment.

- setup development environment

```
cd ngx_mruby
vagrant up       # run provisioner automatically
vagrant ssh
```

- in development environment using ubuntu 16.04

```
cd ngx_mruby/
sh test.sh
```

- code formatting

```
cd ngx_mruby/
sh apply-clang-format
```

## Adding newer version nginx support

Edit [nginx_version](../nginx_version) and [.travis.yml](../.travis.yml).

TODO: retirement policy

## Updating mruby

If you want to update [in-tree mruby](../mruby) to latest version, you can use [update-mruby-subtree](../update-mruby-subtree) script. It adds the mruby upstream repo as dep-mruby and pull all changes to the current branch.

```
% git checkout -b BRANCH
% update-mruby-subtree
```

If you want to update to a specific commit, you can specify a ref.

```
% update-mruby-subtree REF
```

## Updating ngx_devel_kit

If you want to update [in-tree ngx_devel_kit](../dependence/ngx_devel_kit) to latest version, you can use [update-devkit-subtree](../update-devkit-subtree) script. It adds the ngx_devel_kit upstream repo as dep-ngx_devel_kit and pull all changes to the current branch.

```
% git checkout -b BRANCH
% update-devkit-subtree
```

If you want to update to a specific commit, you can specify a ref.

```
% update-devkit-subtree REF
```

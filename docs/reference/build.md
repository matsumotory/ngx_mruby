# Build

This page describes how the build of ngx_mruby fits together, the options
of `./configure` and `build.sh`, the mrbgems of the default build, and the
versions that CI builds and tests. [Install](../install/README.md) has the
steps.

## How the build fits together

```diagram
build-layout
caption: The steps of the build of ngx_mruby, in the order in which `./configure` and `make` run them.
source: configure.in 53-62 190-194
source: Makefile.in 27-28 87 98-119
source: config.in 48-81
source: build_config.rb 81-153
source: build.sh 103 107
at: c35606b0e 2026-10-19
configure: `./configure` writes `config` and `Makefile` from `config.in` and `Makefile.in`
rake: `make` runs mruby's `rake` with `build_config.rb` and its lock: `libmruby.a` with the mrbgems
mrbgems-config: `make` writes `mrbgems_config` (`mrbgems_config_dynamic`) from the flags of that mruby build
nginx-configure: nginx's `configure` with ngx_mruby by `--add-module` (`--add-dynamic-module` after `--enable-dynamic-module`) and `ngx_devel_kit`; `config` reads `mrbgems_config`
nginx-make: nginx's `make`: nginx with ngx_mruby built in, or a module file that nginx loads
modules: in it: `ngx_http_mruby_module`, `ngx_stream_mruby_module` with nginx's stream module, and the upstream keepalive module of ngx_mruby
```

- `./configure` writes `config` and `Makefile` from `config.in` and
  `Makefile.in`. `--enable-dynamic-module` makes the `Makefile` pass
  ngx_mruby to nginx's `configure` with `--add-dynamic-module` instead of
  `--add-module`. It always passes `dependence/ngx_devel_kit` with
  `--add-module`; `mruby_set` uses its `set_var` part.
- `make` first builds mruby: in `mruby/`, `rake` reads `build_config.rb`,
  which names the core gems and the third-party mrbgems, and
  `build_config.rb.lock`, which pins the commit of each third-party
  mrbgem. The result is the library `libmruby.a` with the gems in it, and
  `libmruby.flags.mak` with the compiler and linker flags that the gems
  need, from which `make` writes `mrbgems_config`
  (`mrbgems_config_dynamic` for a dynamic build).
- `make` then runs nginx's `configure` and `make` in the nginx source
  tree. `config` reads `mrbgems_config` and links `libmruby.a` into nginx,
  or into the module file of a dynamic build. The module holds
  `ngx_http_mruby_module`, the upstream keepalive module of ngx_mruby
  (`mruby_upstream_keepalive`) and, in a build with nginx's stream module,
  `ngx_stream_mruby_module`.
- `build.sh` runs `./configure` with the nginx source that it downloads,
  and then `make`.

## Options of configure

| Option | What it sets | Default |
|---|---|---|
| `--with-ngx-src-root=DIR` | the nginx source tree | none: `configure` stops without it |
| `--with-ngx-config-opt=OPT` | the options that `make` passes to nginx's `configure` | none |
| `--enable-dynamic-module` | builds ngx_mruby as a dynamic module | a static module |
| `--with-build-dir=DIR` | the directory that `make clobber` removes; `build.sh` passes `build` or `build_dynamic`, where it puts the nginx source | `build` |
| `--with-openssl-src=DIR` | OpenSSL sources that nginx builds with (`--with-openssl` of nginx) | the system's OpenSSL |
| `--with-openssl-opt=OPTIONS` | more options for the build of OpenSSL (`--with-openssl-opt` of nginx) | none |
| `--with-mruby-root=DIR` | the mruby tree to build | `mruby/` of this repository |
| `--with-mruby-incdir=DIR` | the include directories of mruby | `src`, `include` and `build/host/include` of the mruby tree |
| `--with-mruby-libdir=DIR` | the directory of `libmruby.a` | `build/host/lib` of the mruby tree |
| `--with-ndk-root=DIR` | the `ngx_devel_kit` tree | `dependence/ngx_devel_kit` |

## Environment of the build

| Variable | Read by | What it does |
|---|---|---|
| `NGINX_CONFIG_OPT_ENV` | `build.sh` | all the options of nginx's `configure`, in place of the default set: the prefix `build/nginx` (`build_dynamic/nginx` for a dynamic build), `--with-http_stub_status_module`, `--with-stream`, `--without-stream_access_module` and `--with-cc-opt=-fno-common` |
| `NGINX_SRC_ENV` | `build.sh` | an nginx source tree to use instead of the download of the version in `nginx_version` |
| `BUILD_DYNAMIC_MODULE` | `build.sh` | any value builds a dynamic module in `build_dynamic/` |
| `NUM_THREADS_ENV` | `build.sh` | the number of jobs of `make`; by default half the processors |
| `OPENSSL_SRC_VERSION` | `build.sh` | downloads that version of OpenSSL and builds nginx with it |
| `NGX_MRUBY_AUTO_SSL=1` | `build_config.rb` | adds the auto-ssl mrbgem and its dependencies ([Building with the auto-ssl mrbgem](../install/README.md#building-with-the-auto-ssl-mrbgem)) |
| `NGX_MRUBY_ALLOW_MISSING_CORE_GEMS=1` | `build_config.rb` | skips, with a notice, the names of `NGX_MRUBY_CORE_GEMS` that the mruby being built does not have |
| `NGX_MRUBY_CFLAGS`, `NGX_MRUBY_LDFLAGS`, `NGX_MRUBY_LIBS` | `build_config.rb` | more compiler flags, linker flags and libraries for the mruby build |

## Default mrbgems

The default `build_config.rb` builds these mrbgems into `libmruby.a`,
besides the mruby core gems that `NGX_MRUBY_CORE_GEMS` lists
([Core gems](../install/README.md#core-gems)). `build_config.rb.lock` pins
the commit of each third-party gem
([Gem commits](../install/README.md#gem-commits-build_configrblock)).

- `iij/mruby-env` ([repository](https://github.com/iij/mruby-env)): `ENV`
- `iij/mruby-digest` ([repository](https://github.com/iij/mruby-digest)): `Digest` (MD5, RMD160, SHA1, SHA256, SHA384, SHA512 and HMAC)
- `iij/mruby-process` ([repository](https://github.com/iij/mruby-process)): `Process`
- `mattn/mruby-json` ([repository](https://github.com/mattn/mruby-json)): `JSON`
- `mattn/mruby-onig-regexp` ([repository](https://github.com/mattn/mruby-onig-regexp)): `OnigRegexp`
- `matsumotory/mruby-redis` ([repository](https://github.com/matsumotory/mruby-redis)): `Redis`, a client that waits for each answer of the Redis server in the worker. Its build clones the hiredis library at the tag v1.5.0, checks its commit and links it statically, and clones matsumotory/mruby-pointer, which the gem depends on. A script that calls it needs a running Redis server
- `matsumotory/mruby-vedis` ([repository](https://github.com/matsumotory/mruby-vedis)): `Vedis`
- `matsumotory/mruby-userdata` ([repository](https://github.com/matsumotory/mruby-userdata)): `Userdata`
- `matsumotory/mruby-uname` ([repository](https://github.com/matsumotory/mruby-uname)): `Uname`
- `matsumotory/mruby-mutex` ([repository](https://github.com/matsumotory/mruby-mutex)): `Mutex`
- `matsumotory/mruby-localmemcache` ([repository](https://github.com/matsumotory/mruby-localmemcache)): `Cache`
- `monochromegane/mruby-secure-random` ([repository](https://github.com/monochromegane/mruby-secure-random)): `SecureRandom`
- `mrbgems/ngx_mruby_mrblib` ([source](../../mrbgems/ngx_mruby_mrblib)): the Ruby part of the classes of ngx_mruby
- `mrbgems/rack-based-api` ([source](../../mrbgems/rack-based-api)): the Rack compatible API (`run`)

The check `site/scripts/check-reference.mjs` compares this list with the
lines `conf.gem` of the host build in `build_config.rb` that are not
comments and have no condition. The lines that are comments name gems that the default build
leaves out, such as mruby-discount and mruby-memcached: to build with one,
uncomment its line and remove `mruby/build`.

## Versions that CI builds and tests

The workflow `.github/workflows/test.yml` builds ngx_mruby and runs
`test.sh` for each of these combinations on every pull request:

| nginx | Module | OpenSSL | nginx runs under |
|---|---|---|---|
| 1.31.6, 1.30.5, 1.28.3, 1.26.3 | static and dynamic | 1.1.1w, installed, or built into nginx with `--with-openssl-src` | valgrind |
| 1.31.6 | static | 1.1.1w, installed | AddressSanitizer and UndefinedBehaviorSanitizer |

- The runner is Ubuntu 22.04 with GCC 11. The bundled mruby is 4.0.0
  (`build_config.rb.lock`).
- `nginx_version` names the version that `build.sh` and `test.sh`
  download, 1.31.6.

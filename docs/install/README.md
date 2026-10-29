# Installing ngx_mruby 2.x

This guide builds a standalone nginx with ngx_mruby, then serves an inline
Ruby handler and a cached script on loopback without root privileges.
It uses the released `v2.7.2` tag with nginx 1.31.8, the nginx version
selected by the current 2.x maintenance branch. `master` is the 2.x maintenance development
branch until v3 is promoted; it is not a released version. `next` is v3
and has its own [development documentation](https://ngx.mruby.org/).
Read the [release notes](../releases/README.md) before upgrading an existing installation.

## Installing from source

### Prerequisites

A C/C++ compiler, GNU make, Ruby with rake, bison, git, wget, curl,
OpenSSL development headers/libraries, PCRE development headers/libraries,
and zlib development headers/libraries are required. The build downloads
third-party mrbgems from GitHub. A Docker Hub account is not required.

For example, on Ubuntu 22.04, install the packages with administrator
privileges, then build as an ordinary user:

```sh
sudo apt-get update
sudo apt-get install build-essential ruby rake bison git wget curl ca-certificates libssl-dev libpcre3-dev zlib1g-dev
```

The walkthrough is tested on Linux; package names differ on other systems.
For a version-managed Ruby, ensure its `ruby` and `rake` are on `PATH`.
Do not copy a dynamic module into an unrelated distribution nginx binary:
its nginx version, configuration and ABI need to match.

## 1. Downloading source from github.com

```sh
git clone --branch v2.7.2 https://github.com/matsumotory/ngx_mruby.git
cd ngx_mruby
git rev-parse HEAD
```

The tag selects ngx_mruby's source and its vendored mruby. It does not pin
all external mrbgems: 2.x does not commit `build_config.rb.lock`; fresh builds
can fetch newer gem commits. Keep the generated lock and build log with your
own build record. This is not a promise of byte-for-byte reproducibility.

## 2. Configuring mrbgems

ngx_mruby's default mrbgem configuration contains basic features. But if you want to have __more features__, 
you will find additional mrbgems at [the list of mrbgems](https://github.com/mruby/mruby/wiki/Related-Projects) 
and add them to [build_config.rb](https://github.com/matsumotory/ngx_mruby/blob/master/build_config.rb).

The default build already includes mruby-io. File, socket, sleep and Redis
operations in a handler can block its worker; inclusion does not make them
nginx event-driven operations. See the [API reference](../class_and_method/README.md).

Here is the list of the mrbgems that the default build_config.rb builds.

- full-core gembox: every core mrbgem of the bundled mruby except mruby-bin-debugger and mruby-test, for example mruby-io, mruby-pack (pack, unpack...), mruby-sleep (sleep, usleep...), mruby-random, mruby-socket, mruby-time and mruby-print
- mruby-env: use environment value
- mruby-dir: Dir class
- mruby-digest: MD5, RMD160, SHA1, SHA256, SHA384, SHA512 and HMAC Digests
- mruby-process: Process ::fork, ::kill, ::pid, ::ppid, ::waitpid...
- mruby-json: JSON::parse, JSON::stringify
- mruby-onig-regexp: regexp engine
- mruby-redis: Redis#set, get, [], []=... The build of the gem clones the hiredis library at the tag v1.5.0, checks its commit, and links it statically ([matsumotory/mruby-redis#108](https://github.com/matsumotory/mruby-redis/pull/108)); the build also clones matsumotory/mruby-pointer, which the gem depends on. The default build left the gem out in 2.7.1, because the build of the gem cloned hiredis from an unpinned branch, which broke the build of ngx_mruby, and includes it again since 2.7.2 (see "Redis is in the default build again" in [the 2.7.2 release notes](../releases/v2.7.2.md)). A script that calls Redis needs a running Redis server, and the gem waits for each answer of the server in the worker (it uses the blocking API of hiredis), so the worker serves no other request meanwhile. The examples that use Redis (in the README and in [Use Case](../use_case)) and the client of the auto-ssl mrbgem need the gem.
- mruby-vedis: Vedis#set, get, [], []=...
- mruby-userdata: https://github.com/matsumotory/mruby-userdata
- mruby-uname: https://github.com/matsumotory/mruby-uname
- mruby-mutex: https://github.com/matsumotory/mruby-mutex
- mruby-localmemcache: https://github.com/matsumotory/mruby-localmemcache
- mruby-secure-random: https://github.com/monochromegane/mruby-secure-random
- the mrbgems of ngx_mruby itself: mrbgems/ngx_mruby_mrblib, mrbgems/rack-based-api and mrbgems/auto-ssl (its `Nginx::SSL::ACME::Client` speaks ACMEv1, which Let's Encrypt fully turned off on 1 June 2021, see [the class and method reference](../class_and_method/README.md#auto-ssl-mrbgem))

build_config.rb also has lines for mrbgems that are not built by default.
To build one of them, uncomment its line.

- mruby-memcached: Memcached#set, get, [], []=...
- mruby-file-stat, mruby-discount, mruby-mysql, mruby-geoip, mruby-capability and mruby-cgroup

## 3. Building a binary

### 3-A. Using build.sh

From the repository root, fetch the nginx version used for this walkthrough
and build it explicitly:

```sh
NGINX_SOURCE_DIR="$(mktemp -d)/nginx"
git clone --depth 1 --branch release-1.31.8 https://github.com/nginx/nginx "$NGINX_SOURCE_DIR"
NGINX_SRC_ENV="$NGINX_SOURCE_DIR" sh ./build.sh
make install
./build/nginx/sbin/nginx -V
```

`build.sh` configures and compiles nginx and mruby. It **does not install
the binary**; `make install` installs into the configured prefix. The
default prefix is `$PWD/build/nginx`, writable by the build user, so no
`sudo` is needed. The upstream git checkout avoids depending on the
nginx.org tarball download used when `NGINX_SRC_ENV` is absent.

Without that variable, the script selects `nginx_version` from the checkout.
The v2.7.2 tag still selects nginx 1.31.6, while the current maintenance
branch selects 1.31.8 and records the nginx update in the
[2.7.3 notes](../releases/v2.7.3.md#build-and-test-changes). A tag does not
update itself. Use the explicit 1.31.8 source above for this guide; inspect
`nginx -V` and the upstream changes when choosing another version.

`NGINX_SRC_ENV` selects an existing nginx source tree. Keep that tree until
the build and installation are finished. `NUM_THREADS_ENV=4` can bound
parallel compilation. For a different installation prefix, use an absolute
path; setting `NGINX_CONFIG_OPT_ENV` replaces the default nginx options,
so list every option you need:

```sh
NGINX_SRC_ENV="$NGINX_SOURCE_DIR" NGINX_CONFIG_OPT_ENV="--prefix=$PWD/build/custom-nginx --with-stream --with-http_stub_status_module --with-cc-opt=-fno-common" sh ./build.sh
make install
```

### 3-B. Using Makefile

With an existing nginx source tree, `configure` and `make` provide the same
control. `NGINX_SOURCE_DIR` below is an absolute directory containing nginx
source, not the installed nginx prefix:

```sh
./configure --with-ngx-src-root="$NGINX_SOURCE_DIR" --with-ngx-config-opt="--prefix=$PWD/build/nginx --with-stream --with-cc-opt=-fno-common"
make
make install
```

Run `./configure --help` for the current options, including
`--with-build-dir`, `--with-mruby-root`, `--with-ndk-root`,
`--with-openssl-src` and `--with-openssl-opt`.

### 3-C. Using nginx build system

For an existing nginx build, first build mruby and generate its linker
configuration. Then add both ngx_mruby and its bundled NDK to nginx's
configure command, preserving your other nginx options:

```sh
NGX_MRUBY_SOURCE_DIR="$PWD"
./configure --with-ngx-src-root="$NGINX_SOURCE_DIR"
make build_mruby
make generate_gems_config
cd "$NGINX_SOURCE_DIR"
# A git checkout uses auto/configure; a release tarball uses ./configure.
if [ -f auto/configure ]; then NGX_CONFIGURE=./auto/configure; else NGX_CONFIGURE=./configure; fi
"$NGX_CONFIGURE" --prefix="$NGX_MRUBY_SOURCE_DIR/build/nginx" --add-module="$NGX_MRUBY_SOURCE_DIR" --add-module="$NGX_MRUBY_SOURCE_DIR/dependence/ngx_devel_kit" --with-stream
make
make install
```

### Build options

#### Building with ngx_mruby stream module

The default `build.sh` options enable stream. When supplying your own nginx
options, include `--with-stream`. See the [stream directives](../directives/README.md)
and the [test instructions](../test/README.md) for TCP/UDP verification.

#### Building with non-system openssl

The ordinary build uses the system OpenSSL development package. If you
need a particular OpenSSL source tree, unpack that version yourself, record
its source/version, and pass its absolute directory:

```sh
NGINX_SRC_ENV="$NGINX_SOURCE_DIR" sh ./build.sh --with-openssl-src=/absolute/path/to/openssl-source
make install
```

Do not reuse the historical OpenSSL 1.0.2g download example as a current
installation recommendation. A custom OpenSSL build needs its own validation.

#### Building ngx_mruby as a dynamic module

Use a fresh checkout for a different build mode. This avoids reusing an
nginx configuration from a static build. In that shell, set
`NGINX_SOURCE_DIR` to a fresh checkout of `release-1.31.8` as in 3-A; do not
reuse the configured nginx source tree of a static build:

```sh
NGINX_SRC_ENV="$NGINX_SOURCE_DIR" BUILD_DYNAMIC_MODULE=TRUE sh ./build.sh
make install
./build_dynamic/nginx/sbin/nginx -V
```

The default dynamic prefix is `$PWD/build_dynamic/nginx`. In the **main**
context, before `events` and `http`, load the module from that installation:

```nginx
load_module /absolute/path/to/ngx_mruby/build_dynamic/nginx/modules/ngx_http_mruby_module.so;
```

Use the nginx binary built with this module, and check with `nginx -t`
before starting it. To adapt the trial below, set `NGX_BIN` to that binary
and add the absolute `load_module` line to its configuration. With a custom
nginx build, the corresponding steps are `--enable-dynamic-module` for
ngx_mruby's configure, `make generate_gems_config_dynamic`, and
`--add-dynamic-module` for nginx instead of `--add-module` for ngx_mruby;
the bundled NDK still uses `--add-module`.

## 4. Installing ngx_mruby

Run `make install` after compilation. It installs into the prefix selected
when nginx was configured, not necessarily `/usr/local/nginx`. The quick
start uses `build/nginx`. An existing production prefix may need elevated
permissions and a planned upgrade; the loopback trial below uses neither.

## 5. Writing ruby code

This complete trial uses a separate temporary runtime directory. It binds
only `127.0.0.1:18088`, logs only there and stops only its own nginx.
Choose another unused port consistently if 18088 is already in use.
Run the commands in one shell from the repository root, after `make install`.

```sh
(
set -eu
NGX_BIN="$PWD/build/nginx/sbin/nginx"
RUN_DIR="$(mktemp -d)"
mkdir -p "$RUN_DIR/logs"
printf 'Trial runtime: %s\n' "$RUN_DIR"
started=0
cleanup() {
    if [ "$started" = 1 ]; then "$NGX_BIN" -p "$RUN_DIR/" -c nginx.conf -s quit; fi
}
trap cleanup EXIT
cat > "$RUN_DIR/hello.rb" <<'RUBY'
Nginx::Headers_out.new["Content-Type"] = "text/plain"
Nginx.rputs "hello ngx_mruby\n"
RUBY
cat > "$RUN_DIR/nginx.conf" <<CONF
worker_processes 1;
pid logs/nginx.pid;
error_log logs/error.log notice;
events { worker_connections 64; }
http {
    access_log off;
    default_type text/plain;
    server {
        listen 127.0.0.1:18088;
        location = /inline {
            mruby_content_handler_code 'Nginx::Headers_out.new["Content-Type"] = "text/plain"; Nginx.rputs "hello ngx_mruby\\n"';
        }
        location = /script {
            mruby_content_handler "$RUN_DIR/hello.rb" cache;
        }
    }
}
CONF
"$NGX_BIN" -p "$RUN_DIR/" -c nginx.conf -t
"$NGX_BIN" -p "$RUN_DIR/" -c nginx.conf
started=1
curl --fail --show-error --silent --include http://127.0.0.1:18088/inline
curl --fail --show-error --silent --include http://127.0.0.1:18088/script
"$NGX_BIN" -p "$RUN_DIR/" -c nginx.conf -t && "$NGX_BIN" -p "$RUN_DIR/" -c nginx.conf -s reload
"$NGX_BIN" -p "$RUN_DIR/" -c nginx.conf -s quit
started=0
)
```

Both URLs must return status `200`, `Content-Type: text/plain`, and the
body `hello ngx_mruby` followed by a newline. `Date` and `Server` headers
vary with the environment. The example uses the content phase and no
request-persistent Ruby state. Reload keeps the master process and
replaces its workers; graceful quit uses this runtime's PID file.

### 5-A. Script file

`mruby_content_handler` takes a script path. The trial supplies an absolute
path so its meaning does not depend on nginx's working directory.

### 5-B. inline code

`mruby_content_handler_code` takes Ruby in the nginx configuration. Quote
for both nginx and the shell when using a shell heredoc, as in the trial.

### 5-C. Script file as a handler

`mruby_add_handler on` is another interface, described in the
[directive reference](../directives/README.md). The trial uses explicit
locations so it does not enable execution of every matching `.rb` file.
For script handlers, `cache` caches compiled code; without it the script
is read/compiled per request unless `mruby_cache on` applies. See that
reference before choosing caching behavior for deployment.

## 6. Running ngxinx

Use the installed binary and the same `-p` and `-c` for validation, start,
reload and quit, as above. Do not substitute a different system `nginx`
command, which may not contain ngx_mruby.

## 7. Trying it out

If the trial fails, check these before changing configuration:

| Symptom | Check |
|---|---|
| Binary missing | `build.sh` compiles; run `make install`, then inspect the configured prefix. |
| `unknown directive` | Use the built nginx; for a dynamic build, check the main-context `load_module` path and matching binary. |
| Build cannot find a header or library | Install the development packages, not only the runtime command; read the first compiler/configure error. |
| nginx source download fails | Use the exact matching nginx git tag with `NGINX_SRC_ENV` as above. |
| `bind()` fails | Another process owns the port; choose a free loopback port. Do not stop a process you do not own. |
| Script cannot be opened or a Ruby exception occurs | Read `$RUN_DIR/logs/error.log`; check the absolute file path, permissions and Ruby code. |
| curl does not return the expected body | Check `nginx -t`, the exact URL/port and the error log; a connection success alone is not verification. |

Validation of this walkthrough on 2026-10-29: ngx_mruby `v2.7.2`, nginx
1.31.8 (the upstream `release-1.31.8` git tag, selected through
`NGINX_SRC_ENV`), Ubuntu 22.04 aarch64, GCC 11.4.0 and Ruby 3.0.2/rake
13.0.6. The static build with four compiler jobs plus `make install`, both HTTP responses
(status, explicit content type and 16-byte body), configuration validation,
reload and quit passed. The script was extracted from section 5, not
rewritten for the test. The custom-prefix, direct-nginx, dynamic and custom
OpenSSL alternatives above are configuration guidance, not additional
executed results from that run.

For the full module integration suite, sanitizers and supported test nginx
versions, see [Testing](../test/README.md). This walkthrough verifies a
small HTTP example; it does not certify custom modules, TLS, stream,
performance or a production rollout.

## Playing with an example Docker image

The separate [docker-ngx_mruby repository](https://github.com/matsumotory/docker-ngx_mruby)
is a historical example, not the version-pinned installation verified here.
Its image, configuration and dependencies need independent review before
use. The source walkthrough above requires no registry account.

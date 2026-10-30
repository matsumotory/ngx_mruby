# Installing ngx_mruby 3.x development

This guide builds a standalone nginx with ngx_mruby, then serves an inline
Ruby handler and a cached script on loopback without root privileges.
It uses the `next` development branch with nginx 1.31.8. This is not a
stable release. For a released 2.x build, use the
[maintenance installation guide](https://ngx.mruby.org/v2/guides/install/).
Record the source revision and build configuration before comparing results.
To try the development source in Docker first, see
[the start example](../../examples/start/README.md).
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
git clone --branch next https://github.com/matsumotory/ngx_mruby.git
cd ngx_mruby
git rev-parse HEAD
```

`next` moves as development PRs merge; `git rev-parse HEAD` records the
checkout used. To reproduce a recorded build, check out that exact commit
before building. The repository includes its mruby source and the
third-party gem lock described below; the lock does not pin every external
fetch and does not promise byte-for-byte reproducibility.

## 2. Configuring mrbgems

`build_config.rb` lists the mrbgems that the build puts into mruby: the
mruby core gems of `NGX_MRUBY_CORE_GEMS` ([Core gems](#core-gems)) and
third-party gems. [Default mrbgems](../reference/build.md#default-mrbgems)
in the build reference lists the third-party gems of the default build,
with the classes that each one adds. To add a gem, add a `conf.gem` line
to the host build of `build_config.rb`; the
[list of mrbgems](https://github.com/mruby/mruby/wiki/Related-Projects)
of mruby names more. The lines that are comments in `build_config.rb` name
gems that the default build leaves out, such as mruby-discount and
mruby-memcached: uncomment one to build with it.

The mruby build stops when a gem that `NGX_MRUBY_CORE_GEMS` lists is not in
the `mrbgems` directory of the mruby it builds, for example an mruby of
another version given with `./configure --with-mruby-root`. Edit the list, or
set `NGX_MRUBY_ALLOW_MISSING_CORE_GEMS=1` in the environment of the mruby
build to skip those gems with a notice.

The default build already includes mruby-io. File, socket, sleep and Redis
operations in a handler can block its worker; inclusion does not make them
nginx event-driven operations. See the [API reference](../class_and_method/README.md).

ngx_mruby 3.0.0 has no auto-ssl mrbgem; see
[The auto-ssl mrbgem and the classes that came with it](#the-auto-ssl-mrbgem-and-the-classes-that-came-with-it).

### Core gems

The bundled mruby is 4.0.0. ngx_mruby builds the core gems that
`NGX_MRUBY_CORE_GEMS` names, not mruby's `full-core.gembox`, so that the
classes and methods of ngx_mruby scripts change only when that list
changes. The list is the set that `full-core.gembox` of mruby 3.3.0
selected, with these differences:

- mruby-print is gone (mruby 3.4 removed it). `Kernel#print`, `#puts` and
  `#p` come from mruby-io.
- hal-posix-io, hal-posix-dir and hal-posix-socket are in the list. In
  mruby 4.0.0, mruby-io, mruby-dir and mruby-socket reach the operating
  system through one of these back ends; they add no class or method. Only
  4.0.0 has them: in mruby 4.1.0-rc2 the POSIX back ends are part of
  mruby-io, mruby-dir and mruby-socket, and there are no hal-* gems, so an
  update to mruby 4.1 removes the three names from the list.

Core gems of mruby 4.0.0 that the list leaves out, although
`full-core.gembox` of 4.0.0 takes them:

| Gem | What it would change | Why it is left out |
|---|---|---|
| mruby-task (with hal-posix-task) | `Task`; redefines `Kernel#sleep`; every process that opens an mrb_state gets a SIGALRM interval timer (`setitimer`); at most 8 mrb_states (`MRB_TASK_MAX_VMS`) | the timer and the `sleep` of nginx workers; ngx_mruby has its own `Nginx::Async` |
| mruby-encoding | defines `MRB_UTF8_STRING` for the whole build: `String#size`, `#[]`, `#index` and others count characters instead of bytes; adds `String#valid_encoding?`, `#encoding` and `#force_encoding` | request and response data are bytes, and a script that computes a `Content-Length` from `String#size` would get another number; the owner decided on 2026-10-04 to leave it out of the default build and keep it opt-in. Cost of leaving it out: `String#valid_encoding?`, which mruby 3.3 defined in mruby-string-ext, raises `NoMethodError` (since mruby 3.4 only mruby-encoding defines it) |
| mruby-strftime | adds `Time#strftime` | new API; a decision of its own |
| mruby-benchmark | adds `Benchmark` | new API, a development tool |

`full-core.gembox` of 4.0.0 leaves out mruby-sleep, mruby-bin-debugger and
mruby-test. ngx_mruby keeps mruby-sleep, which defines `Kernel#sleep` and
`#usleep`.

To build with one of the gems that the list leaves out, add its name to
`NGX_MRUBY_CORE_GEMS` in `build_config.rb`, remove `mruby/build` and build
again. With mruby-encoding, check every script that uses `String#size`,
`#length`, `#[]`, `#slice`, `#index` or `#reverse` on request or response
data, and use `#bytesize` and `#byteslice` where bytes are meant;
`Nginx::Utils.escape` already works on bytes. The test suite of ngx_mruby
does not run with mruby-encoding or mruby-task.

A script that calls `String#valid_encoding?` needs mruby-encoding (with the
checks above), or has to drop the call. With the default `build_config.rb`
of ngx_mruby 2.x, which builds mruby 3.3.0 without `MRB_UTF8_STRING`, the
method returned `true` for every string, even `"\xfe"`, so dropping the call
does not change what such a script accepts. A 2.x build whose
`build_config.rb` defines `MRB_UTF8_STRING` got `false` for a string that is
not valid UTF-8; to keep that check, build with mruby-encoding, which
defines both `MRB_UTF8_STRING` and the method.

### Gem commits: build_config.rb.lock

`build_config.rb` names the third-party mrbgems, and `build_config.rb.lock`,
committed next to it, records the commit of each of them, so that a checkout
of the same ngx_mruby commit builds the same gems on every machine and at any
later time. mruby's rake writes the file at the end of every build and reads
it at the start of the next one.

The lock has a section for each mruby build of `build_config.rb`: `host`, the
mruby that ngx_mruby links, and `test`, the `mruby` binary that runs the
tests of `test.sh`. In each section, an entry is keyed by the URL of a gem's
repository and records the branch, the commit and the version of the gem.
The entries cover the gems that `build_config.rb` declares with `github:` and
the gems that those depend on, which rake clones as well (for example
ksss/mruby-stringio, which the bundled rack-based-api needs, in `host`). The
gems of mruby itself (`mruby/mrbgems/`) and the bundled ones under
`mrbgems/` are part of the source tree and have no entry. The `mruby` section
records the version of the bundled mruby.

For a gem that has an entry, rake clones the repository with its whole
history (without `--depth 1`, which it uses for a gem without an entry) into
`mruby/build/repos/host/` or `mruby/build/repos/test/`, and checks the
recorded commit out (a detached HEAD). At the end of the build it writes the
lock again from the clones it used. On the default gem list the content does
not change, so a build leaves `git status` clean.

rake clones a gem only when its directory under `mruby/build/repos/` does not
exist. A clone that exists is checked out at the commit of the lock without a
fetch, so that commit must already be in the clone. After a change of the
lock, remove `mruby/build` before you build. A clone left by a build without
the lock (from before the lock was committed) has only the commit that was
at the head of its branch at that time.

To move a gem to another commit:

1. In `build_config.rb.lock`, change the `commit:` of the gem's entry, in
   each section that has one, or delete the entry to take the current head
   of its branch.
2. Remove the clones: `rm -rf mruby/build`. It leaves
   `build_config.rb.lock` in place. `make clean_mruby` does not work here:
   it runs rake before it removes anything, and rake checks each existing
   clone out at the commit of the lock when it loads `build_config.rb`, so
   it stops with `fatal: reference is not a tree` when a clone does not
   have that commit.
3. Build (`sh test.sh` or `sh build.sh`).
4. Commit the `build_config.rb.lock` that rake wrote.

When you add a gem to `build_config.rb`, the next build clones the head of
its branch and adds its entry, and those of the gems it depends on, to the
lock; commit the lock with the change. When you remove a gem, rake keeps its
entry (it writes back every entry that it read), so delete the entry from the
lock yourself. After an update of the bundled mruby, remove `mruby/build`,
build, and commit the lock with the update: rake records the new version, and
a dependency that the new mruby provides as one of its own gems is no longer
cloned, so delete its entry.

The lock does not pin everything that the build fetches:

- mruby/mgem-list. mruby clones the head of this list of gems to find the
  repository of a gem declared with `mgem:`, or of a dependency declared
  without a source that is not one of mruby's own gems. The default gem list
  does not need it. Until the update to mruby 4.0.0, the `test` build did:
  matsumotory/mruby-simplehttp depends on mruby-polarssl without a source
  unless `NO_SSL` is set, and the list gave the repository
  luisbebop/mruby-polarssl. That gem depends on mruby-print, which mruby 3.4
  removed, so `build_config.rb` now sets `NO_SSL` for the `test` build, and
  the test client has `SimpleHttp` without HTTPS (the suite sends its HTTPS
  requests with curl and `openssl s_client`). If a gem that you add needs
  the list, the lock pins the commit of the gem but the list supplies its
  URL; if the list ever gives another URL, the lock has no entry for it, and
  rake clones the head of that repository. `build_config.rb` therefore
  declares its gems with `github:`.
- symisc/vedis. The `mrbgem.rake` of matsumotory/mruby-vedis clones it with
  `git clone` into the build directory of the gem
  (`mruby/build/host/mrbgems/mruby-vedis/vedis`) when that directory does not
  exist, at the head of its default branch.

Because a clone made at a commit has the whole history of the repository,
the first build fetches more than a build without the lock. The default
build makes 19 clones: 12 in `mruby/build/repos/host` and 7 in
`mruby/build/repos/test`. Measured on 2026-10-04 after a build from an
empty `mruby/build`, they take about 9.3 MiB (7.7 MiB and 1.7 MiB). Before
the update to mruby 4.0.0, the `test` build also cloned
luisbebop/mruby-polarssl with its submodule ARMmbed/mbedtls, which made up
most of the about 178 MiB that the clones of the default build took then.

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
This development snapshot selects 1.31.8. Use the explicit source above for
this walkthrough; inspect `nginx -V` and upstream changes when choosing
another version.

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

If you pass `--with-mruby-incdir`, its list of directories must include the `build/host/include` directory of the mruby build (the default list is `<mruby_root>/src <mruby_root>/include <mruby_root>/build/host/include`), because ngx_mruby includes `<mruby/presym.h>`, which includes the headers that the mruby build generates there.

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

#### The auto-ssl mrbgem and the classes that came with it

ngx_mruby 3.0.0 does not have the auto-ssl mrbgem (`mrbgems/auto-ssl`, the
`Nginx::SSL::ACME` classes), and the mruby build no longer reads
`NGX_MRUBY_AUTO_SSL` ([The auto-ssl mrbgem and `NGX_MRUBY_AUTO_SSL` are removed](../releases/v3.0.0.md#the-auto-ssl-mrbgem-and-ngx_mruby_auto_ssl-are-removed-640)).
Its `Nginx::SSL::ACME::Client` speaks ACMEv1 (`new-reg`, `new-authz`,
`new-cert`), which Let's Encrypt no longer serves, and the gem that it needs
for TLS, pyama86/mruby-polarssl, has had no commit since 2017-03-03 and does
not build with mruby 4: it includes `mruby/ext/io.h`, which mruby 4.0 renamed
to `mruby/io.h`. To get certificates from an ACME server, use nginx's own
module [ngx_http_acme_module](https://nginx.org/en/docs/http/ngx_http_acme_module.html) (nginx-acme). A server that needs
`Nginx::SSL::ACME` keeps a 2.x build; the
[documentation of 2.x](https://github.com/matsumotory/ngx_mruby/blob/v2.7.2/docs/class_and_method/README.md#auto-ssl-mrbgem) describes the gem.

ngx_mruby 2.x also built the gems that auto-ssl depends on:
pyama86/mruby-acme-client, pyama86/mruby-polarssl, which is licensed under
the GPL, matsumotory/mruby-httprequest, matsumotory/mruby-simplehttp,
mattn/mruby-http, mattn/mruby-base64, takahashim/mruby-forwardable and
iij/mruby-tempfile. No other gem of the default build needs them, so a
default build of 3.0.0 does not have what they define either:

- the classes and modules `Acme`, `CustomHttpRequest`, `OpenSSL`,
  `PolarSSL`, `HttpRequest`, `SimpleHttp`, `HTTP`, `Base64`, `Forwardable`,
  `FORWARDABLE`, `Tempfile` and `TempfilePath`;
- `Dir.tmpdir` and `Dir.mktmpdir` (and their helper `Dir._tmpname`), which
  iij/mruby-tempfile adds to `Dir`. The `Dir` class itself stays in the
  default build.

In place of `Dir.tmpdir`, use `ENV['TMPDIR'] || '/tmp'` (the `Dir.tmpdir` of
mruby-tempfile also read `TMP`, `TEMP` and `USERPROFILE` before it fell back
to `/tmp`). In place of `Dir.mktmpdir`, create the directory with
`Dir.mkdir(path, 0700)` under a name that no other process uses;
`Dir.mkdir` raises `Errno::EEXIST` when the name is taken. Where
`Dir.mktmpdir` with a block removed the directory and everything under it
when the block returned, remove them yourself: list each directory with
`Dir.entries`, tell files from directories with `File.directory?` (both
are in the default build), delete the files with `File.delete` and the
directories with `Dir.rmdir`, deepest first. `Dir.rmdir` on a directory
that still has entries raises `Errno::ENOTEMPTY`. In place of `Base64`, the
core `pack('m0')` and `unpack1('m')` work in the default build.

```ruby
tmpdir = ENV['TMPDIR'] || '/tmp'                              # Dir.tmpdir
path = "#{tmpdir}/myapp-#{Process.pid}-#{SecureRandom.hex(8)}"
Dir.mkdir(path, 0700)                                         # Dir.mktmpdir('myapp-')
```

For the other constants, add the gem that defines them with a `conf.gem` line
in a `build_config.rb` of your own. The gems that depend on
pyama86/mruby-polarssl do not build with mruby 4.

## 4. Installing ngx_mruby

Run `make install` after compilation. It installs into the prefix selected
when nginx was configured, not necessarily `/usr/local/nginx`. The quick
start uses `build/nginx`. An existing production prefix may need elevated
permissions and a planned upgrade; the loopback trial below uses neither.

## 5. Running a Ruby script

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

## 6. Running nginx

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

Validated on 2026-10-29 with ngx_mruby development commit
`6d65a12ecf166e11a6ece40d56f0f2efb05ea112` and nginx 1.31.8
(`release-1.31.8`, selected with `NGINX_SRC_ENV`), in Ubuntu 22.04 aarch64,
GCC 11.4.0 and Ruby 3.0.2/rake 13.0.6. The static build with four compiler
jobs and `make install` passed. Section 5 was extracted and executed
unchanged: both responses returned 200, text/plain and the 16-byte body;
configuration validation, reload and quit passed. The gem lock stayed
unchanged. These are results for that source revision, not every future
`next` commit. Custom-prefix, direct-nginx, dynamic and custom OpenSSL
alternatives above are configuration guidance, not additional executed
results from this run.

For the full module integration suite, sanitizers and supported test nginx
versions, see [Testing](../test/README.md). This walkthrough verifies a
small HTTP example; it does not certify custom modules, TLS, stream,
performance or a production rollout.

## Playing with an example Docker image

The separate [docker-ngx_mruby repository](https://github.com/matsumotory/docker-ngx_mruby)
is a historical example, not the version-pinned installation verified here.
Its image, configuration and dependencies need independent review before
use. The source walkthrough above requires no registry account.

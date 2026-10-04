# Playing with an example Docker image

If you just want to play with ngx_mruby, you can use an example Docker image.

## Prerequisites

* git
* Docker
* Docker Hub account
* curl

## 1. Downloading examples configuration from github.com

```sh
$ git clone https://github.com/matsumotory/docker-ngx_mruby.git
```

## 2. Building a Docker image

```sh
$ cd /path/to/docker-ngx_mruby
$ docker login
$ docker build  -t local/docker-ngx_mruby .
```

## 3. Running ngx_mruby with Docker

```sh
$ docker run -p 80:80 local/docker-ngx_mruby
```

## 4. Trying it out

```sh
$ curl http://127.0.0.1/mruby-hello
server ip: 172.17.0.192: hello ngx_mruby world.
```

Welcome mruby world for nginx!

# Installing from source

You can build and install you own ngx_mruby binary from source.

## Prerequisites

* git
* GNU make
* ruby
* rake
* bison
* openssl
* C compiler (GCC or Clang)
* curl

## 1. Downloading source from github.com

```sh
$ git clone https://github.com/matsumotory/ngx_mruby.git
```

If you want to build a specific version of ngx_mruby, please check out the version.

```sh
$ cd /path/to/ngx_mruby
$ git checkout v2.1.2
```

Also you can download tarballs from https://github.com/matsumotory/ngx_mruby/archive/master.zip 
or https://github.com/matsumotory/ngx_mruby/releases .

## 2. Configuring mrbgems

ngx_mruby's default mrbgem configuration contains basic features. But if you want to have __more features__, 
you will find additional mrbgems at [the list of mrbgems](https://github.com/mruby/mruby/wiki/Related-Projects) 
and add them to [build_config.rb](https://github.com/matsumotory/ngx_mruby/blob/master/build_config.rb).

For example, you can use mruby-io to implement 
[access check using a configuration file like .htaccess](https://gist.github.com/matsumotory/7150832).
(FIXME: This is not an appropriate example. mruby-io is a default mrbgem.)

Here are the list of the default mrbgems.

- mruby core gems: the ones that `NGX_MRUBY_CORE_GEMS` in `build_config.rb` lists (the set that `full-core.gembox` of mruby 3.3.0 selects), for example mruby-io, mruby-pack, mruby-sleep and mruby-dir
- mruby-process: Process ::fork, ::kill, ::pid, ::ppid, ::waitpid...
- mruby-pack: pack, unpack...
- mruby-env: use environment value
- mruby-dir: Dir class
- mruby-digest: MD5, RMD160, SHA1, SHA256, SHA384, SHA512 and HMAC Digests
- mruby-json: JSON::parse, JSON::stringify
- mruby-redis: Redis#set, get, [], []=...
- mruby-vedis: Vedis#set, get, [], []=...
- mruby-memcached: Memcached#set, get, [], []=...
- mruby-sleep: sleep, usleep...
- mruby-userdata: https://github.com/matsumotory/mruby-userdata
- mruby-onig-regexp: regexp engine
- mruby-io: https://github.com/iij/mruby-io

The mruby build stops when a gem that `NGX_MRUBY_CORE_GEMS` lists is not in
the `mrbgems` directory of the mruby it builds, for example an mruby of
another version given with `./configure --with-mruby-root`. Edit the list, or
set `NGX_MRUBY_ALLOW_MISSING_CORE_GEMS=1` in the environment of the mruby
build to skip those gems with a notice.

The bundled auto-ssl mrbgem is not in the default build; see
[Building with the auto-ssl mrbgem](#building-with-the-auto-ssl-mrbgem).

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
  without a source that is not one of mruby's own gems. Of the default gem
  list, only the `test` build needs it: matsumotory/mruby-simplehttp depends
  on mruby-polarssl without a source, and the list gives the repository
  https://github.com/luisbebop/mruby-polarssl.git. The lock pins the commit
  of that gem; the list supplies only its URL. If the list ever gives another
  URL, the lock has no entry for it, and rake clones the head of that
  repository. `build_config.rb` therefore declares its gems with `github:`.
- symisc/vedis. The `mrbgem.rake` of matsumotory/mruby-vedis clones it with
  `git clone` into the build directory of the gem
  (`mruby/build/host/mrbgems/mruby-vedis/vedis`) when that directory does not
  exist, at the head of its default branch.
- The submodule of luisbebop/mruby-polarssl (ARMmbed/mbedtls, `test` build).
  rake clones with `--recursive`, which checks the submodule out at the
  commit that the head of the branch records, and the checkout of the
  pinned commit does not update submodules. The pin is the head of the
  branch today, so the two are the same commit. If the pin moves to a commit
  that records another submodule commit, the submodule stays at the one of
  the branch head.

Because a clone made at a commit has the whole history of the repository,
the first build fetches more than a build without the lock. Measured on
2026-10-04 (two runs each), the 21 clones that the default build made at that
time, cloned the way rake clones them, took about 178 MiB in 40 to 43 seconds
instead of about 139 MiB in 32 to 34 seconds with `--depth 1`. The default
build now makes 20: `Dir` comes from mruby's own mruby-dir instead of
iij/mruby-dir, which is no longer cloned. Most of the size
either way is the mbedtls submodule of luisbebop/mruby-polarssl, and so is
most of the difference. `--recursive` does not make submodules shallow, so
both clones have the whole history of the default branch of mbedtls. With
`--depth 1`, git also clones the submodule with `--single-branch`, which
fetches only that branch (about 119 MiB with git 2.34); without
`--depth 1`, git fetches every branch of mbedtls (183 of them on
2026-10-04, about 152 MiB). The other branches account for about 34 MiB of
the 39 MiB difference; the history of mruby-polarssl itself is 1.4 MiB.

## 3. Building a binary

There are 3 options to build a ngx_mruby binary

* Using build.sh
* Using Makefile
* Using nginx build system

### 3-A. Using build.sh

Using build.sh is the easiest way to build the binary.
It automatically downloads nginx source to /path/to/ngx_mruby/build directory and builds ngx_mruby, 
then installs it into /path/to/ngx_mruby/build/nginx.

```
$ cd /path/to/ngx_mruby
$ sh ./build.sh
```

You can install it into a different directory as below. It builds and installs ngx_mruby into
/usr/local/nginx-1.15.6 instead of /path/to/ngx_mruby/build/nginx.

```sh
$ env NGINX_CONFIG_OPT_ENV='--prefix=/usr/local/nginx-1.15.6' sh ./build.sh
```

If you already have nginx source, you can specify the source directory. It doesn't download nginx source.

```
$ env NGINX_SRC_ENV='/usr/local/src/nginx-1.15.6' sh ./build.sh
```

### 3-B. Using Makefile

If you want to use more complex build configuration, you will use configure script and Makefile.
You need to download [nginx](http://nginx.org/en/download.html), then unpack it before running the script.

```sh
$ cd /path/to/ngx_mruby
$ ./configure --with-ngx-src-root=/local/src/nginx-1.15.6 --with-ngx-config-opt=--prefix=/usr/local/nginx-1.15.6
$ make
```

'configre --help' gives you all configuration options.

```sh
$ ./configure --help
`configure' configures this package to adapt to many kinds of systems.

Usage: ./configure [OPTION]... [VAR=VALUE]...

[snip]

  --with-ngx-src-root=DIR pathname to ngx_src_root [[ngx_src_root]]
  --with-openssl-src=DIR  set path to OpenSSL library sources
  --with-build-dir=DIR    set build directory path
  --with-openssl-opt=OPTIONS
                          set additional build options for OpenSSL
  --with-ngx-config-opt=OPT
                          nginx configure option [[ngx_config_opt]]
  --with-mruby-root=DIR   pathname to mruby_root [[mruby_root]]
  --with-mruby-incdir=DIR include directory for mruby [[mruby_incdir]]
  --with-mruby-libdir=DIR library directory to libmruby [[mruby_libdir]]
  --with-ndk-root=DIR     pathname to ndk_root [[ndk_root]]

[snip]
```

If you pass `--with-mruby-incdir`, its list of directories must include the `build/host/include` directory of the mruby build (the default list is `<mruby_root>/src <mruby_root>/include <mruby_root>/build/host/include`), because ngx_mruby includes `<mruby/presym.h>`, which includes the headers that the mruby build generates there.

### 3-C. Using nginx build system

ngx_mruby is a nginx module, so you can simply use nginx build system with --add-module option.

```sh
$ cd /path/to/ngx_mruby
$ ./configure --with-ngx-src-root=/local/src/nginx-1.15.6 --with-ngx-config-opt=--prefix=/usr/local/nginx-1.15.6
$ make build_mruby
$ make generate_gems_config
$ cd /local/src/nginx-1.15.6 
$ ./configure --prefix=/usr/local/nginx-1.15.6 --add-module=/path/to/ngx_mruby --add-module=/path/to/ngx_mruby/dependence/ngx_devel_kit --add-module=/path/to/nginx-module-you-want-to-build
$ make
```

### Build options

This section explains some build options.

#### Building with ngx_mruby stream module

If you want to use ngx_mruby stream module, you need to pass option(s) to nginx's confgiure script.

| nginx version    | option(s) |
|------------------|-----------|
| 1.11.5 or later  | --with-stream |
| 1.9.6 - 1.11.4   | --with-stream --without-stream_access_module |
| 1.9.5 or earlier | Not supported |

Here is an example for build.sh.

```sh
$ env NGINX_CONFIG_OPT_ENV='--prefix=/usr/local/nginx-1.15.6 --with-stream' sh ./build.sh
```

#### Building with non-system openssl

If you want to build ngx_mruby with non-system openssl, you can use --with-openssl-src option.

```sh
$ curl ftp://ftp.openssl.org/source/openssl-1.0.2g.tar.gz | tar -zx
$ cd /path/to/ngx_mruby
$ sh ./build.sh --with-openssl-src=/path/to/openssl-1.0.2g
```

Of course, configure script supports the option.

```sh
$ curl ftp://ftp.openssl.org/source/openssl-1.0.2g.tar.gz | tar -zx
$ cd /path/to/ngx_mruby
$ ./configure --with-ngx-src-root=/local/src/nginx-1.15.6 --with-ngx-config-opt=--prefix=/usr/local/nginx-1.15.6 --with-openssl-src=/path/to/openssl-1.0.2g
$ make
```

#### Building ngx_mruby as a dynamic module

nginx 1.9.11 or later supports dynamic module. You can build ngx_mruby as a dynamic module with build.sh.
It uses 'build_dynamic' directory instead of 'build'. You will find in /path/to/ngx_mruby/build_dynamic.

```sh
$ env BUILD_DYNAMIC_MODULE=TRUE sh ./build.sh
```

You need to add [load_module](http://nginx.org/en/docs/ngx_core_module.html#load_module) directive to nginx.conf as below.

```
load_module /path/to/modules/ngx_http_mruby_module.so;
```

If you don't use build.sh, you need to 

* Pass --enable-dynamic-module to ngx_mruby's configure script
* Generate mrbgems_config_dynamic instead of mrbgems_config
* Use --add-dynamic-module=PATH instead of --add-module=PATH for nginx's configure option.

Here is an example.

```sh
$ cd /path/to/ngx_mruby
$ ./configure --enable-dynamic-module --with-ngx-src-root=/local/src/nginx-1.15.6 --with-ngx-config-opt=--prefix=/usr/local/nginx-1.15.6
$ make build_mruby
$ make generate_gems_config_dynamic
$ cd /local/src/nginx-1.15.6 
$ ./configure --prefix=/usr/local/nginx-1.15.6 --add-dynamic-module=/path/to/ngx_mruby --add-module=/path/to/ngx_mruby/dependence/ngx_devel_kit --add-module=/path/to/nginx-module-you-want-to-build
$ make
```

#### Building with the auto-ssl mrbgem

The auto-ssl mrbgem (`mrbgems/auto-ssl`, the `Nginx::SSL::ACME` classes) is
not in the default build. Its `Nginx::SSL::ACME::Client` speaks ACMEv1
(`new-reg`, `new-authz`, `new-cert`), which Let's Encrypt no longer serves.
The gem also brings in pyama86/mruby-acme-client and pyama86/mruby-polarssl,
which is licensed under the GPL, together with matsumotory/mruby-httprequest,
matsumotory/mruby-simplehttp, mattn/mruby-http, mattn/mruby-base64,
takahashim/mruby-forwardable and iij/mruby-tempfile. No other gem of the
default build needs them, so a default build does not have what they define
either:

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

To build the gem, set `NGX_MRUBY_AUTO_SSL=1` in the environment of the mruby
build. build.sh and test.sh pass their environment on to it.

```sh
$ env NGX_MRUBY_AUTO_SSL=1 sh ./build.sh
```

With the Makefile (3-B) or the nginx build system (3-C), set it for `make` or
`make build_mruby`.

```sh
$ env NGX_MRUBY_AUTO_SSL=1 make build_mruby
```

Any other value, or none, builds without the gem. The variable is read when
mruby is built. Before you change it in a tree that was built already, remove
`mruby/build`: mruby builds and initializes the gems of the new list, but
`mruby/build/host/lib/libmruby.a` keeps the objects of a dropped gem and
`mruby/build/host/LEGAL` is not written again.

CI builds and tests only the default gem list: no CI job sets
`NGX_MRUBY_AUTO_SSL`. The eight third-party gems above have no entry in the
`host` section of the committed `build_config.rb.lock` (see
[Gem commits](#gem-commits-build_configrblock)), because the default build
does not use them. The lock has its entries per build: the entries of
matsumotory/mruby-httprequest, matsumotory/mruby-simplehttp and
mattn/mruby-http in its `test` section pin only the copies that the `test`
build clones. For the `host` build, rake clones the current head of the
eight gems' branches and adds their entries to the `host` section of the
lock in your tree, where they keep later builds of the same tree at those
commits. Do not commit these entries with other changes;
`git checkout build_config.rb.lock` restores the committed file. A build with
the variable can therefore fail after a change in one of these gems or in
mruby while the default build passes.

## 4. Installing ngx_mruby

```sh
$ cd /path/to/ngx_mruby
$ sudo make install
```

## 5. Writing ruby code

There are 3 ways to run you mruby code on ngx_mruby.

* script file
* inline code
* script file as a handler

### 5-A. Script file

You can run a script file as below.

```nginx
location /mruby {
    mruby_content_handler '/usr/local/nginx/html/unified_hello.rb';
}
```

Here is an example script /usr/local/nginx/html/unified_hello.rb.

```ruby
if server_name == "NGINX"
  Server = Nginx
elsif server_name == "Apache"
  Server = Apache
end

Server::rputs "Hello #{Server::module_name}/#{Server::module_version} world!"
```

You can use 'cache' arg to cache compiled mruby code.
By default, ruby code is compiled when every time received a request.

```nginx
location /mruby {
    mruby_content_handler '/usr/local/nginx/html/unified_hello.rb' cache;
}
```

### 5-B. inline code

Also you can write ruby code in nginx.conf.

```nginx
location /mruby {
    mruby_content_handler_code '
      
      if server_name == "NGINX"
        Server = Nginx
      elsif server_name == "Apache"
        Server = Apache
      end
      
      Server::rputs "Hello #{Server::module_name}/#{Server::module_version} world!"
    
    ';
}
```

### 5-C. Script file as a handler

You can run a ruby script file directly without location definition. 
In this case, the script is exposed at http://127.0.0.1/unified_hello.rb instead of http://127.0.0.1/mruby.

```nginx
location ~ \.rb$ {
    mruby_add_handler on;
}
```

## 6. Running ngxinx

```sh
$ /usr/local/nginx/sbin/nginx
```

## 7. Trying it out

```
$ curl http://127.0.0.1/mruby
Hello ngx_mruby/0.0.1 world!
```

Welcome mruby world for nginx!


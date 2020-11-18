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

- gembox: mruby/mruby default mrbgems, mruby-randoma, mruby-env, mruby-print...
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


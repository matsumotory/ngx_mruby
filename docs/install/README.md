## Quick install using Docker
### Use docker images example
Please see [example repository](https://github.com/matsumotory/docker-ngx_mruby).
#### 1. Create Dockerfile
```
FROM matsumotory/ngx-mruby:latest
MAINTAINER matsumotory
```
#### 2. Create docker directory
which was included hook files and nginx.conf in same directory as Dockerfile. like [this](https://github.com/matsumoto-r/ngx_mruby/tree/master/docker)
```
$ ls -lR Dockerfile 
-rw-rw-r-- 1 matsumotory matsumotory 1652 Feb 13 23:03 Dockerfile
$ ls -lR docker/
docker/:
total 8
drwxrwxr-x 2 matsumotory matsumotory 4096 Jan 25 17:46 conf
drwxrwxr-x 2 matsumotory matsumotory 4096 Jan 25 17:46 hook

docker/conf:
total 4
-rw-rw-r-- 1 matsumotory matsumotory 1428 Jan 25 17:46 nginx.conf

docker/hook:
total 8
-rw-rw-r-- 1 matsumotory matsumotory 593 Jan 25 17:46 proxy.rb
-rw-rw-r-- 1 matsumotory matsumotory  40 Jan 25 17:46 test.rb
```

#### 3. Run
```
$ docker build  -t local/docker-ngx_mruby .
$ docker run -p 80:80 local/docker-ngx_mruby
$ curl http://127.0.0.1/mruby-hello
server ip: 172.17.0.192: hello ngx_mruby world.
```

## Install
### 1. Download

```bash
$ git clone git://github.com/matsumoto-r/ngx_mruby.git
$ cd ngx_mruby
```

- if you want __more features__, you can get [mrbgems](https://github.com/mruby/mruby/wiki/Related-Projects) and write to [build_config.rb](https://github.com/matsumoto-r/ngx_mruby/blob/master/build_config.rb)
- for example, use mruby-io and implement [file base access check like .htaccess](https://gist.github.com/matsumoto-r/7150832).
- default mrbgems
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
  - mruby-userdata: https://github.com/matsumoto-r/mruby-userdata
  - mruby-onig-regexp: regexp engine
  - mruby-io: https://github.com/iij/mruby-io
- Notice: If you want to build the ngx_mruby as dynamic module, you should set `-fPIC` flag to build_config. See [build_config_dynamic.rb](https://github.com/matsumoto-r/ngx_mruby/blob/master/build_config_dynamic.rb)
- __We should implement ngx_mruby/mod_mruby extensions as mrbgems, as possible.__
- __We recommend the contribute to mruby by implementing mrbgems.__

### 2. Build 
##### Using build.sh
```bash
# Default install
#  download nginx into ./build/
#  build with ngx_mruby into ./build/nginx

sh build.sh
```
```bash
# install with ENV

NGINX_CONFIG_OPT_ENV='--prefix=/usr/local/nginx-1.4.4' NGINX_SRC_ENV='/usr/local/src/nginx-1.4.4' sh build.sh
```
##### or Download [Nginx](http://nginx.org/en/download.html), unpack, use configure for ngx_mruby, mruby build, ngx_mruby build.
```bash
$ cd ${NGX_MRUBY_SRC}
$ ./configure --with-ngx-src-root=${NGINX_SRC} --with-ngx-config-opt="--prefix=/usr/local/nginx"
$ make build_mruby
$ make
```
##### or configure with ```--add-module=${NGX_MRUBY_SRC}``` for nginx and make it
```bash
$ cd ${NGX_MRUBY_SRC}
$ ./configure --with-ngx-src-root=${NGINX_SRC}
$ make build_mruby
$ make generate_gems_config
$ cd ${NGINX_SRC}
$ ./configure --prefix=/usr/local/nginx --add-module=${NGX_MRUBY_SRC} --add-module=${NGX_MRUBY_SRC}/dependence/ngx_devel_kit --add-module=${SOME_OTHER_MODULE}
$ make
```

##### if you use ngx_mruby stream module

```
--with-stream --without-stream_access_module
```

__you must set `--without-stream_access_module` when building nginx__

##### if you build with non-system openssl

```sh
# using configure

$ cd ${NGX_MRUBY_SRC}
$ curl ftp://ftp.openssl.org/source/openssl-1.0.2g.tar.gz | tar -zx
$ ./configure --with-ngx-src-root=${NGINX_SRC} --with-ngx-config-opt="--prefix=/usr/local/nginx" --with-openssl-src=$(pwd)/openssl-1.0.2g
$ make build_mruby
$ make

# or using build.sh

$ curl ftp://ftp.openssl.org/source/openssl-1.0.2g.tar.gz | tar -zx
$ sh build.sh --with-openssl-src=$(pwd)/openssl-1.0.2g
```

##### Building as a dynamic module

Starting from NGINX 1.9.11, you can also compile this module as a dynamic module, by using the --add-dynamic-module=PATH option instead of --add-module=PATH on the ./configure command line above. And then you can explicitly load the module in your nginx.conf via the [load_module](http://nginx.org/en/docs/ngx_core_module.html#load_module) directive, for example,

```
load_module /path/to/modules/ngx_http_mruby_module.so;
```

`build.sh` suppots building as dynamic module by environment value BUILD_DYNAMIC_MODULE.

```sh
# Default install
#  download nginx into ./build_dynamic/
#  build with ngx_mruby into ./build_dynamic/nginx

$ BUILD_DYNAMIC_MODULE=TRUE sh build.sh
```

To use configure.

```bash
$ cd ${NGX_MRUBY_SRC}
$ ./configure --with-ngx-src-root=${NGINX_SRC}
$ make build_mruby_with_fpic
$ make generate_gems_config_dynamic
$ cd ${NGINX_SRC}
$ ./configure --prefix=/usr/local/nginx --add-dynamic-module=${NGX_MRUBY_SRC} --add-module=${NGX_MRUBY_SRC}/dependence/ngx_devel_kit --add-module=${SOME_OTHER_MODULE}
$ make
```

### 3. Install
```bash
$ sudo make install
```
### 4. Add setting
```nginx
location /mruby {
    mruby_content_handler '/usr/local/nginx/html/unified_hello.rb';
}
```
or file cache enabled
```nginx
location /mruby {
    mruby_content_handler '/usr/local/nginx/html/unified_hello.rb' cache;
}
```
or inline code (cached)
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
or Add handler
```nginx
location ~ \.rb$ {
    mruby_add_handler on;
}
```
### 5. Create mruby script
#### /usr/local/nginx/html/unified_hello.rb
```ruby
if server_name == "NGINX"
  Server = Nginx
elsif server_name == "Apache"
  Server = Apache
end

Server::rputs "Hello #{Server::module_name}/#{Server::module_version} world!"
```

### 6. Start nginx
```bash
/usr/local/nginx/sbin/nginx
```
### 7. Access URL 
#### http://127.0.0.1/mruby or http://127.0.0.1/unified_hello.rb
```
Hello ngx_mruby/0.0.1 world!
```

Display above. Welcome mruby world for nginx!!


# Welcome to ngx_mruby Pages  [![Build Status](https://travis-ci.org/matsumoto-r/ngx_mruby.png?branch=master)](https://travis-ci.org/matsumoto-r/ngx_mruby)

[![ngx_mruby mod_mruby performance](http://blog.matsumoto-r.jp/wp-content/uploads/2013/12/performance_20131226.png)](http://blog.matsumoto-r.jp/?p=3974)

※ [hello world simple benchmark, see details of blog entry.](http://blog.matsumoto-r.jp/?p=3974)

## What's ngx_mruby
__ngx_mruby is A Fast and Memory-Efficient Web Server Extension Mechanism Using Scripting Language mruby for nginx.__

- ngx_mruby is to provide an alternative to lua-nginx-module or [mod_mruby of Apache httpd](http://matsumoto-r.github.io/mod_mruby/). 
- Unified Ruby Code between Apache(mod_mruby), nginx(ngx_mruby) and other Web server software(plan) for Web server extensions.
- You can implement nginx modules by Ruby scripts on nginx!
- You can implement some Web server software extensions by same Ruby code (as possible) 
- Supported nginx __1.2/1.3/1.4/1.5.*__
- [Benchmark between ngx_mruby(19423.42 req/sec) and lua-nginx-module(13894.30 req/sec)](https://gist.github.com/matsumoto-r/6930672)

```ruby
# location /proxy {
#   mruby_set $backend "/path/to/proxy.rb";
#   proxy_pass   http://$backend;
# }

backends = [
  "test1",
  "test2",
  "test3",
]

r = Redis.new "192.168.12.251", 6379
r.get backends[rand(backends.length)]
```

- see [examples](https://github.com/matsumoto-r/ngx_mruby/blob/master/example/nginx.conf)
- __Sample of Unified Ruby Code between Apache(mod_mruby) and nginx(ngx_mruby) for Web server extensions__
- You can implement some Web server software extensions by same Ruby code (as possible) 

```ruby
# Unified Ruby Code between Apache(mod_mruby) and nginx(ngx_mruby)
# for Web server extensions.
#
# Apache httpd.conf by mod_mruby
# 
# <Location /mruby>
#     mrubyHandlerMiddle "/path/to/unified_hello.rb"
# </Location>
#
# nginx ngxin.conf by ngx_mruby
#
# location /mruby {
#     mruby_content_handler "/path/to/unified_hello.rb";
# }
#

if server_name == "NGINX"
  Server = Nginx
elsif server_name == "Apache"
  Server = Apache
end

Server::rputs "Hello #{Server::module_name}/#{Server::module_version} world!"
# mod_mruby => "Hello mod_mruby/0.9.3 world!"
# ngx_mruby => "Hello ngx_mruby/0.0.1 world!"
```

## Abstract

As the increase of large-scale and complex Web services, not only a development of Web applications but also an implementation of Web server extensions is required in many cases. The Web server extensions were mainly implemented in C language because of fast and memory-efficient behavior, but extension methods using scripting language are proposed with consideration of maintainability and productivity. However, if the existing methods primarily intended to enhance not the implementation of Web applications but the implementation of internal processing of the Web server, the problem remains in terms of speed, memory-efficiency and safety. Therefore, we propose a fast and memory-efficient Web server extension mechanism using scripting language. We design the architecture that a server process creates the region to save the state of the interpreter at the server process startup, and multiple scripts share the region in order to process fast when the script is called as internal processing from a Web server process. The server process frees the global variables table, the exception flag and the byte-code which cause the increase of memory usage mainly, in order to reduce the memory usage and extend safety by preventing interference between each scripts because of sharing the region. We implement the mechanism that can extend the internal processing of nginx easily by Ruby scripts using nginx and the embeddable scripting language mruby. It's called "ngx_mruby".

## How to use

### 1. Download

```bash
$ git clone git://github.com/matsumoto-r/ngx_mruby.git
$ cd ngx_mruby
$ git submodule init
$ git submodule update
```

- if you want __more features__, you can get [mrbgems](https://github.com/mruby/mruby/wiki/Related-Projects) and write to [build_config.rb](https://github.com/matsumoto-r/ngx_mruby/blob/master/build_config.rb)
- for example, use mruby-io and implement [file base access check like .htaccess](https://gist.github.com/matsumoto-r/7150832).
- default mrbgems
  - gembox: mruby/mruby default mrbgems, mruby-randoma, mruby-env, mruby-print...
  - mruby-process: Process ::fork, ::kill, ::pid, ::ppid, ::waitpid...
  - mruby-pack: pack, unpack...
  - mruby-digest: MD5, RMD160, SHA1, SHA256, SHA384, SHA512 and HMAC Digests
  - mruby-jason: JSON::parse, JSON::stringify
  - mruby-redis: Redis#set, get, [], []=...
  - mruby-sleep: sleep, usleep...
  - mruby-userdata: https://github.com/matsumoto-r/mruby-userdata
  - mruby-hs-regexp: regexp engine
  - mruby-io: https://github.com/iij/mruby-io
- __We should implement ngx_mruby/mod_mruby extensions as mrbgems, as possible.__
- __We recommend the contribute to mruby by implementing mrbgems.__

### 2. Build 
Using build.sh
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
or Download [Nginx](http://nginx.org/en/download.html), unpack, use configure for ngx_mruby, mruby build, ngx_mruby build.
```bash
$ cd ${NGX_MRUBY_SRC}
$ ./configure --with-ngx-src-root=${NGINX_SRC} --with-ngx-config-opt="--prefix=/usr/local/nginx"
$ make build_mruby
$ make
```
or configure with ```--add-module=${NGX_MRUBY_SRC}``` for nginx and make it
```bash
$ cd ${NGINX_SRC}
$ ./configure --prefix=/usr/local/nginx --add-module=${NGX_MRUBY_SRC} --add-module=${NGX_MRUBY_SRC}/dependence/ngx_devel_kit --add-module=${SOME_OTHER_MODULE}
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
### 5. Create mruby script /usr/local/nginx/html/unified_hello.rb'
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
### 7. Access http://127.0.0.1/mruby or http://127.0.0.1/unified_hello.rb
```
Hello ngx_mruby/0.0.1 world!
```

Display above. Welcome mruby world for nginx!!


# License
under the MIT License:

* http://www.opensource.org/licenses/mit-license.php


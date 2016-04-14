# Welcome to ngx_mruby Pages

[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/matsumoto-r/ngx_mruby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Build Status](https://travis-ci.org/matsumoto-r/ngx_mruby.svg?branch=master)](https://travis-ci.org/matsumoto-r/ngx_mruby) [![wercker status](https://app.wercker.com/status/55f7f7af32d94b01a42f863f3635940c/s "wercker status")](https://app.wercker.com/project/bykey/55f7f7af32d94b01a42f863f3635940c)

[![ngx_mruby mod_mruby performance](https://github.com/matsumoto-r/mod_mruby/raw/master/images/performance_20140301.png)](http://blog.matsumoto-r.jp/?p=3974)

※ [hello world simple benchmark, see details of blog entry.](http://blog.matsumoto-r.jp/?p=3974)

## Documents
- [Install](https://github.com/matsumoto-r/ngx_mruby/wiki/Install)
- [Test](https://github.com/matsumoto-r/ngx_mruby/wiki/Test)
- [Directives](https://github.com/matsumoto-r/ngx_mruby/wiki/Directives)
- [Class and Method](https://github.com/matsumoto-r/ngx_mruby/wiki/Class-and-Method)
- [Use Case](https://github.com/matsumoto-r/ngx_mruby/wiki/Use-Case)
- [Examples](https://github.com/hsbt/nginx-tech-talk)

## What's ngx_mruby
__ngx_mruby is A Fast and Memory-Efficient TCP/UDP Load Balancing and Web Server Extension Mechanism Using Scripting Language mruby for nginx.__

- ngx_mruby is to provide an alternative to lua-nginx-module or [mod_mruby of Apache httpd](http://mod.mruby.org/).
- Unified Ruby Code between Apache(mod_mruby), nginx(ngx_mruby) and other Web server software(plan) for Web server extensions.
- You can implement nginx modules by Ruby scripts on nginx!
- You can implement some Web server software extensions by same Ruby code (as possible)
- Supported nginx __1.4/1.6/1.8./1.9.*__
- [Benchmark between ngx_mrubyand lua-nginx-module](https://www.techempower.com/benchmarks/#section=data-r10&hw=peak&test=plaintext&w=4-0)

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

Server = get_server_class

Server::rputs "Hello #{Server::module_name}/#{Server::module_version} world!"
# mod_mruby => "Hello mod_mruby/0.9.3 world!"
# ngx_mruby => "Hello ngx_mruby/0.0.1 world!"
```

## Abstract

As the increase of large-scale and complex Web services, not only a development of Web applications but also an implementation of Web server extensions is required in many cases. The Web server extensions were mainly implemented in C language because of fast and memory-efficient behavior, but extension methods using scripting language are proposed with consideration of maintainability and productivity. However, if the existing methods primarily intended to enhance not the implementation of Web applications but the implementation of internal processing of the Web server, the problem remains in terms of speed, memory-efficiency and safety. Therefore, we propose a fast and memory-efficient Web server extension mechanism using scripting language. We design the architecture that a server process creates the region to save the state of the interpreter at the server process startup, and multiple scripts share the region in order to process fast when the script is called as internal processing from a Web server process. The server process frees the global variables table, the exception flag and the byte-code which cause the increase of memory usage mainly, in order to reduce the memory usage and extend safety by preventing interference between each scripts because of sharing the region. We implement the mechanism that can extend the internal processing of nginx easily by Ruby scripts using nginx and the embeddable scripting language mruby. It's called "ngx_mruby".

# License
under the MIT License:

* http://www.opensource.org/licenses/mit-license.php


# Welcome to ngx_mruby Wiki  [![Build Status](https://travis-ci.org/matsumotory/ngx_mruby.png?branch=master)](https://travis-ci.org/matsumotory/ngx_mruby)

[![ngx_mruby mod_mruby performance](https://github.com/matsumotory/mod_mruby/raw/master/images/performance_20140301.png)](http://blog.matsumoto-r.jp/?p=3974)

※ [hello world simple benchmark, see details of blog entry.](http://blog.matsumoto-r.jp/?p=3974)

## Documents
- [Install](./install)
- [Test](./test)
- [Directives](./directives)
- [Class and Method](./class_and_method)
- [Use Case](./use_case)
- [Release notes](./releases): read "Behavior changes" before upgrading

## Branches and releases
- [Branch strategy](../README.md#branch-strategy): what `master`, `next` and `v2.x` hold, and what to pin to stay on 2.x
- [Promoting v3 to master](./DEVELOPMENT.md#promoting-v3-to-master): the procedure, for maintainers

## What's ngx_mruby
__ngx_mruby is A Fast and Memory-Efficient Web Server Extension Mechanism Using Scripting Language mruby for nginx.__

- ngx_mruby is to provide an alternative to lua-nginx-module or [mod_mruby of Apache httpd](http://mod.mruby.org/). 
- Unified Ruby Code between Apache(mod_mruby), nginx(ngx_mruby) and other Web server software(plan) for Web server extensions.
- You can implement nginx modules by Ruby scripts on nginx!
- You can implement some Web server software extensions by same Ruby code (as possible) 
- Supported nginx __main-line and stable-line__
- [Benchmark between ngx_mruby(19423.42 req/sec) and lua-nginx-module(13894.30 req/sec)](https://gist.github.com/matsumotory/6930672)

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

This example needs the `Redis` class of mruby-redis, and a running Redis server. The default `build_config.rb` builds mruby-redis again since 2.7.2; 2.7.1 left it out.

- see [examples](https://github.com/matsumotory/ngx_mruby/blob/master/example/nginx.conf)
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
# nginx nginx.conf by ngx_mruby
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

### What a worker keeps between requests

The abstract above describes the design of the paper. ngx_mruby today does not free the global variables table between scripts. nginx creates one `mrb_state` for the `http {}` block (and one for the `stream {}` block) while it reads the configuration, and runs the init code (`mruby_init`, `mruby_stream_init`) and the server configuration code (`mruby_server_context_handler_code`) in it before it starts the workers, in the master process. Each worker process gets its own copy when nginx forks it, and runs all the other mruby code of the block in that copy: the init_worker and exit_worker code and every handler and filter, in every server and location, for every client. A reload or a restart starts new workers with a new state.

Global variables, constants, instance variables of `main` (the `self` of handler code), methods defined with `def`, classes and modules with their constants, and what `Userdata` holds (it keeps its values in a global variable) stay in the worker from one request to the next. What one request leaves behind is seen by every later request that the same worker handles, also when the code raised an exception after it made the change. Each worker has its own copy, so one worker does not see the values of another. After each run, ngx_mruby clears the exception (`mrb->exc`); a script file without `cache` is read and compiled again for the next run, and inline code and cached scripts keep the byte-code compiled at startup. The garbage collector frees the objects that nothing refers to any more. Local variables do not stay: each run of handler code starts without them.

Do not keep the data of one request in global variables, constants, instance variables of `main` or `Userdata`, since the next request of the worker, from any client, sees it. Use local variables, and read and write the request through `Nginx::Request`, `Nginx::Var`, `Nginx::Headers_in` and `Nginx::Headers_out` (in `stream {}`, where code runs per session, `Nginx::Stream::Connection`). To pass data from one handler to a later handler of the same request, declare an nginx variable with `set $name "";` and read and write it through `Nginx::Var`, or set the `Userdata` value in every request before it is read. A `set` in the location runs after `mruby_rewrite_handler` and empties the variable again, so declare a variable that a rewrite handler writes with `set` in the `server {}` block. Keep in globals and constants only what all requests of the worker are meant to share, such as settings that the init or init_worker code prepares. [`Nginx.remove_global_variable`](class_and_method/README.md#nginxremove_global_variable) removes a global variable.

# License
under the MIT License:

* http://www.opensource.org/licenses/mit-license.php


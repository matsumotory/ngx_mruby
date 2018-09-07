<p align="center">
  <img alt="ngx_mruby" src="https://github.com/matsumotory/ngx_mruby/blob/master/misc/logo.png?raw=true" width="500">
</p>

<p align="center">
  <strong>ngx_mruby</strong>: ngx_mruby - A Fast and Memory-Efficient Web Server Extension Mechanism Using Scripting Language mruby for nginx.
</p>

<p align="center">

[![Backers on Open Collective](https://opencollective.com/ngx_mruby/backers/badge.svg)](#backers) [![Sponsors on Open Collective](https://opencollective.com/ngx_mruby/sponsors/badge.svg)](#sponsors)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/matsumoto-r/ngx_mruby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Build Status](https://travis-ci.org/matsumotory/ngx_mruby.svg?branch=master)](https://travis-ci.org/matsumotory/ngx_mruby) 

[![ngx_mruby mod_mruby performance](https://github.com/matsumotory/mod_mruby/raw/master/images/performance_20140301.png)](http://blog.matsumoto-r.jp/?p=3974)

※ [hello world simple benchmark, see details of blog entry.](http://blog.matsumoto-r.jp/?p=3974)

</p>

## Documents
- [Install](https://github.com/matsumotory/ngx_mruby/tree/master/docs/install)
- [Test](https://github.com/matsumotory/ngx_mruby/tree/master/docs/test)
- [Directives](https://github.com/matsumotory/ngx_mruby/tree/master/docs/directives)
- [Class and Method](https://github.com/matsumotory/ngx_mruby/tree/master/docs/class_and_method)
- [Use Case](https://github.com/matsumotory/ngx_mruby/tree/master/docs/use_case)
- [Examples](https://github.com/hsbt/nginx-tech-talk)

## What's ngx_mruby
__ngx_mruby is A Fast and Memory-Efficient TCP/UDP Load Balancing and Web Server Extension Mechanism Using Scripting Language mruby for nginx.__

- ngx_mruby is to provide an alternative to lua-nginx-module or [mod_mruby of Apache httpd](http://mod.mruby.org/).
- Unified Ruby Code between Apache(mod_mruby), nginx(ngx_mruby) and other Web server software(plan) for Web server extensions.
- You can implement nginx modules by Ruby scripts on nginx!
- You can implement some Web server software extensions by same Ruby code (as possible)
- Supported nginx main-line and stable-line
- [Benchmark between ngx_mruby and lua-nginx-module](https://www.techempower.com/benchmarks/#section=data-r10&hw=peak&test=plaintext&w=4-0)

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

As the increase of large-scale and complex Web services, not only the development of Web applications is required, but also the implementation of Web server extensions in many cases. Most Web server extensions are mainly implemented in the C language because of fast and memory-efficient behavior, but by writing extensions using a scripting language we can achieve better maintainability and productivity. 

However, if the existing methods are primarily intended to enhance not the implementation of Web applications but the implementation of internal processing of the Web server, the problem remains in terms of speed, memory-efficiency and safety.

Therefore, we propose a fast and memory-efficient Web server extension mechanism using a scripting language. We designed an architecture where the server process creates a region in memory to save the state of the interpreter at the server process startup, and multiple scripts share this region to process the scripts quickly when new request are made.

The server process frees the global variables table, the exception flag and the byte-code which cause an increase of memory usage, in order to reduce the memory usage and extend safety by preventing interference between each script because of sharing the region. We implemented a mechanism that can extend the internal processing of nginx easily by Ruby scripts using nginx and the embeddable scripting language mruby. It's called "ngx_mruby".

# Contributions

This project exists thanks to all the people who contribute. We also welcome financial contributions in full transparency on our [open collective](https://opencollective.com/ngx_mruby).

## Backers

Thank you to all our backers! 🙏 [[Become a backer](https://opencollective.com/ngx_mruby#backer)]

<a href="https://opencollective.com/ngx_mruby#backers" target="_blank"><img src="https://opencollective.com/ngx_mruby/backers.svg?width=890"></a>


## Sponsors

Support this project by becoming a sponsor. Your logo will show up here with a link to your website. [[Become a sponsor](https://opencollective.com/ngx_mruby#sponsor)]

# License

This project is under the MIT License:

* http://www.opensource.org/licenses/mit-license.php

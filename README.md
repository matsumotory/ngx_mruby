<p align="center">
  <img alt="ngx_mruby" src="https://github.com/matsumotory/ngx_mruby/blob/master/misc/logo.png?raw=true" width="300">
</p>

<p align="center">
  <strong>ngx_mruby</strong>: A Fast and Memory-Efficient Nginx Extension Mechanism Scripting with mruby.
</p>

<p align="center">
  <a href="#backers" title="Backers on Open Collective"><img src="https://opencollective.com/ngx_mruby/backers/badge.svg"></a>
  <a href="#sponsors" title="Sponsors on Open Collective"><img src="https://opencollective.com/ngx_mruby/sponsors/badge.svg"></a>
  <a href="https://github.com/matsumotory/ngx_mruby/actions" title="Build Status"><img src="https://github.com/matsumotory/ngx_mruby/actions/workflows/test.yml/badge.svg?branch=master"></a>
</p>

## Documents
- [Install](https://github.com/matsumotory/ngx_mruby/tree/master/docs/install)
- [Test](https://github.com/matsumotory/ngx_mruby/tree/master/docs/test)
- [Directives](https://github.com/matsumotory/ngx_mruby/tree/master/docs/directives)
- [Class and Method](https://github.com/matsumotory/ngx_mruby/tree/master/docs/class_and_method)
- [Use Case](https://github.com/matsumotory/ngx_mruby/tree/master/docs/use_case)
- [Examples](https://github.com/hsbt/nginx-tech-talk)

## Branch strategy

ngx_mruby has three long-lived code branches: `master`, `next` and `v2.x` (the `gh-pages` branch holds the site, [ngx.mruby.org](https://ngx.mruby.org/)). Their names and roles stay as they are. `master` is the 2.x line until v3 is promoted to it, so that everyone who builds from the default branch keeps receiving the 2.x security fixes. v3 is developed on `next` and becomes `master` at v3.0.0 (the promotion). From then on, `v2.x` carries 2.x.

```text
              until the promotion                 |  after the promotion
                                                  |
next    ---*alpha.1---*beta.1---*rc.1---*rc.N---+ |  - - ?
                                                 \
master  -*v2.7.0--*v2.7.x-- ... -----------o------M------*------*--- ... --> 3.x
         :        :                        :
v2.x    -*v2.7.0--*v2.7.x-- ... -----------o----------*------*------ ... --] 2.x

*  a release tag (v2.*, v3.*) or a pre-release tag (v3.0.0-*); v2.7.x stands
   for the 2.x releases after v2.7.0
o  the last 2.x commit on master
:  the same commit on both branches
M  the merge of next into master, tagged v3.0.0
?  what next becomes after the promotion is open (see the table below)
]  the end of 2.x support, twelve months after v3.0.0
The merges of master into next before the promotion are not drawn.
```

| Branch | Until the promotion | After the promotion (v3.0.0) |
|---|---|---|
| `master` (default branch) | The 2.x line: 2.x fixes, `v2.*` releases | The 3.x line: `v3.*` releases |
| `v2.x` | The same commits as `master`: a workflow copies every push to `master` to `v2.x` | The 2.x line: stability and security fixes, `v2.*` releases |
| `next` | Development of v3 and its pre-releases | Open; the recommendation is to keep it for the development of 3.1 (see [Promoting v3 to master](docs/DEVELOPMENT.md#promoting-v3-to-master)) |

Until the promotion, `master` is merged into `next` after 2.x fixes, so v3 has them too.

v3 is developed on `next`. Its pre-releases are tagged `v3.0.0-alpha.N`, `v3.0.0-beta.N` and `v3.0.0-rc.N` and are marked as pre-releases on GitHub. Section 6 of the v3 plan ([docs/proposals/v3-plan.md](https://github.com/matsumotory/ngx_mruby/blob/next/docs/proposals/v3-plan.md) on `next`) sets when the first pre-release of each kind is tagged:

- `v3.0.0-alpha.1`: when the 2.x test suite passes on the new core of v3 and the sanitizers report nothing.
- `v3.0.0-beta.1`: when the migration guide and the examples exist.
- `v3.0.0-rc.1`: when the site and the examples are complete.

`v3.0.0` is tagged when `next` is promoted to `master`, under the conditions in [Promoting v3 to master](docs/DEVELOPMENT.md#promoting-v3-to-master). No date is set. At least one `v3.0.0-rc.N` comes first, and how long the last one stays out before v3.0.0 is still open. The pre-releases and releases appear on the [releases page](https://github.com/matsumotory/ngx_mruby/releases); to be notified of them, watch the repository with "Custom" and "Releases" selected.

### For existing users

If you do not want anything to change, build from `v2.x` or from the latest `v2.*` release tag instead of `master`, and switch now:

```sh
git clone -b v2.x https://github.com/matsumotory/ngx_mruby.git     # the 2.x branch
git clone -b vX.Y.Z https://github.com/matsumotory/ngx_mruby.git   # or the latest v2.* release tag
```

A release tag does not receive fixes. If you pin one, move to each new 2.x release, because only the latest 2.x release is supported (see [SECURITY.md](SECURITY.md#supported-versions)), or pin `v2.x`, which receives the 2.x fixes as they are merged.

If you start using ngx_mruby now, the same applies: for production, build from `v2.x` or the latest `v2.*` release tag, and to try v3, track `next`.

Until the promotion, `v2.x` has the same commits as `master`, so pinning it does not change the code you build until then. At the promotion, `master` becomes v3.0.0, a new major version. Section 7 of the [v3 plan](https://github.com/matsumotory/ngx_mruby/blob/next/docs/proposals/v3-plan.md) already decides changes to its build requirements and behavior: mruby 4.1 instead of 3.3; nginx 1.30 (stable) and 1.31 (mainline) as the oldest supported versions, raised every April, so that users of older nginx (1.28, or the 1.26 and 1.24 packages of Linux distributions) stay on 2.x; OpenSSL 3.5 as the baseline with 1.1.1 and 3.0 dropped; `auto-ssl` removed from the default build; and the behavior changes of item 8: a Ruby API called outside the phase it is designed for raises an exception, an exception after `rputs` returns 500, `Headers#delete` matches the full header name, `Nginx.return 200` with an empty body is allowed, and a body is sent with any status. The v3 migration guide will list each change.

The 2.x line (`master` until the promotion, then `v2.x`) puts compatibility first. It receives only stability fixes (crashes, hangs, leaks, and build fixes such as those for new nginx, OS, compiler or OpenSSL releases) and security fixes, and it changes behavior only as far as the fix of a defect requires. From the next release on, the release notes in [docs/releases/](docs/releases/) list each such change. 2.x stays supported for twelve months after v3.0.0 (see [SECURITY.md](SECURITY.md#supported-versions)).

Releases are tagged `vX.Y.Z`. If you contribute a fix, send 2.x fixes to `master` until the promotion and v3 work to `next` (see [AGENTS.md](AGENTS.md#branches-and-pull-requests)).

Before upgrading, read the "Behavior changes: read before upgrading" section of every newer release in [docs/releases/](docs/releases/).

Please report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

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


[![ngx_mruby mod_mruby performance](https://github.com/matsumotory/mod_mruby/raw/master/images/performance_20140301.png)](http://blog.matsumoto-r.jp/?p=3974)

※ [hello world simple benchmark, see details of blog entry.](http://blog.matsumoto-r.jp/?p=3974)


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

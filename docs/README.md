# Welcome to ngx_mruby Wiki  [![Build Status](https://travis-ci.org/matsumotory/ngx_mruby.png?branch=master)](https://travis-ci.org/matsumotory/ngx_mruby)

[![ngx_mruby mod_mruby performance](https://github.com/matsumotory/mod_mruby/raw/master/images/performance_20140301.png)](http://blog.matsumoto-r.jp/?p=3974)

※ [hello world simple benchmark, see details of blog entry.](http://blog.matsumoto-r.jp/?p=3974)

## Documents
- [Get started](../examples/start/README.md): run nginx with a Ruby handler in Docker, then change the script
- [Install](./install)
- [Test](./test)
- [Directives](./directives)
- [Class and Method](./class_and_method)
- [Build](./reference/build.md): how the build fits together, the options of `configure`, the default mrbgems and the versions that CI tests
- [Migrating from ngx_mruby 2.x to 3.0.0](./migration): the steps for the behavior changes of v3.0.0
- Guides: [Route requests to a backend](./guides/routing.md), [Deny clients listed in a file](./guides/access-control.md), [Limit the rate per API key](./guides/rate-limit.md), [Change a response body](./guides/body-filter.md), [Allow TCP connections in Ruby](./guides/tcp.md)
- [Use cases](./use_case): each with a sample that CI runs, or marked untested with the reason
- [Concepts](./concepts/README.md): [request phases](./concepts/request-phases.md), [filters](./concepts/filters.md), [waiting without blocking](./concepts/async.md) and [lifetimes](./concepts/lifetimes.md)
- [Release notes](./releases): read "Behavior changes" before upgrading
- [Trust boundary](#trust-boundary): what ngx_mruby trusts, what it treats as client input, and what a script is responsible for

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

The abstract above describes the design of the paper. ngx_mruby today does not free the global variables table between scripts: [Lifetimes](concepts/lifetimes.md) says what a worker keeps between requests.

## Trust boundary

ngx_mruby runs Ruby code that the operator of the nginx server writes, and it treats what a client sends as input to that code. It is not a sandbox: it does not confine the code that the configuration loads. This section says what each side of the boundary is, what ngx_mruby is responsible for, what the operator's code is responsible for, and how this maps onto the scope of [SECURITY.md](../SECURITY.md).

### The trusted side: the configuration and the code it loads

- The nginx configuration and all the Ruby code that it loads are trusted: the script files that the directives name (`mruby_content_handler /path/to/handler.rb` and the others), the inline code of the `*_code` directives, and the gems that `build_config.rb` builds into the module. ngx_mruby compiles and runs this code as it is, and does not check what the code does.
- With [`mruby_add_handler on`](directives/README.md#mruby_add_handler), the request URI chooses which file runs: ngx_mruby maps the URI to a path under the location's root and runs that file as a content handler. Every file that the location matches under that root is code of this kind.
- The init code (`mruby_init`, `mruby_init_code`, `mruby_stream_init`, `mruby_stream_init_code`) and the server configuration code (`mruby_server_context_handler_code`, `mruby_stream_server_context_code`) run in the master process while nginx reads the configuration, with the privileges that nginx was started with (root, when nginx is started as root). All the other code (init_worker and exit_worker code, every handler and filter, the SSL handshake handlers, the stream handlers) runs in the worker processes, with the privileges of the workers (the user of the `user` directive, when the master runs as root).
- All the code of an `http {}` block runs in one `mrb_state` per worker (and one for the `stream {}` block), shared by every server, location and client of that block ([What a worker keeps between requests](concepts/lifetimes.md#what-a-worker-keeps-between-requests)). The code of one location can read and change the global variables, constants, classes and methods that the code of another server or location defined. ngx_mruby does not separate the scripts of one block from each other.
- The default build gives this code the mruby core gems that `NGX_MRUBY_CORE_GEMS` in `build_config.rb` lists ([Core gems](install/README.md#core-gems)) and the other gems of `build_config.rb`. Among them are `eval` and `instance_eval` (mruby-eval), files, `IO.popen` and backquotes, which run shell commands (mruby-io), sockets (mruby-socket), `sleep` (mruby-sleep), `Process` (iij/mruby-process), `ENV` and `Dir`. A script can do what the user of its process can do.

Whoever can change the nginx configuration, a script that it loads, a directory that holds such a script, or `build_config.rb` can therefore run any code as the workers, and through the init code as the master. A setup that takes nginx configuration or Ruby code from parties that the operator does not trust, such as a multi-tenant service that runs a snippet per customer, gives each of those parties that power over the whole nginx and every other party's traffic. ngx_mruby has no means to confine such code, and does not support this use.

### The untrusted side: what a client sends

Everything that a client sends is untrusted input: the request line, the URI and its arguments, the headers and cookies, the request body, and the values that nginx derives from them. Scripts read these values through [`Nginx::Request`](class_and_method/README.md#nginxrequest-class) (`uri`, `unparsed_uri`, `args`, `uri_args`, `post_args`, `method`, `headers_in`, `get_body`, `user` and the others), [`Nginx::Headers_in`](class_and_method/README.md#nginxheaders_in-class), and [`Nginx::Var`](class_and_method/README.md#nginxvar-class) (for example `$http_*`, `$arg_*`, `$cookie_*` and `$request_uri`). The server name that a client sends in the TLS handshake ([`Nginx::SSL#servername`](class_and_method/README.md#nginxsslservername---string)) is untrusted in the same way. A response from an upstream server, also one that a subrequest or an output filter reads, is as trustworthy as that upstream server.

### What ngx_mruby is responsible for

- nginx parses the request before ngx_mruby sees it. The C code of ngx_mruby (`src/`) and its bundled gems (`mrbgems/`) hand the request's values to the script as Ruby strings and other objects, and take the values that the script passes back as data. A configuration that uses the directives and methods as they are documented is not meant to make ngx_mruby read or write memory outside its buffers, end or hang the worker, or give one request the data of another, whatever the client sends and also when the script passes client input on to a method of ngx_mruby. Where it does, that is a defect of ngx_mruby, also when the script's own call, and no client value, triggers it.
- 2.7.1 and 2.7.2 fixed defects of this kind in calls that the configuration's own code makes; in some of them a client value had no part. In 2.7.0 a body filter that made a body written with `Nginx.rputs` or `Nginx.echo` shorter sent bytes from beyond the end of the new body, and request-scoped methods called outside a request could use the data of another request ([2.7.1 release notes](releases/v2.7.1.md), entries 2 and 8, and the advisory [GHSA-h7fw-wf49-8rv5](https://github.com/matsumotory/ngx_mruby/security/advisories/GHSA-h7fw-wf49-8rv5)). In 2.7.1 `Nginx::Var` read memory outside the name or the arguments for an empty name, a name made only of `=`, and a setter without its value, and `Nginx::Var#set` changed the String or Symbol passed as the name ([2.7.2 release notes](releases/v2.7.2.md), entries 1 and 2). The accessor now checks the name and the arguments before it reads them, and `#set` looks the variable up by a lowercased copy of the name, whatever value the script passes, also one that it took from the client.

### What the operator's code is responsible for

ngx_mruby runs what the script asks for. What follows from passing client input on is the script's responsibility.

- Validate client input before it reaches anything that acts on it: `eval` or `instance_eval`, a shell command (backquotes, `IO.popen`, `Process`), a file path (`File`, `Dir`, [`Nginx::SSL#certificate=`](class_and_method/README.md#nginxsslcertificatestring) and `#certificate_key=`), the name of an nginx variable (`Nginx::Var` with a name built at run time, `Nginx::Var#set`), an upstream address (`mruby_set $backend`, `Nginx::Upstream#server=`), a redirect target or a response header. Compare the input with a list of allowed values, or parse it into the type that the code expects, and reject what does not match. For example, a handshake handler that builds the path of a certificate from the server name lets the client choose the path; look the name up in a table instead, so that only names with a certificate reach a path:

  ```nginx
  http {
      mruby_init_code '
          CERT_DIRS = {
            "example.com"     => "/etc/nginx/certs/example.com",
            "www.example.com" => "/etc/nginx/certs/www.example.com",
          }
      ';

      server {
          listen 443 ssl;
          ssl_certificate     /etc/nginx/certs/default.crt;
          ssl_certificate_key /etc/nginx/certs/default.key;

          mruby_ssl_handshake_handler_code '
              ssl = Nginx::SSL.new
              dir = CERT_DIRS[ssl.servername]
              if dir
                ssl.certificate = "#{dir}/cert.pem"
                ssl.certificate_key = "#{dir}/key.pem"
              end
          ';
      }
  }
  ```

  A handshake whose code sets no certificate uses the server's `ssl_certificate` and `ssl_certificate_key` ([Nginx::SSL](class_and_method/README.md#nginxssl-class)). `certificate=` and `certificate_key=` make the worker read the files during the handshake, which blocks it (see the next item). To avoid the read, load the PEM data in the init code and set it with [`certificate_data=`](class_and_method/README.md#nginxsslcertificate_datastring) and [`certificate_key_data=`](class_and_method/README.md#nginxsslcertificate_key_datastring).
- Keep the data of one request out of global variables, constants, instance variables of `main` and `Userdata`: the next request of the worker, from any client, sees it ([What a worker keeps between requests](concepts/lifetimes.md#what-a-worker-keeps-between-requests)).
- Avoid blocking calls on the request path. A worker serves many clients at once, and while a script waits in `sleep`, a socket, a file, a shell command, `Process` or a Redis call, the worker serves no other client. A client that can make a script wait can therefore slow down every client of that worker. Use [`Nginx::Async.sleep`](class_and_method/README.md#nginxasyncsleepmsec) and [`Nginx::Async::HTTP.sub_request`](class_and_method/README.md#nginxasynchttpsub_requestlocation-string_or_hashnil) where their documentation says that they work, and add `cache` to the script directives, set `mruby_cache on`, or use inline code, so that a script file is not read from disk on every request.
- Keep the nginx configuration, the scripts, the directories that hold them and `build_config.rb` writable only by the operator. With `mruby_add_handler on`, keep only handler scripts under that root, and do not store files that clients upload there.

### How this maps onto SECURITY.md

Report privately, as [SECURITY.md](../SECURITY.md) describes, a defect of ngx_mruby (`src/`, `mrbgems/`) that makes ngx_mruby read or write memory outside its buffers, end or hang the worker, or reveal or change the data of another request, in a configuration that uses the directives and methods as they are documented, in particular when input a client controls triggers it. This includes a script that passes client input on to a method of ngx_mruby, and a documented call of the script that triggers the defect without any client value. Defects of bundled or third-party components go to their upstream projects as well, as SECURITY.md says. If you are not sure whether a defect is in scope, report it privately.

Outside the scope of SECURITY.md is what follows from the trusted side doing what it was written to do: a script that passes client input to `eval`, a shell command, a file path or another of the uses above; data of one request that a script keeps in a global and a later request sees; a blocking call in a script that stalls its worker; anyone who can change the configuration, a script or `build_config.rb` running code; and a setup that takes nginx configuration or Ruby code from parties that the operator does not trust.
## Development

- [State of the work](./HANDOFF.md): open pull requests, decisions, work in progress and the queue, for any session or contributor to continue. The rules are in [AGENTS.md](../AGENTS.md).

# License
under the MIT License:

* http://www.opensource.org/licenses/mit-license.php


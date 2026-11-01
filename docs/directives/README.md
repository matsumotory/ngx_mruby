# Directives

ngx_mruby enables you to run mruby scripts on nginx. For example, you can implement:

* [your own auth mechanism](../use_case/README.md#file-based-access-list) like nginx [auth_basic](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-http-basic-authentication/)
* [reverse proxy with your own backend selection algorithm](../use_case/README.md#reverse-proxy)
* [content handler that returns any HTTP response](../use_case/README.md#hello-world)

See [use cases](../use_case) page for more examples.
The scripts can be invoked at any of nginx HTTP phases. See [nginx phases doc](http://nginx.org/en/docs/dev/development_guide.html#http_phases) for more details of the phases.

ngx_mruby provides 2 modules. One is HTTP module for HTTP, the other is Stream module for TCP/UDP stream.
See [HTTP module directives](#http-module-directives) and [Stream module directive](#stream-module-directives) section for more details.

Here is a simple example of a content handler for HTTP.

**nginx.conf**
```nginx
location /hello {
    mruby_content_handler /path/to/hello.rb;
}
```

**/path/to/hello.rb**
```
Nginx.echo "Hello World"
```

```
$ curl http://127.0.0.1/hello
Hello World
```

'mruby_content_handler' is a directive to specify a mruby script file that is invoked at NGX_HTTP_CONTENT_PHASE to generate the response.
You will get 'Hello World' as a HTTP response body if you access '/hello' endpoint.

'Nginx.echo' is a method to creates a response body. ngx_mruby provides classes for accessing or manipulating nginx internal data structures. See [classes for ngx_mruby](../class_and_method) for more information.

## Caching compile code

By default, mruby script is compiled whenever it is invoked.
You can enable compiled code cache with 'cache' argument for performance.

**nginx.conf**
```nginx
location /hello {
    mruby_content_handler /path/to/hello.rb cache;
}
```

## Inline code

You can write mruby code in nginx.conf instead of creating a script file. The compiled code is cached.

**nginx.conf**
```nginx
location /hello {
    mruby_content_handler_code '
        Nginx.echo "Hello World"
    ';
}
```

## Nginx variables

You can set nginx variable by a mruby script.
The following example set a value returned from 'proxy.rb' to the variable '$backend'.

**nginx.conf**
```nginx
location /proxy {
    mruby_set $backend /path/to/proxy.rb;
}
```

Also you can enable caching, or write inline mruby code as same as other directives.

**nginx.conf**
```nginx
location /proxy {
    mruby_set $backend /path/to/proxy.rb cache;
}
```

**nginx.conf**
```nginx
location /proxy {
    mruby_set_code $backend '
        backends = [
          "test1.example.com",
          "test2.example.com",
          "test3.example.com",
        ]
        backends[rand(backends.length)]
   ';
}
```

## Hooks on initialization phases

ngx_mruby provides hooks invoked on several nginx initialization phases as below.
See nginx [Core Modules](http://nginx.org/en/docs/dev/development_guide.html#core_modules) doc for more about initialization phases.

```nginx
http {
  mruby_init /path/to/init.rb;
  mruby_init_worker /path/to/init_worker.rb;
  mruby_exit_worker /path/to/exit_worker.rb;
  server {
    location / {
      mruby_content_handler /path/to/handler.rb;
    }
  }
}
```

## Script file as a handler

You can run a ruby script file directly without location definition. 
In the following example, the script is exposed at http://127.0.0.1/YOUR_MRUBY_SCRIPT.rb

```nginx
location ~ \.rb$ {
    mruby_add_handler on;
}
```

## Messages logged while nginx reads the configuration

While nginx reads the configuration, ngx_mruby logs these messages at the `info` level:

* `ngx_mruby/VERSION (mruby/VERSION) mechanism enabled`, once for the `http {}` block
* `compile info: code->code.file=(...)` or `compile info: code->code.string=(...)` for each directive with Ruby code, in `http {}` and in `stream {}`
* `target variable=(...)` for each `mruby_set` and `mruby_set_code`

nginx logs what happens while it reads the configuration through its startup log, not through the log that `error_log` configures.
The startup log is the file given with `nginx -e` (nginx 1.19.5 and later), or else the error log path compiled into nginx (`--error-log-path`, `logs/error.log` under the prefix by default), and its level is `notice` whatever `error_log` says.
nginx uses the configured `error_log` only after it has read the configuration. So:

* A start of nginx does not write these messages, whatever the level of `error_log`.
* `nginx -t` raises the startup log to `info`, so it writes them to the startup log.
* A reload (`nginx -s reload`) reads the new configuration through the `error_log` of the running configuration, so it writes them when that `error_log` is at `info` or `debug`.

A script file that cannot be opened, or an argument that a directive does not accept, is still logged at `emerg`, and nginx stops.

In ngx_mruby 2.x these messages were logged at `notice`, so the startup log wrote them at every start, also with `error_log ... warn;` ([#320](https://github.com/matsumotory/ngx_mruby/issues/320)).
From v3 on, to see them, run `nginx -t -e stderr`, read the startup log after `nginx -t`, or reload with `error_log` at `info`.

# HTTP module directives

* [mruby_init and mruby_init_code](#mruby_init-and-mruby_init_code)
* [mruby_init_worker and mruby_init_worker_code](#mruby_init_worker-and-mruby_init_worker_code)
* [mruby_exit_worker and mruby_exit_worker_code](#mruby_exit_worker-and-mruby_exit_worker_code)
* [mruby_ssl_handshake_handler and mruby_ssl_handshake_handler_code](#mruby_ssl_handshake_handler-and-mruby_ssl_handshake_handler_code)
* [mruby_server_context_handler_code](#mruby_server_context_handler_code)
* [mruby_add_handler](#mruby_add_handler)
* [mruby_cache](#mruby_cache)
* [mruby_post_read_handler and mruby_post_read_handler_code](#mruby_post_read_handler-and-mruby_post_read_handler_code)
* [mruby_server_rewrite_handler, mruby_server_rewrite_handler_code, mruby_rewrite_handler and mruby_rewrite_handler_code](#mruby_server_rewrite_handler-mruby_server_rewrite_handler_code-mruby_rewrite_handler-and-mruby_rewrite_handler_code)
* [mruby_access_handler and mruby_access_handler_code](#mruby_access_handler-and-mruby_access_handler_code)
* [mruby_content_handler and mruby_content_handler_code](#mruby_content_handler-and-mruby_content_handler_code)
* [mruby_log_handler and mruby_log_handler_code](#mruby_log_handler-and-mruby_log_handler_code)
* [mruby_set and mruby_set_code](#mruby_set-and-mruby_set_code)
* [mruby_output_body_filter, mruby_output_body_filter_code, mruby_output_header_filter and mruby_output_header_filter_code](#mruby_output_body_filter-mruby_output_body_filter_code-mruby_output_header_filter-and-mruby_output_header_filter_code)
* [mruby_enable_read_request_body](#mruby_enable_read_request_body)
* [mruby_upstream_keepalive](#mruby_upstream_keepalive)
* [mruby_output_filter and mruby_output_filter_code (removed)](#mruby_output_filter-and-mruby_output_filter_code-removed)

## mruby_init and mruby_init_code

```
Syntax:  mruby_init /PATH/TO/YOUR/MRUBY/SCRIPT.rb [cache];
Default: -
Context: http
Phase:   initialize master process
```

```
Syntax:  mruby_init_code 'YOUR MRUBY CODE HERE';
Default: -
Context: http
Phase:   initialize master process
```
'mruby_init' and 'mruby_init_code' are called at initialized time in the context of the master process.

## mruby_init_worker and mruby_init_worker_code

```
Syntax:  mruby_init_worker /PATH/TO/YOUR/MRUBY/SCRIPT.rb [cache];
Default: -
Context: http
Phase:   initialize worker process
```

```
Syntax:  mruby_init_worker_code 'YOUR MRUBY CODE HERE';
Default: -
Context: http
Phase:   initialize worker process
```

After initializing nginx master process, it creates worker processes.
'mruby_init_worker' and 'mruby_init_worker_code' are called when worker processes are created.

The code runs outside any request.
`Nginx.log` writes to nginx's error log here (since 2.7.1; 2.7.0 raised a `RuntimeError`).
Request-scoped methods such as `Nginx::Request`, `Nginx::Var` and `Nginx.rputs` raise a `RuntimeError` here (since 2.7.1; in 2.7.0 they crashed the worker).
See [Nginx.errlogger](../class_and_method/README.md#nginxerrloggerlog_level-string) for what code outside a request can call.

## mruby_exit_worker and mruby_exit_worker_code

```
Syntax:  mruby_exit_worker /PATH/TO/YOUR/MRUBY/SCRIPT.rb [cache];
Default: -
Context: http
Phase:   exit worker process
```

```
Syntax:  mruby_exit_worker_code 'YOUR MRUBY CODE HERE';
Default: -
Context: http
Phase:   exit worker process
```

'mruby_exit_worker' and 'mruby_exit_worker_code' are called when a worker process is shutdown or terminated.

The code runs outside any request.
`Nginx.log` writes to nginx's error log here (since 2.7.1).
Request-scoped methods such as `Nginx::Request`, `Nginx::Var` and `Nginx.rputs` raise a `RuntimeError` here (since 2.7.1; in 2.7.0 they used the last request that the worker had handled, or crashed the worker when it had handled none).
See [Nginx.errlogger](../class_and_method/README.md#nginxerrloggerlog_level-string) for what code outside a request can call.

## mruby_ssl_handshake_handler and mruby_ssl_handshake_handler_code

```
Syntax:  mruby_ssl_handshake_handler /PATH/TO/YOUR/MRUBY/SCRIPT.rb [cache];
Default: -
Context: server
Phase:   SSL handshake
```

```
Syntax:  mruby_ssl_handshake_handler_code 'YOUR MRUBY CODE HERE';
Default: -
Context: server
Phase:   SSL handshake
```

'mruby_ssl_handshake_handler' and 'mruby_ssl_handshake_handler_code' are called when SSL handshake is started.
Both are enabled only if ngx_mruby is compiled with OpenSSL.

The code runs for a TLS connection, before any request on it, and uses [Nginx::SSL](../class_and_method/README.md#nginxssl-class) to read the server name and to set the certificate.
`Nginx::SSL.log` writes to the log of the connection, and `Nginx.log` writes to nginx's error log (since 2.7.1).
Request-scoped methods such as `Nginx::Request`, `Nginx::Var` and `Nginx.rputs` raise a `RuntimeError` here (since 2.7.1; in 2.7.0 they used the last request that the worker had handled, or crashed the worker when it had handled none).
See [Nginx.errlogger](../class_and_method/README.md#nginxerrloggerlog_level-string) for what code outside a request can call.

## mruby_server_context_handler_code

```
Syntax:  mruby_server_context_handler_code 'YOUR MRUBY CODE HERE';
Default: -
Context: server
Phase:   read the configuration, in the master process
```

The code runs once for its `server` block, while nginx reads the configuration, in the master process.
It configures the server: [`Nginx::Server#add_listener`](../class_and_method/README.md#nginxserveradd_listenerhash) adds a `listen` address to it.
No request exists yet, so the request-scoped methods raise a `RuntimeError` here.

## mruby_add_handler

```
Syntax:  mruby_add_handler on | off;
Default: off
Context: server, location
Phase:   initialize master process
```

When set to the value on, mruby scripts are added as handlers.
You can run the script files directly without endpoint definition.

## mruby_cache

```
Syntax:  mruby_cache on | off;
Default: off
Context: server, location
Phase:   initialize master process
```

When set to the value on, nginx compiles the script files of the post-read, server rewrite, rewrite, access, content and log handlers, the header and body filters and `mruby_set` of the server or location once, when it reads the configuration, as the parameter `cache` does for one directive.
`mruby_ssl_handshake_handler` and the init and exit hooks take only their own parameter `cache`.
With off, a script file without `cache` is read from disk and compiled for every request, so that a change of the file takes effect at the next request (see [Caching compile code](#caching-compile-code)).

## mruby_post_read_handler and mruby_post_read_handler_code

```
Syntax:  mruby_post_read_handler /PATH/TO/YOUR/MRUBY/SCRIPT.rb [cache];
Default: -
Context: server
Phase:   NGX_HTTP_POST_READ_PHASE
```

```
Syntax:  mruby_post_read_handler_code 'YOUR MRUBY CODE HERE';
Default: -
Context: server
Phase:   NGX_HTTP_POST_READ_PHASE
```

'mruby_post_read_handler' and 'mruby_post_read_handler_code' are called at NGX_HTTP_POST_READ_PHASE.
It is first phase of HTTP request handling.

## mruby_server_rewrite_handler, mruby_server_rewrite_handler_code, mruby_rewrite_handler and mruby_rewrite_handler_code

```
Syntax:  mruby_server_rewrite_handler /PATH/TO/YOUR/MRUBY/SCRIPT.rb [cache];
Default: -
Context: server, location
Phase:   NGX_HTTP_SERVER_REWRITE_PHASE
```

```
Syntax:  mruby_server_rewrite_handler_code 'YOUR MRUBY CODE HERE';
Default: -
Context: server, location
Phase:   NGX_HTTP_SERVER_REWRITE_PHASE
```

```
Syntax:  mruby_rewrite_handler /PATH/TO/YOUR/MRUBY/SCRIPT.rb [cache];
Default: -
Context: server, location
Phase:   NGX_HTTP_REWRITE_PHASE
```

```
Syntax:  mruby_rewrite_handler_code 'YOUR MRUBY CODE HERE';
Default: -
Context: server, location
Phase:   NGX_HTTP_REWRITE_PHASE
```

The rewrite handlers are mainly used for URL rewrite.
'mruby_server_rewrite_handler' and 'mruby_server_rewrite_handler_code' are used in a server block (and outside a location).
'mruby_rewrite_handler' and 'mruby_rewrite_handler_code' are used in a location block.

TODO: I'm not sure if the above contexts are correct.

## mruby_access_handler and mruby_access_handler_code

```
Syntax:  mruby_access_handler /PATH/TO/YOUR/MRUBY/SCRIPT.rb [cache];
Default: -
Context: server, location
Phase:   NGX_HTTP_ACCESS_PHASE
```

```
Syntax:  mruby_access_handler_code 'YOUR MRUBY CODE HERE';
Default: -
Context: server, location
Phase:   NGX_HTTP_ACCESS_PHASE
```

'mruby_access_handler' and 'mruby_access_handler_code' are basically for authentication and authorization.

## mruby_content_handler and mruby_content_handler_code

```
Syntax:  mruby_content_handler /PATH/TO/YOUR/MRUBY/SCRIPT.rb [cache];
Default: -
Context: server, location
Phase:   NGX_HTTP_CONTENT_PHASE
```

```
Syntax:  mruby_content_handler_code 'YOUR MRUBY CODE HERE';
Default: -
Context: server, location
Phase:   NGX_HTTP_CONTENT_PHASE
```

mruby_content_handler and mruby_content_handler_code are normally used for generating a HTTP response.

## mruby_log_handler and mruby_log_handler_code

```
Syntax:  mruby_log_handler /PATH/TO/YOUR/MRUBY/SCRIPT.rb [cache];
Default: -
Context: server, location
Phase:   NGX_HTTP_LOG_PHASE
```

```
Syntax:  mruby_log_handler_code 'YOUR MRUBY CODE HERE';
Default: -
Context: server, location
Phase:   NGX_HTTP_LOG_PHASE
```

'mruby_log_handler' and 'mruby_log_handler_code' are called at the end of request processing for logging.

## mruby_set and mruby_set_code

```
Syntax:  mruby_set $VARNAME /PATH/TO/YOUR/MRUBY/SCRIPT.rb [cache];
Default: -
Context: server, location
Phase:   NGX_HTTP_SERVER_REWRITE_PHASE, NGX_HTTP_REWRITE_PHASE
```

```
Syntax:  mruby_set_code $VARNAME 'YOUR MRUBY CODE HERE';
Default: -
Context: server, location
Phase:   NGX_HTTP_SERVER_REWRITE_PHASE, NGX_HTTP_REWRITE_PHASE
```

'mruby_set' and 'mruby_set_code' are called at one of the rewrite phases to set a nginx variable.

If the code raises an exception before it waits in `Nginx::Async.sleep`, ngx_mruby logs it, the variable is set to an empty string (as when the code returns `nil`), also when an earlier directive of the location gave it a value, and the request goes on.
Text that the code wrote with `Nginx.rputs` or `Nginx.echo` before the exception is not sent and does not count in the `Content-Length` of the response.
If the code raises after the sleep, the request gets 500 and the output of `Nginx.rputs` is not sent, as described under [Nginx::Async#sleep](../class_and_method/README.md#nginxasyncsleepmsec).

The value of the code is converted to a String with `to_s`. When the value has no `to_s`, when `to_s` raises, or when it returns an object that is not a String, ngx_mruby logs the exception (a `TypeError` for the object that is not a String) and the request gets 500, with or without a sleep. Unlike an exception of the code, which leaves the variable empty, such a value ends the request: the code returned a value that the variable cannot hold.

`Nginx::Async::HTTP.sub_request` raises a `RuntimeError` in `mruby_set` and `mruby_set_code`, because nginx does not wait for a subrequest of the rewrite script: call it in a rewrite or access handler, and set the variable there with `Nginx::Var#set`. Since 3.0.0; on 2.x nginx went on without waiting for the variable (see [the release notes of 3.0.0](../releases/v3.0.0.md#nginxasynchttpsub_request-raises-a-runtimeerror-in-an-mruby_set-handler-735)).

When the code waits in `Nginx::Async.sleep`, the directives of the same rewrite script after the `mruby_set` run before the sleep ends, without the value. When the code returns, the variable is set and the request goes on with the next handler of its phase, as without the sleep, so the later phases (`proxy_pass`, a content handler) read the value. A status that the code sets with `Nginx.return` does not end the request, with or without the sleep. Since 3.0.0; on 2.x, a request whose code slept ended without a response, unless an earlier handler of the request had returned `Nginx::DECLINED`, and a status set after the sleep ended the request with that status (see [the release notes of 3.0.0](../releases/v3.0.0.md#an-mruby_set-handler-that-waits-in-nginxasyncsleep-sets-its-variable-and-the-request-goes-on-715)).

## mruby_output_body_filter, mruby_output_body_filter_code, mruby_output_header_filter and mruby_output_header_filter_code

```
Syntax:  mruby_output_body_filter /PATH/TO/YOUR/MRUBY/SCRIPT.rb [cache];
Default: -
Context: server, location
Phase:   
```

```
Syntax:  mruby_output_body_filter_code 'YOUR MRUBY CODE HERE';
Default: -
Context: server, location
Phase:   
```

```
Syntax:  mruby_output_header_filter /PATH/TO/YOUR/MRUBY/SCRIPT.rb [cache];
Default: -
Context: server, location
Phase:   
```

```
Syntax:  mruby_output_header_filter_code 'YOUR MRUBY CODE HERE';
Default: -
Context: server, location
Phase:   
```

The filters are used for processing a response. The header filters are for HTTP header, the body filters are for HTTP body.

A body filter reads the response body with `Nginx::Filter#body` and can replace it with `Nginx::Filter#body=` (or `#output`).
The response then has exactly that body, and `Content-Length` is its length.
Since 2.7.1 this also holds when the body was written with `Nginx.rputs` or `Nginx.echo`; in 2.7.0 such a response kept the length that `Nginx.rputs` had produced, so a replacement body of another length was cut or padded.

A header filter runs before the body has been read.
There `Nginx::Filter#body` returns an empty string and `Nginx::Filter#body=` raises a `RuntimeError` (both since 2.7.1).

`Nginx::Async.sleep` and `Nginx::Async::HTTP.sub_request` raise a `RuntimeError` in both kinds of filter (since 2.7.1), because nginx cannot resume a filter that waits.

## mruby_enable_read_request_body

```
Syntax:  mruby_enable_read_request_body on | off;
Default: off
Context: server, location
Phase:   initialize master process
```

When set to the value on, ngx_mruby reads a HTTP request body before calling mruby code.

Due to nginx event driven nature, a request body is not always read when invoking a handler like mruby_content_handler.
The directive force to read the request body.

When the body is not complete yet, a post-read, server rewrite, rewrite, access or content handler runs once nginx has read the rest of it, and the request then goes on with the later phases, also with a phase handler that waits for a subrequest, such as `auth_request`.
If the client closes the connection or `client_body_timeout` expires first, nginx ends the request and the handler does not run; after `client_body_timeout` nginx closes the connection without a response, and the access log records status 408.
Before 2.7.1, a server rewrite, rewrite or content handler whose body was not complete never ran, and the client got no response; after a post-read or access handler had waited for the body, a later phase handler that waits for a subrequest, such as `auth_request`, was not resumed.

`mruby_set` and `mruby_set_code` handlers, log handlers and header and body filters cannot wait for the rest of the body, because nginx goes on as soon as they return.
They see the body only when it is complete before they run: when an earlier handler or module has read it, or, for HTTP/1.x with a `Content-Length` header, when the whole body is in the buffer that nginx read the request headers into (`client_header_buffer_size`, or a buffer of `large_client_header_buffers` when the headers needed one).
A chunked body, an HTTP/2 or HTTP/3 body, and a body of which only a part is in that buffer count as not complete, even when the rest has already arrived.
Otherwise they run without the body (`Nginx::Request#body` returns `nil`), and ngx_mruby logs that at the `info` level.
A body that a post-read, server rewrite, rewrite, access or content handler is still waiting for does not count as complete either: when nginx ends that read without the rest of the body (the client closes the connection, `client_body_timeout` expires, or nginx answers 400 or 413 to the body), a log handler or a filter that runs afterwards runs at once, without waiting for the rest, and the waiting handler does not run.
`Nginx::Request#body` then returns the part of the body that nginx had read before it ended the read, or `nil` when that part did not fit in `client_body_buffer_size` and nginx had written it to a temporary file.
A later handler that can wait, or a module such as `proxy_pass`, still reads the whole body.
To give these handlers the whole body, read it first in a handler that can wait and runs before them, such as a server-level `mruby_post_read_handler_code`.
Before 2.7.1, such a handler did not run its code when the body was not complete, and the body read that it had started ran the phases of the request again when it completed (since 2.7.1 it runs at once, without waiting for the rest of the body, as described above).

## mruby_upstream_keepalive

```
Syntax:  mruby_upstream_keepalive connections;
Default: -
Context: upstream
Phase:   initialize master process
```

Activates the cache for connections to upstream servers.
It's same as ngx_http_upstream_module's [keepalive](http://nginx.org/en/docs/http/ngx_http_upstream_module.html#keepalive).

TODO: describe the difference between keepalive and mruby_upstream_keepalive.

## mruby_output_filter and mruby_output_filter_code (removed)

Both directives were removed in v1.17.2. `nginx -t` rejects a configuration that has one of them, with the message `mruby_output_filter{,_code} was deleted from v1.17.2, you should use mruby_output_body_filter{,_code} for response body, or use mruby_output_header_filter{,_code} for response headers.`
Use [mruby_output_body_filter and mruby_output_header_filter](#mruby_output_body_filter-mruby_output_body_filter_code-mruby_output_header_filter-and-mruby_output_header_filter_code) instead.

# Stream module directives

The stream module directives run Ruby for TCP and UDP sessions in the `stream {}` block, which has an mruby state of its own.
nginx compiles the code of each directive once, when it reads the configuration.

* [mruby_stream_init and mruby_stream_init_code](#mruby_stream_init-and-mruby_stream_init_code)
* [mruby_stream_init_worker and mruby_stream_init_worker_code](#mruby_stream_init_worker-and-mruby_stream_init_worker_code)
* [mruby_stream_exit_worker and mruby_stream_exit_worker_code](#mruby_stream_exit_worker-and-mruby_stream_exit_worker_code)
* [mruby_stream and mruby_stream_code](#mruby_stream-and-mruby_stream_code)
* [mruby_stream_server_context_code](#mruby_stream_server_context_code)

**nginx.conf**

```nginx
stream {
  mruby_stream_init_code '
    Userdata.new.allowed = ["127.0.0.1"]
  ';

  upstream backend {
    server 127.0.0.1:8080;
  }

  server {
    listen 12346;
    mruby_stream_code '
      c = Nginx::Stream::Connection
      c.stream_status = Nginx::Stream::ABORT unless Userdata.new.allowed.include?(c.remote_ip)
    ';
    proxy_pass backend;
  }
}
```

The guide [Allow TCP connections in Ruby](../guides/tcp.md) has a sample that CI runs.

## mruby_stream_init and mruby_stream_init_code

```
Syntax:  mruby_stream_init /PATH/TO/YOUR/MRUBY/SCRIPT.rb;
Default: -
Context: stream
Phase:   initialize master process
```

```
Syntax:  mruby_stream_init_code 'YOUR MRUBY CODE HERE';
Default: -
Context: stream
Phase:   initialize master process
```

The code runs once while nginx reads the configuration, in the master process, before nginx starts the workers.
Each worker gets a copy of what it leaves in the mruby state of the `stream {}` block.

## mruby_stream_init_worker and mruby_stream_init_worker_code

```
Syntax:  mruby_stream_init_worker /PATH/TO/YOUR/MRUBY/SCRIPT.rb;
Default: -
Context: stream
Phase:   initialize worker process
```

```
Syntax:  mruby_stream_init_worker_code 'YOUR MRUBY CODE HERE';
Default: -
Context: stream
Phase:   initialize worker process
```

The code runs in each worker process when nginx starts it, outside any session.
Session-scoped methods such as `Nginx::Stream::Connection.remote_ip` raise a `RuntimeError` here; `Nginx::Stream.log` writes to nginx's error log.

## mruby_stream_exit_worker and mruby_stream_exit_worker_code

```
Syntax:  mruby_stream_exit_worker /PATH/TO/YOUR/MRUBY/SCRIPT.rb;
Default: -
Context: stream
Phase:   exit worker process
```

```
Syntax:  mruby_stream_exit_worker_code 'YOUR MRUBY CODE HERE';
Default: -
Context: stream
Phase:   exit worker process
```

The code runs in each worker process when nginx stops it, outside any session.

## mruby_stream and mruby_stream_code

```
Syntax:  mruby_stream /PATH/TO/YOUR/MRUBY/SCRIPT.rb;
Default: -
Context: stream, server
Phase:   NGX_STREAM_ACCESS_PHASE
```

```
Syntax:  mruby_stream_code 'YOUR MRUBY CODE HERE';
Default: -
Context: stream, server
Phase:   NGX_STREAM_ACCESS_PHASE
```

The code runs once per session, in the access phase of the stream module, before nginx reads data from the client and before it connects to the upstream of `proxy_pass`.
It reads the session through [Nginx::Stream::Connection](../class_and_method/README.md#nginxstreamconnection-class), and closes the session by setting `Nginx::Stream::Connection.stream_status = Nginx::Stream::ABORT`.
In the `stream` block, the code applies to every `server` that has none of its own.

## mruby_stream_server_context_code

```
Syntax:  mruby_stream_server_context_code 'YOUR MRUBY CODE HERE';
Default: -
Context: server
Phase:   read the configuration, in the master process
```

The code runs once for its `server` block, while nginx reads the configuration.
[`Nginx::Stream.add_listener`](../class_and_method/README.md#nginxstreamadd_listener) adds a `listen` address to the server.

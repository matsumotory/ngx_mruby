# Ruby classes and methods

This is the mruby API documentation for ngx_mruby.

ngx_mruby provides mruby APIs to access and manipulate nginx internal data structure. 
You can use these classes and methods in handlers like `mruby_content_handler_code`.

Available APIs depend on your build configuration.
See [Configuring mrbgems](../install/README.md#2-configuring-mrbgems) and [Build options](../install/README.md#build-options) for the build configuration.

## ngx_mruby HTTP module

The ngx_mruby HTTP module is a nginx module to extend the HTTP server by mruby and the core of ngx_mruby.

__Notice__: `ngx_mruby_mrblib` is a required mrbgem and a part of The HTTP module. The classes and methods provided by `ngx_mruby_mrblib` are documented here.

- [Kernel Module](#kernel-module)
- [Nginx Class](#nginx-class)
- [Nginx::SSL Class](#nginxssl-class)
- [Nginx::Request Class](#nginxrequest-class)
- [Nginx::Server Class](#nginxserver-class)
- [Nginx::Connection Class](#nginxconnection-class)
- [Nginx::Var Class](#nginxvar-class)
- [Nginx::Headers_in Class](#nginxheaders_in-class)
- [Nginx::Headers_out Class](#nginxheaders_out-class)
- [Nginx::Filter Class](#nginxfilter-class)
- [Nginx::Upstream Class](#nginxupstream-class)
- [Nginx::Async Class](#nginxasync-class)
- [Nginx::Async::HTTP Class](#nginxasync-class)

## ngx_mruby stream module

The ngx_mruby stream module is an optional nginx module to handle TCP and UDP stream.

- [Nginx::Stream Class](#nginxstream-class)
- [Nginx::Stream::Connection Class](#nginxstreamconnection-class)
- [Nginx::Stream::Async Class](#nginxstreamasync-class)

## rack-based-api mrbgem 

The rack-based-api mrbgem is an optional bundled mrbgem.
It provides [RACK](https://rack.github.io/) (Ruby Webserver Interface) compatible APIs to make development and testing easier.

- [RACK Compatible API](#rack-compatible-api)

## auto-ssl mrbgem

ngx_mruby 3.0.0 does not have the auto-ssl mrbgem (`Nginx::SSL::ACME::Client`
and `Nginx::SSL::ACME::Dehydrated`). The
[documentation of 2.x](https://github.com/matsumotory/ngx_mruby/blob/v2.7.2/docs/class_and_method/README.md#auto-ssl-mrbgem) describes it, and
[The auto-ssl mrbgem and `NGX_MRUBY_AUTO_SSL` are removed](../releases/v3.0.0.md#the-auto-ssl-mrbgem-and-ngx_mruby_auto_ssl-are-removed-640)
says why it was removed and what to use instead.

# Add classes and methods reference.

## built-in mrbgems

The default build adds the classes of the mrbgems that
[Default mrbgems](../reference/build.md#default-mrbgems) in the build
reference lists, with the class of each gem and a link to the repository
that documents it.

`Dir` comes from the mruby core gem mruby-dir
([mruby/mrbgems/mruby-dir](../../mruby/mrbgems/mruby-dir)). ngx_mruby 2.x took it from
iij/mruby-dir, which the core gem started from; every method of that gem
stays. The differences:

- Reading or closing a closed `Dir` raises `IOError` instead of `RuntimeError`.
- `Dir.open` with a block no longer raises when the block closed the `Dir`.
- `Dir.foreach` with a block closes the `Dir` that it opened.
- `Dir` includes `Enumerable`, and has `Dir.children`, `Dir.empty?` and
  `Dir#each_child`. With the bundled mruby 4.1.0-rc2, `Dir.children` and
  `Dir#each_child` leave out `.` and `..`, as in CRuby. (With mruby 3.3.0
  they were aliases of `Dir.entries` and `Dir#each` and included them.)

The `Redis` class was left out of the default build in 2.7.1 and is in it again since 2.7.2 (see "Redis is in the default build again" in [the 2.7.2 release notes](../releases/v2.7.2.md)).

You can also use the classes of the mruby core gems that `NGX_MRUBY_CORE_GEMS` in
[build_config.rb](../../build_config.rb) lists (the gems in [mruby/mrbgems](../../mruby/mrbgems)
of that name). [Core gems](../install/README.md#core-gems) in the install
guide says which core gems of mruby 4.1.0-rc2 are in the list, which are
left out and why. The changes that the bundled mruby brings to scripts are listed
under [Behavior changes: read before upgrading](../releases/v3.0.0.md#behavior-changes-read-before-upgrading)
in the release notes of v3.0.0, and
[Migrating from ngx_mruby 2.x to 3.0.0](../migration/README.md) has the
steps for finding and changing the scripts that they affect.

# Kernel Module

ngx_mruby HTTP module adds two methods to `Kernel` module. These methods are called without a receiver.
Both are provided to write portable code for [mod_mruby](https://github.com/matsumotory/mod_mruby).

## Module Methods

### get_server_class -> class_object

Returns server software class `Nginx`. 

```ruby
Server = get_server_class

Server.echo "hello world"  # Nginx.echo is called
```

### server_name -> string

Returns server software name `NGINX` as a string.

```ruby
if server_name == "NGINX"
  Server = Nginx
elsif server_name == "Apache" 
  Server = Apache
end
```

# Nginx Class

## Class Methods

### Nginx.rputs(string)

Puts response text.
If a post-read, server rewrite, rewrite, access or content handler raises an exception afterwards, the request gets 500 and the text is not sent, unless the response was already started, for example by the location that `Nginx.redirect` ran.
Since 2.7.1 this also holds for a handler that raises before it waits in `Nginx::Async`; in 2.7.0 such a handler sent the text with status 200.
In an `mruby_set*` handler, a log handler or an output filter, the text is not sent after an exception either, and the request goes on as after an exception without output: `Content-Length` does not count the text (since 2.7.1).
For an `mruby_set*` handler this holds when the code raises before it waits in `Nginx::Async.sleep`. When it raises after the sleep, the request gets 500, as described under [Nginx::Async#sleep](#nginxasyncsleepmsec). `Nginx::Async::HTTP.sub_request` raises a `RuntimeError` in an `mruby_set*` handler (since 3.0.0; on 2.x nginx went on without waiting for the variable, and an exception after the call left the client without a response; see [the release notes of 3.0.0](../releases/v3.0.0.md#nginxasynchttpsub_request-raises-a-runtimeerror-in-an-mruby_set-handler-735)).
To end a content handler early after writing the text, leave it with `return` instead of `raise`.

In a post_read or access handler, the text ends the request: nginx sends the response and does not go on with the phases, with or without `Nginx::Async.sleep` before. Since 3.0.0; on 2.x, such a handler that did not wait sent the response and nginx then went on with the next handlers, and closed the connection when the content phase tried to answer once more (see [the release notes of 3.0.0](../releases/v3.0.0.md#an-access-or-post_read-handler-that-writes-output-ends-the-request-after-the-response-715)).

```ruby
Nginx.rputs "hello ngx_mruby world!"
```

An argument that is not a String is converted with `to_s`, so `Nginx.rputs nil`
writes nothing, as `print nil` does in CRuby. A content handler that writes
nothing and sets no status answers 200 with an empty body (see
[Nginx.return](#nginxreturnnginx_status_code)).

### Nginx.echo(string)

Puts response text with a newline.
Like `Nginx.rputs`, the text is not sent when the handler raises an exception afterwards (since 2.7.1).

```ruby
Nginx.echo "hello ngx_mruby world!"
```

is equal to

```ruby
Nginx.rputs "hello ngx_mruby world!\n"
```

### Nginx.return(nginx_status_code)

Returns [nginx status code](#constants-for-http-status) to send back HTTP status to the client or
control nginx request processing flow. The status code consists of nginx internal status and HTTP status.

```ruby
Nginx.return Nginx::HTTP_SERVICE_UNAVAILABLE  # returns HTTP status 503
```

The value is the result of the handler that calls it, not of the later handlers of the request (since 3.0.0).
A handler that calls none of `Nginx.return`, `Nginx.send_header` and `Nginx.status_code=` has no result, whatever an earlier handler of the request returned: a content handler of the main request without output answers 200 with an empty body (below), and a post_read or access handler goes on as with `Nginx::OK`.
On 2.x, a handler without a result returned the value that an earlier handler of the request had set, for example the `Nginx::DECLINED` of a server rewrite handler that runs for every request, so that a content handler without output went on to the next content handler (see [the release notes of 3.0.0](../releases/v3.0.0.md#a-handler-that-sets-no-result-does-not-take-the-result-of-an-earlier-handler-715)).
A rewrite or server rewrite handler without a result, or with `Nginx::OK`, goes on to the next phase handler, as with `Nginx::DECLINED` (since 3.0.0; on 2.x nginx ended the request without a response, see [the release notes of 3.0.0](../releases/v3.0.0.md#a-rewrite-or-server-rewrite-handler-that-ends-without-a-result-goes-on-to-the-next-phase-handler-720)).
A return code below 0, such as `Nginx::DECLINED`, is the result of the handler only: it does not change the status of the response.

A content handler that ends without output answers as nginx's `return 200;`
does: with the status it set, 200 when it set none, `Content-Length: 0` and an
empty body, and nginx keeps a keep-alive connection for the next request. It
sends no `Content-Type`, as the answers with output do not; nginx's
`return 200;` sends the one of `default_type`. A
request body that no handler read is discarded before the empty answer, as
before an answer with output. This
covers `Nginx::HTTP_OK` and the other statuses from 200 to 299 that nginx does
not answer by itself (for example `Nginx::HTTP_ACCEPTED`), a handler that
writes nothing or only `""` or `nil` with `Nginx.rputs`, and a handler that only
sets response headers. A HEAD request gets the same header, and the output
filters of the location run on the empty response. After a HEAD request to a
location with an mruby output body filter, nginx sends the header and closes
the connection instead of keeping it, as it does there for a handler with
output. nginx answers
`Nginx::HTTP_CREATED`, `Nginx::HTTP_NO_CONTENT` (204 without a body) and the
statuses from 300 up by itself, for example with its error page. A status below
200 without output answers 500 with nginx's error page, and error.log gets a
line at the error level that ends with
`response body is empty. return NGX_HTTP_INTERNAL_SERVER_ERROR`.

```nginx
location /empty {
    mruby_content_handler_code 'Nginx.return Nginx::HTTP_OK';  # 200 with Content-Length: 0
}
```

In the other handlers, for example a rewrite or an access handler,
`Nginx::HTTP_OK` without output answers 500 with nginx's error page and logs
that line. In the content handler of a subrequest
(`Nginx::Async::HTTP.sub_request`, an SSI include, `auth_request`),
`Nginx::HTTP_OK` without output sets the status of the subrequest to 500 and
logs that line too. A content handler of a subrequest that writes nothing and
sets no status or another status below 300 ends the subrequest without a
response body, and the parent request answers.

On the 2.x line, a content handler that ends without output and with no
status or a status from 200 to 299 that nginx does not answer by itself
answers 500 instead (see [docs/releases/v3.0.0.md](../releases/v3.0.0.md)).

A content handler on the main request that writes output with `Nginx.rputs`
or `Nginx.echo` and then calls `Nginx.return` (or `Nginx.send_header`,
`Nginx.status_code=`) answers as follows, also after
`Nginx::Async::HTTP.sub_request` resumed it:

- `Nginx::HTTP_OK`, or another status below 300 other than
  `Nginx::HTTP_CREATED` and `Nginx::HTTP_NO_CONTENT`: the output, with that
  status and `Content-Length` of the output, like nginx's own
  `return 202 "text";` without its `Content-Type`. A status below 200
  goes out the same way, although HTTP does not allow a final response with
  it. `Nginx.return 0` sets no status, and the output gets 200. Since 2.7.2;
  in 2.7.1 these statuses, other than 200, left the client without a
  response.
- `Nginx::HTTP_CREATED`, `Nginx::HTTP_NO_CONTENT` or a status from 300 up:
  nginx's own response for that status, without the output.

A status set before the first `Nginx.rputs` or `Nginx.echo` does not apply to
the output: the response is 200.

```nginx
location /accepted {
    mruby_content_handler_code '
         Nginx.rputs "queued"
         Nginx.return Nginx::HTTP_ACCEPTED  # 202 with the body "queued"
    ';
}
```

In the content handler of a subrequest, a status other than `Nginx::HTTP_OK`
set after output ends the subrequest without a response body, and the parent
request answers.

Don't confuse `Nginx.return` method with mruby's `return` statement.
ngx_mruby supports `return` statement in handler code as below.
It just returns from the handler. Since 3.0.0 this holds also for a `return`
inside a block or the body of `for` at the top level of the code: the code
after it does not run, and the response is the one that the code set before
it (see [the release notes of 3.0.0](../releases/v3.0.0.md#a-return-inside-a-block-or-a-for-body-of-handler-code-ends-the-code-561)).

```nginx
location /foo {
    mruby_content_handler_code '
         Nginx.rputs "foo"            # generates HTTP body "foo"
         Nginx.return Nginx::HTTP_OK  # returns HTTP status 200 
         return if true               # returns from this handler
         Nginx.rputs "bar"            # not reached
    ';
}
```

In 2.x, a `return` inside a block or inside the body of `for` at the top
level of handler code does not return from the handler: mruby 3.3.0, which
2.x bundles, raises `LocalJumpError` (`unexpected return`) there, and
error.log records it as `mrb_run failed`. The handler then fails as after any
other exception: a rewrite or content handler answers 500, and the output
that the code wrote before the `return` is not sent (2.7.0 sent it with 200;
see [Nginx.rputs](#nginxrputsstring)). On both versions, calling
`Nginx.return` in a block does not end the code: it sets the status, and the
code after the block still runs. To end the handler from a block in code
that runs on 2.x as well as on 3.0.0, leave the block with `break` and
`return` at the top level of the code, or put the code in a method (or in a
lambda, `->() do ... end.call`) and call it, so that the `return` returns
from the method or the lambda:

```nginx
location /foo_break {
    mruby_content_handler_code '
         done = false
         ["foo"].each do |body|
           Nginx.rputs body             # generates HTTP body "foo"
           Nginx.return Nginx::HTTP_OK  # returns HTTP status 200
           done = true
           break                        # leaves the block
         end
         return if done                 # returns from this handler
         Nginx.rputs "bar"              # not reached
    ';
}

location /foo_method {
    mruby_content_handler_code '
         def foo
           ["foo"].each do |body|
             Nginx.rputs body             # generates HTTP body "foo"
             Nginx.return Nginx::HTTP_OK  # returns HTTP status 200
             return                       # returns from the method foo
           end
           Nginx.rputs "bar"              # not reached
         end
         foo
    ';
}
```

### Nginx.send_header(nginx_status_code)

Alias for ``Nginx.return``

### Nginx.status_code=(nginx_status_code)

Alias for ``Nginx.return``

### Nginx.errlogger(log_level, string)

Sends an error to the log file via [ngx_log_error()](https://www.nginx.com/resources/wiki/extending/api/logging/#c.ngx_log_error).
The method accepts one of [log levels](#constants-for-log-levels) and a message to send as arguments.

```ruby
Nginx.errlogger Nginx::LOG_ERR, "ngx_mruby error!"
```

You will see an error message in error.log as below.

```
2014/03/03 00:07:09 [error] 37667#0: *2 ngx_mruby error!, client: 192.168.12.9, server: localhost, request: "GET /log-test HTTP/1.1", host: "192.168.12.9:8001"
```

The code of `mruby_init*`, `mruby_init_worker*`, `mruby_exit_worker*`, `mruby_ssl_handshake_handler*` and `mruby_server_context_handler_code` runs outside a request.
There the method writes the message to nginx's error log, without the client and request part (since 2.7.1; 2.7.0 raised a `RuntimeError` when the process had not handled a request yet, and otherwise wrote through the last request that the process had handled).

Code outside a request can also call `Nginx.module_name`, `Nginx.module_version`, `Nginx.nginx_version`, `Nginx.server_version`, `Nginx.configure`, `Nginx.remove_global_variable` and `server_name`, use the constants, and use classes that do not depend on a request, such as `Userdata`.
Since 2.7.1 the request-scoped methods raise a `RuntimeError` (`this method can only be used while processing a request`) there: the methods of `Nginx::Request`, `Nginx::Var`, `Nginx::Headers_in`, `Nginx::Headers_out`, `Nginx::Connection`, `Nginx::Server`, `Nginx::Filter`, `Nginx::Upstream` and `Nginx::Async`, and `Nginx.rputs`, `Nginx.echo`, `Nginx.return`, `Nginx.send_header`, `Nginx.status_code=` and `Nginx.redirect`.
In 2.7.0 they crashed the process when it had not handled a request yet, and otherwise returned or changed data of the last request that the process had handled.
`Nginx::Server#add_listener` works only in `mruby_server_context_handler_code`, and `Nginx::SSL` only in `mruby_ssl_handshake_handler*`.

### Nginx.log(log_level, string)

Alias for Nginx.errlogger.
Outside a request it writes to nginx's error log, as described under `Nginx.errlogger` (since 2.7.1).

### Nginx.module_name -> string

Returns module name `ngx_mruby`.

```ruby
Nginx.echo Nginx.module_name #=> ngx_mruby
```

### Nginx.module_version -> string

Returns ngx_mruby version as a string.

```ruby
Nginx.echo Nginx.module_version #=> 0.0.1
```

### Nginx.nginx_version -> string

Returns nginx version as a string.

```ruby
Nginx.echo Nginx.nginx_version #=> 1.4.4
```

### Nginx.server_version -> string

Returns server software version as a string. Alias for ``Nginx.nginx_version``.
It's provided to write portable code for [mod_mruby](https://github.com/matsumotory/mod_mruby).

### Nginx.configure -> string

Returns nginx build configuration as a string. It's same as output of `nginx -V` configure arguments.

```ruby
Nginx.echo Nginx.configure #=>  --add-module=/home/matsumoto_r/DEV/ngx_mruby \
                           #    --add-module=/home/matsumoto_r/DEV/ngx_mruby/dependence/ngx_devel_kit \
                           #    --prefix=/usr/local/nginx-1.4.4
```

### Nginx.redirect(url_or_internal_location, http_status=Nginx::HTTP_MOVED_TEMPORARILY)

Redirects to the URL or the internal location. It is designed to be used in the rewrite handlers.

The URL redirect returns HTTP status codes 3xx like `307 Temporary Redirect` with `Location` header to the client.

```ruby
Nginx.redirect "http://ngx.mruby.org/", Nginx::HTTP_MOVED_PERMANENTLY
```

The internal redirect never returns response to the client. The original request is internally forwarded to
other location, then the location returns to a response to the client.
See [error_page](http://nginx.org/en/docs/http/ngx_http_core_module.html#error_page) and
[internal](http://nginx.org/en/docs/http/ngx_http_core_module.html#internal) directives, and
[Creating NGINX Rewrite Rules](https://www.nginx.com/blog/creating-nginx-rewrite-rules/) for more about the internal redirect.

In a post_read, server rewrite, rewrite, access or content handler, the internal redirect takes effect when the handler ends (since 3.0.0): the code after the call runs first, and then nginx runs the phases of the other location, whose handlers answer the request and can wait like any handler.
The output and the status that the handler writes or sets are not sent; when the code writes output or sets a status after the call, error.log gets a line at the warn level that ends with `set after Nginx.redirect are not sent`.
Response headers that the handler sets, and changes that it makes to the request such as its arguments (`Nginx::Request#args=`), stay, also after the call: the answer of the other location carries those headers, and that location sees those arguments.
When the handler raises an exception, the request gets 500, and the redirect does not take effect.
When an mruby handler or filter of the other location raises an exception, the exception ends that handler as it does without the redirect: the request gets 500 unless its response was already started.
On 2.x the internal redirect ran the handlers of the other location before the call returned, and the calling handler went on after the call and could answer the request as well (see [the release notes of 3.0.0](../releases/v3.0.0.md#nginxredirect-with-a-local-uri-takes-effect-when-the-handler-ends-728)).
In an `mruby_set*` handler, a log handler or a filter, the internal redirect still runs before the call returns.

```nginx
location /secret-location {
  internal;
  mruby_content_handler_code '
    r = Nginx::Request.new
    Nginx.echo "Returns from /secret-location."
    Nginx.return Nginx::HTTP_OK
  ';
}

location /public-location {
  mruby_content_handler_code '
    Nginx.redirect "/secret-location"
  ';
}
```

### Nginx.remove_global_variable

Removes a mruby's global variable.

```ruby
$a = 1
Nginx.echo global_variables #=> [:$stdout, :$$, :$/, :$stdin, :$?, :$a, :$stderr, :$1, :$2, :$3, :$4, :$5, :$6, :$7, :$8, :$9]
Nginx.remove_global_variable :$a
Nginx.echo global_variables #=> [:$stdout, :$$, :$/, :$stdin, :$?, :$stderr, :$1, :$2, :$3, :$4, :$5, :$6, :$7, :$8, :$9]
```

## Constants

### Constants for log levels

Log levels for `Nginx.errlogger` that mirror nginx error log levels.
See [nginx log levels](https://www.nginx.com/resources/wiki/extending/api/logging/#ngx-log-error) and 
[core/ngx_log.h](https://github.com/nginx/nginx/blob/master/src/core/ngx_log.h).

Name|Description
-----|-----------
Nginx::LOG_STDERR|Defined in core/ngx_log.h, but it's never used
Nginx::LOG_EMERG|Emergency error log level
Nginx::LOG_ALERT|Alert error log level
Nginx::LOG_CRIT|Critical error log level
Nginx::LOG_ERR|Error log level
Nginx::LOG_WARN|Warning log level
Nginx::LOG_NOTICE|Notice log level
Nginx::LOG_INFO|Information log level
Nginx::LOG_DEBUG|Debug log level

### Constants for HTTP status

HTTP status and internal nginx status for `Nginx.return`.
See nginx [HTTP Return Codes](https://www.nginx.com/resources/wiki/extending/api/http/) for the HTTP statuses.
The statuses from `Nginx::OK` (0) to `Nginx::ABORT` (-6) are internally used to control nginx processing flow.
They are defined in [core/ngx_core.h](https://github.com/nginx/nginx/blob/master/src/core/ngx_core.h).

Name|Value
-----|-----------
Nginx::OK|0
Nginx::ERROR|-1
Nginx::AGAIN|-2
Nginx::BUSY|-3
Nginx::DONE|-4
Nginx::DECLINED|-5
Nginx::ABORT|-6
Nginx::HTTP_CONTINUE|100
Nginx::HTTP_SWITCHING_PROTOCOLS|101
Nginx::HTTP_PROCESSING|102
Nginx::HTTP_OK|200
Nginx::HTTP_CREATED|201
Nginx::HTTP_ACCEPTED|202
Nginx::HTTP_NO_CONTENT|204
Nginx::HTTP_PARTIAL_CONTENT|206
Nginx::HTTP_SPECIAL_RESPONSE|300
Nginx::HTTP_MOVED_PERMANENTLY|301
Nginx::HTTP_MOVED_TEMPORARILY|302
Nginx::HTTP_SEE_OTHER|303
Nginx::HTTP_NOT_MODIFIED|304
Nginx::HTTP_TEMPORARY_REDIRECT|307
Nginx::HTTP_BAD_REQUEST|400
Nginx::HTTP_UNAUTHORIZED|401
Nginx::HTTP_FORBIDDEN|403
Nginx::HTTP_NOT_FOUND|404
Nginx::HTTP_NOT_ALLOWED|405
Nginx::HTTP_REQUEST_TIME_OUT|408
Nginx::HTTP_CONFLICT|409
Nginx::HTTP_LENGTH_REQUIRED|411
Nginx::HTTP_PRECONDITION_FAILED|412
Nginx::HTTP_REQUEST_ENTITY_TOO_LARGE|413
Nginx::HTTP_REQUEST_URI_TOO_LARGE|414
Nginx::HTTP_UNSUPPORTED_MEDIA_TYPE|415
Nginx::HTTP_RANGE_NOT_SATISFIABLE|416
Nginx::HTTP_TOO_MANY_REQUESTS|429
Nginx::HTTP_CLOSE|444
Nginx::HTTP_NGINX_CODES|494
Nginx::HTTP_REQUEST_HEADER_TOO_LARGE|494
Nginx::HTTPS_CERT_ERROR|495
Nginx::HTTPS_NO_CERT|496
Nginx::HTTP_TO_HTTPS|497
Nginx::HTTP_CLIENT_CLOSED_REQUEST|499
Nginx::HTTP_INTERNAL_SERVER_ERROR|500
Nginx::HTTP_NOT_IMPLEMENTED|501
Nginx::HTTP_BAD_GATEWAY|502
Nginx::HTTP_SERVICE_UNAVAILABLE|503
Nginx::HTTP_GATEWAY_TIME_OUT|504
Nginx::HTTP_INSUFFICIENT_STORAGE|507

# Nginx::SSL Class

Nginx::SSL class is designed to be used in the ssl handshake handlers.
Since 2.7.1 its methods raise a `RuntimeError` when they are called anywhere else, for example in `mruby_content_handler_code`; in 2.7.0 such a call could crash the worker or return meaningless values.
A handshake whose code sets no certificate, also one whose code does not call `Nginx::SSL.new`, uses the server's `ssl_certificate` and `ssl_certificate_key` (since 2.7.1; in 2.7.0 a handshake whose code did not call `Nginx::SSL.new` could get the certificate that an earlier handshake on the same worker had set, or fail).

## Instance Methods

### Nginx::SSL#servername -> string

Returns the SNI server name from the client.
The client chooses this name, Treat it as untrusted input (see [Trust boundary](../security/trust-boundary.md)): look it up in a table of known names, and do not build a path from it.

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

The lookup is exact: the name is compared as the client sent it, including its case. A name that is not in `CERT_DIRS`, also an empty name from a client that sends none, keeps the certificate of `ssl_certificate` and `ssl_certificate_key`.

### Nginx::SSL#certificate=(string)

Sets the certificate file path used for the connection.
The worker reads the file during the handshake.
Take the path from a table, not from the server name.

```nginx
mruby_ssl_handshake_handler_code '
  ssl = Nginx::SSL.new
  dir = CERT_DIRS[ssl.servername]
  if dir
    ssl.certificate = "#{dir}/cert.pem"
    ssl.certificate_key = "#{dir}/key.pem"
  end
';
```

`CERT_DIRS` is the table of the example under [`servername`](#nginxsslservername---string).

### Nginx::SSL#certificate_key=(string)

Sets the certificate key file path used for the connection.
Set it together with `certificate=`; the handshake changes the certificate only when both are set.
Take the path from a table, not from the server name.

```nginx
mruby_ssl_handshake_handler_code '
  ssl = Nginx::SSL.new
  dir = CERT_DIRS[ssl.servername]
  if dir
    ssl.certificate = "#{dir}/cert.pem"
    ssl.certificate_key = "#{dir}/key.pem"
  end
';
```

`CERT_DIRS` is the table of the example under [`servername`](#nginxsslservername---string).

### Nginx::SSL#certificate_data=(string)

Sets the certificate data used for the connection, as a string in PEM format (the certificate, then its chain).
Read the files once in the init code, so that the handshake does not read a file, and look the data up by server name.
The init code runs once, so a certificate that changes on disk reaches the handshake after `nginx -s reload`.

```nginx
http {
    mruby_init_code '
        CERT_DATA = {}
        ["example.com", "www.example.com"].each do |name|
          CERT_DATA[name] = [
            File.read("/etc/nginx/certs/#{name}/cert.pem"),
            File.read("/etc/nginx/certs/#{name}/key.pem"),
          ]
        end
    ';

    server {
        listen 443 ssl;
        ssl_certificate     /etc/nginx/certs/default.crt;
        ssl_certificate_key /etc/nginx/certs/default.key;

        mruby_ssl_handshake_handler_code '
          ssl = Nginx::SSL.new
          data = CERT_DATA[ssl.servername]
          if data
            ssl.certificate_data = data[0]
            ssl.certificate_key_data = data[1]
          end
        ';
    }
}
```

### Nginx::SSL#certificate_key_data=(string)

Sets the certificate key data used for the connection, as a string in PEM format.
Set it together with `certificate_data=`; the handshake changes the certificate by data only when both are set, and then it does not use the paths.

```nginx
mruby_ssl_handshake_handler_code '
  ssl = Nginx::SSL.new
  data = CERT_DATA[ssl.servername]
  if data
    ssl.certificate_data = data[0]
    ssl.certificate_key_data = data[1]
  end
';
```

`CERT_DATA` is the table of the example under [`certificate_data=`](#nginxsslcertificate_datastring).

### Nginx::SSL.errlogger(log_level, string)

Sends an error to the log file via [ngx_log_error()](https://www.nginx.com/resources/wiki/extending/api/logging/#c.ngx_log_error).
The method accepts one of [log levels](#constants-for-log-levels) and a message to send as arguments.

```ruby
Nginx::SSL.errlogger Nginx::LOG_ERR, "ngx_mruby error!"
```

### Nginx::SSL.log(log_level, string)

Alias for Nginx::SSL.errlogger

### Nginx::SSL#local_port -> integer

Returns the port number used for the connection. 

```nginx

mruby_ssl_handshake_handler_code '
  ssl = Nginx::SSL.new
  Userdata.new.ssl_local_port = ssl.local_port
';

location /local_port {
     mruby_content_handler_code "Nginx.rputs Userdata.new.ssl_local_port.to_s";
}
```

### Nginx::SSL#tls_version -> string

Returns the name of the protocol like `TLSv1.3` used for the connection. 
This is a wrapper for SSL_get_version(). See [SSL_get_version(3)](https://www.openssl.org/docs/man1.1.1/man3/SSL_get_version.html) for the return values.

```nginx
mruby_ssl_handshake_handler_code '
  ssl = Nginx::SSL.new
  Userdata.new.ssl_tls_version = ssl.tls_version
';

location /tls_version {
    mruby_content_handler_code "Nginx.rputs Userdata.new.ssl_tls_version.to_s";
}
```

# Nginx::Request Class

## Instance Methods

### Nginx::Request#scheme -> string

Returns the scheme name of the requested URL.

```ruby
# curl https://127.0.0.1/

r = Nginx::Request.new
r.scheme #=> https
```

### Nginx::Request#content_type=(string)

Set the content type to the *response*.

__Notice__: Unlike the name suggests, `Nginx::Request#content_type=()` and `Nginx::Request#content_type()` handle HTTP response, not request.

```nginx
location /foo {
  mruby_content_handler_code '
    r = Nginx::Request.new
    r.content_type = "text/plain"
    Nginx.rputs "This is a plain text"
  ';
}
```

```bash
% curl -v http://127.0.0.1:58080/foo

[snip]

< HTTP/1.1 200 OK
< Date: Thu, 29 Nov 2018 07:55:22 GMT
< Content-Type: text/plain
< Content-Length: 20
< Connection: keep-alive
< hoge: fuga
< Server: global_ngx_mruby
<
* Connection #0 to host 127.0.0.1 left intact
This is a plain text
```

### Nginx::Request#content_type -> string

Returns the content type of the *response*.

```ruby
r = Nginx::Request.new
r.content_type = "text/plain"

# Do some other things

Nginx.echo r.content_type #=> text/plain
```

### Nginx::Request#request_line -> string

Returns the HTTP request line.

```ruby
# curl http://127.0.0.1/hello?a=1

r = Nginx::Request.new
Nginx.echo r.request_line #=> GET /hello?a=1 HTTP/1.1
```

### Nginx::Request#request_line=(string)

Sets the string to the HTTP request line.

```ruby
r = Nginx::Request.new
Nginx.echo r.request_line = 'GET /hello?a=1&b=1 HTTP/1.1'
```

### Nginx::Request#sub_request? -> true or false

Return true if the request is a sub request.

nginx provides a mechanism to internally send a sub request when received a request.
See [Authentication Based on Subrequest Result](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/) for how it works.

```ruby
r = Nginx::Request.new

# location / { mruby_content_handler /path/to/hook.rb; }
Nginx.echo r.sub_request?.to_s #=> "false"
```

### Nginx::Request#uri -> string

Returns an URI without the query parameters in the HTTP request line.

```ruby
# curl http://127.0.0.1/hello?a=1

r = Nginx::Request.new
Nginx.echo r.uri #=> /hello
```

### Nginx::Request#uri=(string)

Set the string to uri.

```
r = Nginx::Request.new
Nginx.echo r.uri = "/foo"
```

### Nginx::Request#unparsed_uri -> string

Returns an URI in the original HTTP request line.

```ruby
# curl http://127.0.0.1/hello?a=1

r = Nginx::Request.new
Nginx.echo r.unparsed_uri #=> /hello?a=1
```

### Nginx::Request#unparsed_uri=(string)

Sets the string to unparsed_uri.

```ruby
r = Nginx::Request.new
Nginx.echo r.unparsed_uri = "/hello?a=1"
```

### Nginx::Request#method -> string

Returns the HTTP method of the request as a string like `GET`.

```ruby
# curl http://127.0.0.1/hello?a=1

r = Nginx::Request.new
Nginx.echo r.method #=> GET
```

### Nginx::Request#method=(string)

Sets the string to method.

```ruby
r = Nginx::Request.new
Nginx.echo r.method = "POST"
```

### Nginx::Request#protocol -> string

Returns the request protocol of the request like `HTTP/1.1`.

```ruby
# curl http://127.0.0.1/hello?a=1

r = Nginx::Request.new
Nginx.echo r.protocol #=> HTTP/1.1
```

### Nginx::Request#protocol=(string)

Sets the string to the request protocol

```ruby
# curl http://127.0.0.1/hello?a=1

r = Nginx::Request.new
Nginx.echo r.protocol = "HTTP/1.0"
```

### Nginx::Request#args -> string

Returns the URL query parameters.
See [Nginx::Request#uri_args](#nginxrequesturi_args---hash) if you need parsed query parameters.

```ruby
# curl http://127.0.0.1/hello?a=1&b=2

r = Nginx::Request.new
Nginx.echo r.args #=> a=1&b=2
```

### Nginx::Request#args=(string)

Sets the string to args.

```ruby
r = Nginx::Request.new
Nginx.echo r.args "a=10&b=20"
```

### Nginx::var -> var

Returns a Var instance of the request.
See [Nginx::Var Class](#nginxvar-class) for more details.

```ruby
r = Nginx::Request.new
v = r.var
v.exist? "foo" #=> false
```

### Nginx::Request#headers_in -> headers_in

Returns a Headers_in instance of the request.
See [Nginx::Headers_in Class](#nginxheaders_in-class) for more details.

```ruby
r = Nginx::Request.new
headers = r.headers_in
headers["User-Agent"] #=> curl/7.52.1
```

### Nginx::Request#headers_out -> headers_out

Returns a Headers_out instance of the request.
See [Nginx::Headers_out Class](#nginxheaders_out-class) for more details.

```ruby
r = Nginx::Request.new
headers = r.headers_out
headers["X-Request-Id"] = r.var.request_id
```

### Nginx::Request#hostname -> string

Returns the host name. It's same as nginx variable `$host`. 
Therefore, the order of precedence is: host name in the request line, 
host name in `Host` HTTP request header, or server name defined in nginx.conf.

```ruby
# curl http://127.0.0.1:8001/hello?a=1 

r = Nginx::Request.new
Nginx.echo r.hostname #=> "127.0.0.1"
```

### Nginx::Request#authority -> string

Returns authority without userinfo.

```ruby
# curl -v http://127.0.0.1:8001/hello?a=1

r = Nginx::Request.new
Nginx.echo r.authority #=> "127.0.0.1:8001"
```

### Nginx::Request#filename -> string

Returns the requested filename. It's same as nginx variable `$request_filename`.

```ruby
# curl -v http://127.0.0.1/hello?a=1

r = Nginx::Request.new
Nginx.echo r.filename #=> /usr/local/nginx-1.4.4/html/hello
```

### Nginx::Request#user -> string

Returns the user name of the Basic authentication.

```ruby
# curl http://127.0.0.1/hello?a=1 -u matsumoto_r

r = Nginx::Request.new
Nginx.echo r.user #=> matsumoto_r
```

### Nginx::Request#read_body -> integer 

Does nothing and always returns Nginx::OK. It is only for backward compatibility. 

### Nginx::Request#get_body -> string

Returns the request body as a string.

__Notice__: If you want to use the the method, you must use `mruby_enable_read_request_body` directive in nginx.conf to force reading the request body as below.

```nginx
location /foo {
  mruby_enable_read_request_body on;          # Force reading the request body 
  mruby_access_handler_code '
    req = Nginx::Request.new
    body = req.get_body                       # Get the body
    Nginx.log Nginx::LOG_ERR, "body:#{body}"
    Userdata.new.req_body = body              # Set the body to Userdata used in the content handler
  ';
  mruby_content_handler_code '
    Nginx.rputs Userdata.new.req_body
  ';
}
```

### Nginx::Request#body -> string

Alias for Nginx::Request#get_body.

### Nginx::Request#document_root -> string

Returns the document root directory. It is configured by `root` directive. 
See the [ngx_http_core_module documentation](http://nginx.org/en/docs/http/ngx_http_core_module.html#root) for the directive.

```ruby
r = Nginx::Request.new
r.document_root #=> /usr/local/nginx-1.4.4
```

### Nginx::Request#uri_args -> hash

Returns the URL query parameters as a hash.

```ruby
# curl http://127.0.0.1/hello?a=1&b=2

r = Nginx::Request.new
Nginx.echo r.uri_args #=> {"a" => "1", "b" => "2"}
```

### Nginx::Request#uri_args=(hash)

Set the hash to uri_args.

```ruby
r = Nginx::Request.new
r.uri_args = {"a" => "10", "b" => "20"}
```

### Nginx::Request#post_args -> hash

Returns the request body as a hash. 
The method assume the content type is `application/x-www-form-urlencoded`.

```ruby
# curl http://127.0.0.1/hello?a=1&b=2

r = Nginx::Request.new
Nginx.echo r.uri_args #=> {"a" => "1", "b" => "2"}
```

## Return value examples of the URL related methods

Here is the return value examples of the above URL related methods.
if you send a HTTP/1.1 GET request to https://user:pass@api.example.com:8080/foo?a=1&b=2,
you will get the following values.

Method|Return Value
------|-----------
scheme|https
request_line|GET /foo?a=1&b=2 HTTP/1.1
uri|/foo
unparsed_uri |/foo?a=1&b=2
method|GET
protocol|HTTP/1.1
args|foo?a=1&b=2
hostname|api.example.com
authority|api.example.com:8080
filename|/path/to/document/root/foo
user|user
uri_args|{"a" => "1", "b" => "2"}
document_root|/path/to/document

# Nginx::Server Class

## Instance Methods

### Nginx::Server#add_listener(hash)

Create a listener on the specified IP address and the port in the hash.
The method works only in `mruby_server_context_handler_code`, while nginx reads the configuration.
Anywhere else, for example in a request handler, it raises a `RuntimeError` (`add_listener can only be used in mruby_server_context_handler_code`, since 2.7.1).

```ruby
s = Nginx::Server.new
s.add_listener({address: "127.0.0.1:58101"})
s.add_listener({address: "58102"})
s.add_listener({address: "58103", ssl: true})
```

Here is an example to create multiple listeners on port 20001 to 30000.

```nginx
http {
    server {
        mruby_server_context_handler_code '
          s = Nginx::Server.new
          (20001..30000).each { |port| s.add_listener({address: port.to_s}) }
        ';

        location /mruby {
          mruby_content_handler_code '
            Nginx.rputs "Hello on port #{Nginx::Connection.new.local_port}"
          ';
        }
    }
}
```

### Nginx::Server#document_root

Returns the document root directory.

```ruby
# curl http://127.0.0.1:8001/hello?a=1

s = Nginx::Server.new
Nginx.echo s.document_root # => /usr/local/nginx-1.4.4/html
```

### Nginx::Server#realpath_root

Returns the document root directory with symlinks resolved to real paths.
It's same as nginx variable `$realpath_root`.

```ruby
# curl http://127.0.0.1:8001/hello?a=1

s = Nginx::Server.new
Nginx.echo s.realpath_root # => /usr/local/nginx-1.4.4/html
```

### Nginx::Server#path

Alias for Nginx::Server#realpath_root.

# Nginx::Connection Class

## Instance Methods

### Nginx::Connection#remote_ip

Returns the client IP address. It's same as nginx variable `$remote_addr`.

```ruby
# curl http://192.168.0.2:8001/hello?a=1 on 192.168.0.1

c = Nginx::Connection.new
Nginx.echo c.remote_ip # => 192.168.0.1
```

### Nginx::Connection#remote_port

Return the client port number. It's same as nginx variable `$remote_port`.

```ruby
# curl http://192.168.0.2:8001/hello?a=1 on 192.168.0.1

c = Nginx::Connection.new
Nginx.echo c.remote_port # => 54430
```

### Nginx::Connection#local_ip

Returns the IP address that accepts the request. It's same as nginx variable `$server_addr`.

```ruby
# curl http://192.168.0.2:8001/hello?a=1 on 192.168.0.1

c = Nginx::Connection.new
Nginx.echo c.local_ip # => 192.168.0.2
```

### Nginx::Connection#local_port

Returns the port number that accepts the request. It's same as nginx variable `$server_port`.

```ruby
# curl http://192.168.0.2:8001/hello?a=1 on 192.168.0.1

c = Nginx::Connection.new
Nginx.echo c.local_port # => 8001
```

# Nginx::Var Class

nginx supports embedded variables such as `$http_host`. 
You can get or set the variables via Var class.
See [Embedded Variables](http://nginx.org/en/docs/http/ngx_http_core_module.html#variables) for 
variables supported by the ngx_http_core_module.

You can use Var instance as below.

```ruby
v = Nginx::Var.new
Nginx.echo "$http_host core variable is #{v.http_host}"
v.http_host = "192.168.0.1"
Nginx.echo "$http_host is overridden to #{v.http_host}"
```

Also you can use your own variable.

__Notice__: You must use `set` or `mruby_set_code` directive to define the variable within the accessible context in nginx.conf. You can *NOT* add a new variable from mruby code.

```
location /foo {
  set $backend_user = "foo"
  mruby_set_code $auth '
    r = Nginx::Request.new
    backend_user = r.var.backend_user
    backend_pass = lookup_pass_for(user)
    'Basic ' + [backend_user + ':' + backend_pass].pack('m0')
  ';
  proxy_set_header Authorization $auth;
  proxy_pass  http://backend.example.com;
}
```

## Instance Methods

### Nginx::Var#method_missing(symbol [, *args]) -> result

It is designed for providing accessor to nginx variable.
The method is called when `Nginx::Var#VARNAME` or `Nginx::Var#VARNAME=` is evaluated.
Set the 2nd arg to the variable if the symbol ends with `=`. Otherwise, returns the value.

The variable is looked up by the name in lowercase. Since 2.7.2, a name that is empty or made only of `=` raises `NoMethodError`, and a setter called without a value raises `ArgumentError` and leaves the variable as it was.

Since 3.0.0, the first `v.NAME` or `v.NAME = value` of a name in a worker process also defines the accessor as a method of `Nginx::Var`, and the later accesses of that name in the worker call the method instead of `method_missing`. The method reads and writes the variable as `method_missing` does: the same values, `nil` for a name that is not a variable, the same exceptions and the same lines in `error.log`. A worker defines:

- a getter and a setter for each declared variable that scripts use: the variables of nginx and its modules, and the ones that `set` declares;
- a getter for the first 16 names of prefix variables that scripts use, the variables whose names start with a prefix that nginx defines, such as `arg_`, `http_`, `cookie_` and `upstream_http_`. Any suffix makes such a name, so a worker keeps at most 16 of them.

Only a name in lowercase gets a method: the name has to be made of `a` to `z`, `0` to `9` and `_` (with `=` at the end for a setter). `v.Request_Method` reads `$request_method` through `method_missing` and defines nothing. No method is defined for a name that is not a variable, for a setter of a prefix variable, for an instance of a subclass of `Nginx::Var`, when `Nginx::Var` is frozen, or when `Nginx::Var` or one of its ancestors already has a method of that name.

The defined methods show in introspection: after the first `v.request_method` in a worker, `v.respond_to?(:request_method)` returns `true` and `Nginx::Var.instance_methods(false)` lists `request_method`. What they show depends on the requests that the worker has served, so two workers can answer differently. To tell whether a variable exists, use `Nginx::Var#exist?`. Once the method exists, a method of the same name that a script defines later on `Object` or `Kernel`, for example with a `def` at the top level of handler code, no longer hides the variable from `v.NAME`.

`Nginx::Connection#remote_ip`, `#remote_port`, `#local_ip` and `#local_port`, `Nginx::Server#document_root`, `#realpath_root` and `#path`, and `Nginx::Request#hostname`, `#authority`, `#filename`, `#user` and `#get_body` read their variables from nginx directly. Since 3.0.0, a method that a script defines on `Nginx::Var` does not change what they return.

### Nginx::Var#set(name, value)

Set the value to the nginx variable.

`name` is looked up in lowercase. Since 2.7.2, `set` does not change the String or Symbol passed as `name`.

```ruby
v = Nginx::Request.new.var
v.set "backend", "http://192.168.0.9/"  # Set "http://192.168.0.9/" to $backend
```

A `name` or a `value` that is not a String is converted with `to_s`. When `to_s` is missing, raises, or returns an object that is not a String, `set` raises that exception (a `TypeError` for the object that is not a String), and so does `Nginx::Var#<name>=`.

## Nginx::Var#.exist? -> true or false

Returns true if the variable is defined.
If `backend` variable is not defined in nginx.conf, you will get false.

```ruby
v = Nginx::Request.new.var
v.exist? "backend" # => false
```

# Nginx::Headers_in Class

Headers_in class stores HTTP request headers.
The name comes from [ngx_http_headers_in_t](https://www.nginx.com/resources/wiki/extending/api/http/#ngx-http-headers-in-t).

## Instance Methods

### Nginx::Headers_in#\[\](string) -> string

Returns the value of the http request header.

```ruby
hin = Nginx::Headers_in.new
Nginx.rputs hin["User-Agent"] #=> curl/7.29.0
```

### Nginx::Headers_in#[]=(string, string)

Sets the value to the http request header.

```ruby
hin = Nginx::Headers_in.new
Nginx.rputs hin["User-Agent"] #=> curl/7.29.0

hin["User-Agent"] = "test-agent"
Nginx.rputs hin["User-Agent"] #=> test-agent
```

### Nginx::Headers_in#all -> hash

Returns the all http request headers.

```ruby
hin = Nginx::Headers_in.new

hin.all.keys.each do |k|
  Nginx.echo "#{k}: #{hin[k]}"
end
```

```
$ curl http://127.0.0.1:8001/hello
#Host: 127.0.0.1:8001
#User-Agent: curl/7.29.0
#Accept: */*
```

### Nginx::Headers_in#delete(string)

Delete the field from the http request headers.

```ruby
hin = Nginx::Headers_in.new
hin["X-Remove-Header"] = "to be deleted!"
hin.delete("X-Remove-Header")
Nginx.rputs hin["X-Remove-Header"] #=> nil
```

# Nginx::Headers_out Class

Headers_out class stores HTTP response headers.
The name comes from [ngx_http_headers_out_t](https://www.nginx.com/resources/wiki/extending/api/http/#ngx-http-headers-out-t).

## Instance Methods

### Nginx::Headers_out#\[\](string) -> string

Returns the value of the http response header.

```ruby
hout = Nginx::Headers_out.new
hout["X-NGX-MRUBY"] = "support"
Nginx.rputs hout["X-NGX-MRUBY"] #=> support
```

### Nginx::Headers_out#[]=(string, string)

Sets the value to the http response header.

```ruby
hout = Nginx::Headers_out.new
hout["X-NGX-MRUBY"] = "support"
Nginx.rputs hout["X-NGX-MRUBY"] #=> support
```

### Nginx::Headers_out#all -> hash

Returns the all http response headers.

```ruby
hout = Nginx::Headers_out.new

hout["X-NGX-MRUBY"] = "support"
hout.all.keys.each do |k|
  Nginx.echo "#{k}: #{hout[k]}"
end
```

```
$ curl -v http://192.168.12.9:8001/hello?a=1
#X-NGX-MRUBY: support
```

### Nginx::Headers_out#delete(string)

Delete the field from the http response headers.

```ruby
hout = Nginx::Headers_out.new
hout["X-Remove-Header"] = "to be deleted!"
hout.delete("X-Remove-Header")
Nginx.rputs hout["X-Remove-Header"] #=> nil
```

# Nginx::Filter Class

Nginx::Filter class is designed to be used in the output body handlers.
Before the body filter has read the body, `Nginx::Filter#body` returns an empty string: in a content handler, as before, and in a header filter (since 2.7.1).
Outside an output body filter, `Nginx::Filter#body=` and `#output` raise a `RuntimeError` (since 2.7.1).

__Notice__: You can *NOT* use `Nginx.rputs` and `Nginx.echo` in the output header and body handlers
(`mruby_output_header_filter`, `mruby_output_body_filter` and their `_code` forms).

Here is an example how it works.

```nginx
location /foo {
  return 200 hello;
}

location /bar {
  mruby_output_header_filter_code '
    Nginx::Request.new.headers_out["X-Filter"] = "on"
  ';
  mruby_output_body_filter_code '
    f = Nginx::Filter.new
    f.body = f.body.upcase
  ';
  return 200 hello;
}
```

```bash
$ curl -v http://127.0.0.1:59090/foo

[snip]

< HTTP/1.1 200 OK
< Server: nginx/1.15.7
< Date: Wed, 05 Dec 2018 06:27:19 GMT
< Content-Type: text/plain
< Content-Length: 5
< Connection: keep-alive
< 
* Connection #0 to host 127.0.0.1 left intact
hello
```

```bash
$ curl -v http://127.0.0.1:59090/bar

[snip]

< HTTP/1.1 200 OK
< Server: nginx/1.15.7
< Date: Wed, 05 Dec 2018 06:27:24 GMT
< Content-Type: text/plain
< Content-Length: 5
< Connection: keep-alive
< X-Filter: on
< 
* Connection #0 to host 127.0.0.1 left intact
HELLO
```

## Instance Methods

### Nginx::Filter#body -> string

Returns the response body.
In a header filter, which runs before the body has been read, it returns an empty string (since 2.7.1; 2.7.0 returned a string as long as `Content-Length` whose bytes were not the body, or raised an `ArgumentError` when the length was unknown or 10 MB or more).
To learn the length there, call `Nginx::Var.new.sent_http_content_length`, which reads the variable.

```ruby
f = Nginx::Filter.new
response = f.body.upcase
```

### Nginx::Filter#body=(string)

Sets the string to the response body.
The response is sent with exactly this body, and `Content-Length` is its length; since 2.7.1 this also holds when the body was written with `Nginx.rputs` or `Nginx.echo`.
It can only be used in an output body filter; anywhere else it raises a `RuntimeError` (since 2.7.1).

```ruby
f = Nginx::Filter.new
f.body = "The original body is removed"
```

An empty String sends the response with `Content-Length: 0` and no body, and
so does a body filter that leaves the body of a response without a body
empty. 2.7.2 and earlier releases closed the connection there without a
response and logged `zero size buf in writer`; 2.7.3 sends the response as
well (see [docs/releases/v3.0.0.md](../releases/v3.0.0.md) and
[entry 8 of docs/releases/v2.7.3.md](../releases/v2.7.3.md#8-an-output-body-filter-can-send-an-empty-body-664)).

### Nginx::Filter#output

Alias for `Nginx::Filter#body=`.

# Nginx::Upstream Class

You can access `upstream` configuration via Nginx::Upstream. Here is an example.

```nginx
http {
    upstream my_upstream {
      server 127.0.0.1:80;
    }
    server {
        location /foo {
          mruby_rewrite_handler_code '
            u = Nginx::Upstream.new "my_upstream"
            u.server = "127.0.0.1:58081"          # Change 'server' to 127.0.0.1:58081 from 127.0.0.1:80
            Nginx.return Nginx::DECLINED
          ';
          proxy_pass http://my_upstream;
        }
    }
}
```

## Instance Methods

### Nginx::Upstream#new(string) -> upstream

Creates and returns an Upstream instance.

The string is the whole name of an `upstream {}` block, compared case-insensitively as nginx compares upstream names. The method raises `RuntimeError` when no upstream has that name, and `TypeError` when the argument is not a String. Up to 2.7.2 the method compared only the length of the argument, so it also found the first upstream whose name started with it, and it did not check the class of the argument.

```ruby
u = Nginx::Upstream.new "YOUR_UPSTREAM_NAME"
```

### Nginx::Upstream#keepalive_cache -> integer

Returns the keepalive cache of the upstream.

```
u = Nginx::Upstream.new "YOUR_UPSTREAM_NAME"
n = u.keepalive_cache
```

### Nginx::Upstream#keepalive_cache=(integer)

Sets the keepalive cache of the upstream.

```
u = Nginx::Upstream.new "YOUR_UPSTREAM_NAME"
u.keepalive_cache = 0
```

### Nginx::Upstream#server -> string

Returns the server of the upstream.

```
u = Nginx::Upstream.new "YOUR_UPSTREAM_NAME"
Nginx.echo u.server                           #=> 127.0.0.1:80
```

### Nginx::Upstream#server=(string)

Sets the string to the server of the upstream.

The servers of the upstream block that are not `backup` must have one address in all: `Nginx::Upstream.new` raises `RuntimeError` for more, for example for two `server` lines, or for one whose host name nginx resolved to two addresses. `backup` servers are not counted, and the method does not change them. The new server is that peer's for every later request that the worker sends to the upstream, not only for the current request, until the worker exits or the configuration is reloaded; each worker keeps its own. An upstream with a `zone` is not supported: since 2.7.3 the method raises `RuntimeError` for one and leaves its server. Up to 2.7.2 it changed the server, and the change was not valid in the other workers (see "Not changed by this release" of the `Nginx::Upstream#server=` entry in [the 2.7.2 release notes](../releases/v2.7.2.md)).

The string is an IP address and a port: an IPv4 address is four decimal numbers, an IPv6 address goes in brackets, and `unix:` with a path names a UNIX-domain socket. The port is 80 when the string has none. A host name is not resolved, because the worker would serve no other client while it waited; give an IP address. An IPv4 address in a form that only a resolver reads, such as `127.1`, and `255.255.255.255` count as host names here. The method raises `TypeError` when the argument is not a String (since 2.7.3), `ArgumentError` when the string is empty or 256 bytes or longer, when it holds a NUL byte (since 2.7.3), and when it is a host name or anything else that nginx cannot read as an address (since 3.0.0 for these two; see the entries of the 3.0.0 release notes on [a host name](../releases/v3.0.0.md#nginxupstreamserver-raises-argumenterror-for-a-host-name-instead-of-resolving-it-680) and on [the other strings](../releases/v3.0.0.md#nginxupstreamserver-and-nginxstreamconnectionupstream_server-raise-argumenterror-for-a-string-that-cannot-be-a-server-680)), and `RuntimeError` when nginx fails while it reads the string; the server stays as it was then.

```
u = Nginx::Upstream.new "YOUR_UPSTREAM_NAME"
s = u.server                                  #=> 127.0.0.1:80
u.server = "127.0.0.1:8080"                   #=> 127.0.0.1:8080
```

# Nginx::Async Class

## Instance Methods

### Nginx::Async#sleep(msec)

Sleeps in non-blocking way.
It's currently supported in the set, post_read, server rewrite, rewrite, access and content handlers.
When the sleep ends, nginx calls the handler again, which goes on with the code after the sleep, and the phase of the handler handles its result as for a handler that did not wait (since 3.0.0).
An access handler without a result then goes on with the next access handler under `satisfy all` and allows the request under `satisfy any`; a 401 or 403 under `satisfy any` lets nginx try the next access handler; a post_read handler without a result goes on with the next phase.
While the handler waits, nginx does not run its code again.
On 2.x the timer ended the handler with the rules of the content phase: an access or post_read handler without a result answered and then closed the connection, and a 401 or 403 under `satisfy any` ended the request (see [the release notes of 3.0.0](../releases/v3.0.0.md#an-access-or-post_read-handler-that-waits-in-nginxasyncsleep-ends-as-without-the-wait-715)).
An `mruby_set*` handler that sleeps sets its variable when the code returns, and the request goes on, as described under [mruby_set](../directives/README.md#mruby_set-and-mruby_set_code).
In a content handler (`mruby_content_handler*`) nginx waits for the handler since 2.7.3: the code after the sleep runs, and the request gets the response that the handler writes or the status that it returns. Up to 2.7.2 the request ended at the sleep without a response (see "Known limitations" in [the 2.7.1 release notes](../releases/v2.7.1.md#known-limitations)).
A handler of the location that `Nginx.redirect` sends the request to can sleep like any handler, since 3.0.0: the redirect takes effect when the calling handler ends (see [Nginx.redirect](#nginxredirecturl_or_internal_location-http_statusnginxhttp_moved_temporarily)). On 2.x a content handler there ended the request at the sleep.
After the sleep, a content handler can wait for `Nginx::Async::HTTP.sub_request` as well (since 3.0.0; 2.7.3 raises a `RuntimeError` there).
In a log handler (`mruby_log_handler`, `mruby_log_handler_code`) and in the
output filters (`mruby_output_header_filter*`, `mruby_output_body_filter*`),
nginx cannot resume a handler that waits, so it raises a `RuntimeError` (since 2.7.1; in 2.7.0 a sleep in a log handler could crash the worker, and a sleep in a filter stopped the filter there and sent the response unfiltered).
If the handler raises an exception after the call returns, the request gets 500 and the output of `Nginx.rputs` is not sent, unless the response was already started, for example by the location that `Nginx.redirect` ran.
Then the 500 is not sent either.
This holds since 2.7.1; in 2.7.0 the client got no response, the output of `Nginx.rputs` with status 200, or the status that the handler had set before the exception.

```ruby
Nginx::Async.sleep 3000    # Sleep 3000 millisec
```

# Nginx::Async::HTTP Class

## Instance Methods

### Nginx::Async::HTTP#sub_request(location, string_or_hash=nil)

Sends a sub request in non-blocking way, waits for its end, and returns its response, an `Nginx::Async::HTTP::Response` with the same status, headers and body as `Nginx::Async::HTTP.last_response` (since 3.0.0; 2.x returns `nil`).
It's supported in the post_read, server rewrite, rewrite, access and content handlers. In an `mruby_set*` handler it raises a `RuntimeError`, because nginx does not wait for a subrequest there: call it in a rewrite or access handler and set the variable with [Nginx::Var#set](#nginxvarsetname-value) (since 3.0.0; on 2.x the request went on without waiting for the variable).
When the subrequest ends, nginx calls the handler again, which goes on with the code after the call, and the phase of the handler handles its result as for a handler that did not wait, as after [Nginx::Async#sleep](#nginxasyncsleepmsec); the code of the handler runs once.
A content handler can wait for it also after `Nginx::Async.sleep` (since 3.0.0; 2.7.3 raises a `RuntimeError` there, because nginx would not finish the request after the subrequest).
Like `Nginx::Async.sleep`, it raises a `RuntimeError` in a log handler and in
the output filters (since 2.7.1; 2.7.0 started the subrequest there).
If the handler raises an exception after the call returns, the request gets 500 and the output of `Nginx.rputs` is not sent, unless the response was already started, for example by the location that `Nginx.redirect` ran.
Then the 500 is not sent either.
This holds since 2.7.1, as for `Nginx::Async.sleep`.

```ruby
res = Nginx::Async::HTTP.sub_request "/example", "q1=foo&q2=bar" # Send a sub request with the parameters, and get its response

res = Nginx::Async::HTTP.last_response                     # The same response, also on 2.x

Nginx.rputs res.body                                       #=> "hello world"
Nginx.rputs res.headers                                    #=> {"Date" => "Thu, 29 Nov 2018 07:55:22 GMT", ...}
Nginx.rputs res.status                                     #=> 200
```

You can pass a hash instead of the string.

TODO: do we really need Utils.encode_parameters? It is called in sub_request().
Also is the following comment in test/conf/nginx.conf still true?
"# BUG?: using Nginx::Utils.encode_parameters is sometimes missing call method for fiber_proc"

```ruby
Nginx::Async::HTTP.sub_request "/example", Nginx::Utils.encode_parameters({q1: "foo", q2: "bar"})
```
### Nginx::Async::last_response -> http_response

Returns the response of the last sub request. 
See [Nginx::Async::HTTP#sub_request](#nginxasynchttpsub_requestlocation-string_or_hashnil) for usage.

# Nginx::Async::HTTP::Response Class

Response class returned from Nginx::Async::last_response.
See [Nginx::Async::HTTP#sub_request](#nginxasynchttpsub_requestlocation-string_or_hashnil) for usage.

## Instance Methods

### Nginx::Async::HTTP::Response#body -> string

Returns the response body of the last sub request. 
See [Nginx::Async::HTTP#sub_request](#nginxasynchttpsub_requestlocation-string_or_hashnil) for usage.

### Nginx::Async::HTTP::Response#headers -> hash

Returns the response headers of the last sub request. 
See [Nginx::Async::HTTP#sub_request](#nginxasynchttpsub_requestlocation-string_or_hashnil) for usage.

### Nginx::Async::HTTP::Response#status -> integer

Returns the HTTP response status of the last sub request. 
See [Nginx::Async::HTTP#sub_request](#nginxasynchttpsub_requestlocation-string_or_hashnil) for usage.

# RACK Compatible API

rack-based-api mrbgem provides RACK compatible APIs. You can write mruby code in the RACK way as below.

```nginx
location /hello {
  mruby_content_handler_code '
    proc = Proc.new do |env|
      [200, {"Content-Type" => "text/plain"}, ["hello ngx_mruby world!"]]
    end
    run proc
  ';
}
```

## Kernel Module Methods

rack-based-api mrbgem adds `run` method to `Kernel` module. It takes care everything.

### run(obj)

Send a `call` message to the obj. 

The obj must respond to `call`. It takes one argument, the environment. 
It must return an array that contains the status, the headers and the body. 
See [The RACK specification](https://www.rubydoc.info/github/rack/rack/file/SPEC) for more details.

```
class MyApp
  def call(env)
    status = 200
    headers = {"Content-Type" => "text/plain", "X-NGX-MRUBY-INTERACTION-ID" => Uuid.uuid}
    body = ["Got a request from " + env["REMOTE_ADDR"]]
    [status, headers, body]
  end
end
run MyApp.new
```

# Nginx::Stream class

TODO: cleanup and add descriptions.

## example

```nginx
stream {
  upstream dynamic_server0 {
    server 127.0.0.1:58080;
  }

  server {
      listen 12346;
      mruby_stream_code '
        c = Nginx::Stream::Connection.new "dynamic_server0"
        c.upstream_server = "192.168.0.3:54321"
        Nginx::Stream.log Nginx::Stream::LOG_NOTICE, "dynamic_server0 was changed to 192.168.0.3:54321"
      ';
      proxy_pass dynamic_server0;
  }
}
```

## Class Methods

### Nginx::Stream.add_listener

Create a listener on the specified IP address and the port in the hash.

```ruby
Nginx::Stream.add_listener({address: "127.0.0.1:12350"})
Nginx::Stream.add_listener({address: "12351"})
```

See [Nginx::Server#add_listener()](#nginxserveradd_listenerhash) for an example to create multiple listeners

The method works only in `mruby_stream_server_context_code`, while nginx reads the configuration.
Anywhere else, for example in `mruby_stream_code` or `mruby_stream_init_worker_code`, it raises a `RuntimeError` (since 2.7.1).

### Nginx::Stream.errlogger(log_level, string)

```ruby
Nginx::Stream.errlogger Nginx::Stream::LOG_NOTICE, "logging something"
```

### Nginx::Stream.log(log_level, string)

Alias for `Nginx::Stream.errlogger`.

### Nginx::Stream.module_name -> string

Returns the module name `ngx_mruby-stream-module`.

```ruby
Nginx::Stream.module_name #=> "ngx_mruby-stream-module"
```

## Constants 

### Constants for log levels

Log levels for `Nginx::Stream.errlogger` that mirror nginx error log levels.
See [Constants for log levels](#constants-for-log-levels) in the Nginx Class documentation for more details.

Name|Description
-----|-----------
Nginx::Stream::LOG_STDERR|Defined in core/ngx_log.h, but it's never used
Nginx::Stream::LOG_ALERT|Emergency error log level
Nginx::Stream::LOG_EMERG|Alert error log level
Nginx::Stream::LOG_CRIT|Critical error log level
Nginx::Stream::LOG_ERR|Error log level
Nginx::Stream::LOG_WARN|Warning log level
Nginx::Stream::LOG_NOTICE|Notice log level
Nginx::Stream::LOG_INFO|Information log level
Nginx::Stream::LOG_DEBUG|Debug log level

### Constants for status

The values of the session status that `Nginx::Stream::Connection.stream_status` returns and `.stream_status=` sets.

Name|Value
-----|-----------
Nginx::Stream::OK|0
Nginx::Stream::ERROR|-1
Nginx::Stream::AGAIN|-2
Nginx::Stream::BUSY|-3
Nginx::Stream::DONE|-4
Nginx::Stream::DECLINED|-5
Nginx::Stream::ABORT|-6

## Nginx::Stream::Connection class

- example

```nginx
stream {
  upstream dynamic_server0 {
    server 127.0.0.1:58080;
  }

  mruby_stream_init_code '
    Userdata.new.new_upstream = "127.0.0.1:58081"
  ';

  mruby_stream_init_worker_code '
    p "ngx_mruby: STREAM: mruby_stream_init_worker_code"
  ';

  mruby_stream_exit_worker_code '
    p "ngx_mruby: STREAM: mruby_stream_exit_worker_code"
  ';

  server {
      listen 12346;
      mruby_stream_code '
        c = Nginx::Stream::Connection.new "dynamic_server0"
        c.upstream_server = Userdata.new.new_upstream
      ';
      proxy_pass dynamic_server0;
  }
}
```

### Nginx::Stream::Connection#new

get the upstream configuration via upstream name

As for `Nginx::Upstream.new`, the string is the whole name of an `upstream {}` block of the `stream {}` block, compared case-insensitively; the method raises `RuntimeError` when no upstream has that name, and `TypeError` when the argument is not a String (since 2.7.3; up to 2.7.2 it also found an upstream whose name started with the argument).

```ruby
# == nginx.conf ==
#   upstream dynamic_server0 {
#    server 127.0.0.1:58080;
#  }
c = Nginx::Stream::Connection.new "dynamic_server0"
```

### Nginx::Stream::Connection#upstream_server

```ruby
# == nginx.conf ==
#   upstream dynamic_server0 {
#    server 127.0.0.1:58080;
#  }
c = Nginx::Stream::Connection.new "dynamic_server0"
c.upstream_server #=> "127.0.0.1:58080"
```

### Nginx::Stream::Connection#upstream_server=

Sets the server of the upstream that `Nginx::Stream::Connection.new` named. As for `Nginx::Upstream#server=`, the servers of the upstream block that are not `backup` must have one address in all, and `backup` servers are not changed. The new server is that peer's for every later session that the worker sends to the upstream, until the worker exits or the configuration is reloaded; each worker keeps its own. An upstream with a `zone` is not supported: since 2.7.3 the method raises `RuntimeError` for one and leaves its server.

The string is an IP address and a port, such as `127.0.0.1:12345` or `[::1]:12345`, or `unix:` with a path; host names are not resolved and raise. A string without a port is accepted, and the port is then 0. The method raises `TypeError` when the argument is not a String (since 2.7.3), `ArgumentError` when the string is empty or 256 bytes or longer, when it holds a NUL byte, and when it is a host name or anything else that nginx cannot read as an address (since 3.0.0; 2.x raises `RuntimeError` for these, for a NUL byte since 2.7.3; see [the 3.0.0 release notes](../releases/v3.0.0.md#nginxupstreamserver-and-nginxstreamconnectionupstream_server-raise-argumenterror-for-a-string-that-cannot-be-a-server-680)), and `RuntimeError` when nginx fails while it reads the string; the server stays as it was then.

```ruby
# == nginx.conf ==
#   upstream dynamic_server0 {
#    server 127.0.0.1:58080;
#  }
c = Nginx::Stream::Connection.new "dynamic_server0"
c.upstream_server #=> "127.0.0.1:58080"
c.upstream_server = "192.168.0.3:54321"
```

### Nginx::Stream::Connection.stream_status

get the current stream status
```ruby
if Nginx::Stream::Connection.remote_ip == "127.0.0.1"
  current_status = Nginx::Stream::Connection.stream_status #=> Nginx::Stream::DECLINED
end
```

### Nginx::Stream::Connection.stream_status=

```ruby
if Nginx::Stream::Connection.remote_ip == "127.0.0.1"
  current_status = Nginx::Stream::Connection.stream_status #=> Nginx::Stream::DECLINED
  Nginx::Stream::Connection.stream_status = Nginx::Stream::ABORT
  Nginx::Stream.log Nginx::Stream::LOG_NOTICE, ¥
    "current status=#{(current_status == Nginx::Stream::DECLINED) ? "NGX_DECLINED" : current_status} but deny from #{Nginx::Stream::Connection.remote_ip} return NGX_ABORT"
end
```

### Nginx::Stream::Connection.remote_ip

```ruby
if Nginx::Stream::Connection.remote_ip == "127.0.0.1"
  # something access control
end
```

- access control example

```nginx
stream {
  server {
      listen 12347;
      mruby_stream_code '
        if Nginx::Stream::Connection.remote_ip == "127.0.0.1"
          current_status = Nginx::Stream::Connection.stream_status
          Nginx::Stream::Connection.stream_status = Nginx::Stream::ABORT
          Nginx::Stream.log Nginx::Stream::LOG_NOTICE, "current status=#{(current_status == Nginx::Stream::DECLINED) ? "NGX_DECLINED" : current_status} but deny from #{Nginx::Stream::Connection.remote_ip} return NGX_ABORT"
        end
      ';
      proxy_pass dynamic_server1;
  }
}
```

### Nginx::Stream::Connection.{remote_port,local_ip,local_addr,local_port,local_ip_port}

```nginx
server {
    listen 127.0.0.1:12348;
    mruby_stream_code '
      Nginx::Stream.log Nginx::Stream::LOG_NOTICE, "local is #{Nginx::Stream::Connection.local_ip}:#{Nginx::Stream::Connection.local_port} remote_port is #{Nginx::Stream::Connection.remote_ip}:#{Nginx::Stream::Connection.remote_port}"
      if Nginx::Stream::Connection.local_port != 12348 && Nginx::Stream::Connection.local_ip != "127.0.0.1"
        Nginx::Stream::Connection.stream_status = Nginx::Stream::ABORT
      end
    ';
    proxy_pass static_server0;
}

server {
    listen 127.0.0.1:12349;
    mruby_stream_code '
      Nginx::Stream.log Nginx::Stream::LOG_NOTICE, "local_ip_port is #{Nginx::Stream::Connection.local_ip_port}"
      if Nginx::Stream::Connection.local_ip_port != "127.0.0.1:12349"
        Nginx::Stream::Connection.stream_status = Nginx::Stream::ABORT
      end
    ';
    proxy_pass static_server0;
}
```

### Nginx::Stream::Connection.{proxy_protocol_addr,proxy_protocol_ip}

On a `listen ... proxy_protocol`, returns the source address of the PROXY protocol header that nginx read when the connection was accepted, as a String. `proxy_protocol_ip` is another name of the same method, and both are also instance methods. The method returns `nil` when the connection has no such address: on a listen without `proxy_protocol`, and for the headers `PROXY UNKNOWN` (version 1) and `LOCAL` (version 2). This holds since 3.0.0 and 2.7.4.

```nginx
server {
    listen 127.0.0.1:12350 proxy_protocol;
    mruby_stream_code '
      if Nginx::Stream::Connection.proxy_protocol_addr != "192.0.2.10"
        Nginx::Stream::Connection.stream_status = Nginx::Stream::ABORT
      end
    ';
    proxy_pass static_server0;
}
```

## Nginx::Stream::Async Class
### Method
#### Nginx::Stream::Async#sleep
Do non-blocking sleep. It works in the code of `mruby_stream` and `mruby_stream_code`, which runs in the access phase of the stream session.

After the sleep, the session goes on as it does when the code does not sleep, by the result of the code: the next handler for `Nginx::Stream::DECLINED` (the default of `Nginx::Stream::Connection.stream_status`), the next phase for `Nginx::Stream::OK`, the wait of the session for `Nginx::Stream::DONE` and `Nginx::Stream::AGAIN`, and the end of the session for `Nginx::Stream::ABORT` or another status, and for an exception, which `error.log` records.
This holds since 2.7.3; up to 2.7.2 a session whose code raised or set a status other than `Nginx::Stream::DECLINED` after the sleep was neither ended nor continued, and an exception after the sleep also aborted the next session.

While the code of a TCP session sleeps, nginx reads nothing from the client, also on a `listen ... proxy_protocol`: the bytes that the client sends then stay for the phase after the code, such as `proxy_pass`, which sends them to the upstream. This holds since 3.0.0 and 2.7.4.

A session runs its code once (since 3.0.0): while the code waits, datagrams that the client of a UDP session (`listen ... udp`) sends do not start it again, and nginx does not give them to the code. On 2.x each such datagram started the code again in another fiber of the session, and only the last run went on after its sleep.
When `worker_shutdown_timeout` expires in a worker that shuts down, a session whose code waits ends: the code after the sleep does not run, and `error.log` gets `shutdown timeout` at the `info` level (since 3.0.0; up to 2.7.3 the session went on; since 2.7.4 a TCP session ends too, and `error.log` gets `the session ends during the wait of its code` at the `info` level instead, while a UDP session goes on). See the entries ["A UDP stream session runs its code once"](../releases/v3.0.0.md#a-udp-stream-session-runs-its-code-once-datagrams-that-arrive-while-the-code-waits-do-not-start-it-again-727) and ["A stream session that waits when `worker_shutdown_timeout` expires ends then"](../releases/v3.0.0.md#a-stream-session-that-waits-when-worker_shutdown_timeout-expires-ends-then-727) of the release notes of 3.0.0.

```ruby
# sleep 3000 millisec
Nginx::Stream::Async.sleep 3000
```

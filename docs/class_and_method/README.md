# Mruby API documentation for ngx_mruby

This is the mruby API documentation for ngx_mruby.

ngx_mruby provides mruby APIs to access and manipulate nginx internal data structure. 
You can use these classes and methods in handlers like `mruby_content_handler_code`.

Available APIs depend on your build configuration.
See [Configuring mrbgems](../install#2-configuring-mrbgems) and [Build options](../install#build-options) for the build configuration.

TODO: Sort. I don't think alphabetical order is easy to read.

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

## rack-based-api mrbgem 

The rack-based-api mrbgem is an optional bundled mrbgem.
It provides [RACK](https://rack.github.io/) (Ruby Webserver Interface) compatible APIs to make development and testing easier.

- [RACK Compatible API](#rack-compatible-api)

## auto-ssl mrbgem

The auto-ssl mrbgem is an optional bundled mrbgem to support 
[Automatic Certificate Management Environment](https://ietf-wg-acme.github.io/acme/draft-ietf-acme-acme.html) (ACME) 
protocol client. You can easily get SSL certificates from [Let’s Encrypt](https://letsencrypt.org/).

It is still in early development phase.
See script files in [mrbgems/auto-ssl/mrblib](https://github.com/matsumotory/ngx_mruby/tree/master/mrbgems/auto-ssl/mrblib)
for APIs.

# Add classes and methods reference.

## built-in mrbgems

You can use the following classes with default build configuration.

- [Cache Class](https://github.com/matsumotory/mruby-localmemcache)
- [Dir class](https://github.com/iij/mruby-dir)
- [Digest Class](https://github.com/iij/mruby-digest)
- [ENV class](https://github.com/iij/mruby-env)
- [JSON Class](https://github.com/mattn/mruby-json)
- [Mutex class](https://github.com/matsumotory/mruby-mutex)
- [OnigRegexp Class and Regexp Engine](https://github.com/mattn/mruby-onig-regexp)
- [Process Class](https://github.com/iij/mruby-process)
- [Redis Class](https://github.com/matsumotory/mruby-redis)
- [SecureRandom Class](https://github.com/monochromegane/mruby-secure-random)
- [Userdata Class](https://github.com/matsumotory/mruby-userdata)
- [Uname Class](https://github.com/matsumotory/mruby-uname)
- [Vedis Class](https://github.com/matsumotory/mruby-vedis)
### ngx_mruby STREAM module(TCP/UDP Load Balancing)
- [Nginx::Stream class](#nginxstream-class)
- [Nginx::Stream::Connection class](#nginxstreamconnection-class)
- [Nginx::Stream::Async class](#nginxstreamasync-class)

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

```ruby
Nginx.rputs "hello ngx_mruby world!"
```

### Nginx.echo(string)

Puts response text with a newline.

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

Don't confuse `Nginx.return` method with mruby's `return` statement.
ngx_mruby v2 supports `return` statement in handler code as below.
It just returns from the handler.

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

### Nginx.log(log_level, string)

Alias for Nginx.errlogger

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
It doesn't work in other handlers like `mruby_content_handler_code`.

## Instance Methods

### Nginx::SSL#servername -> string

Returns the SNI server name from the client.

```nginx
mruby_ssl_handshake_handler_code '
  ssl = Nginx::SSL.new
  ssl.certificate = "/path/to/#{ssl.servername}.crt"
  ssl.certificate_key = "/path/to/#{ssl.servername}.key"
';

```
### Nginx::SSL#certificate=(string)

Sets the certificate file path used for the connection.

```nginx
mruby_ssl_handshake_handler_code '
  ssl = Nginx::SSL.new
  ssl.certificate = "/path/to/#{ssl.servername}.crt"
  ssl.certificate_key = "/path/to/#{ssl.servername}.key"
';
```

### Nginx::SSL#certificate_key=(string)

Sets the certificate key file path used for the connection.

```nginx
mruby_ssl_handshake_handler_code '
  ssl = Nginx::SSL.new
  ssl.certificate = "/path/to/#{ssl.servername}.crt"
  ssl.certificate_key = "/path/to/#{ssl.servername}.key"
';
```
### Nginx::SSL#certificate_data=(string)

Sets the string representation of the certificate data used for the connection

```nginx
mruby_ssl_handshake_handler_code '
  ssl = Nginx::SSL.new
  certificate_data = File.read("/path/to/#{ssl.servername}.crt")
  key_data = File.read("/path/to/#{ssl.servername}.key")
  ssl.certificate_data = certificate_data
  ssl.certificate_key_data = key_data
';
```

### Nginx::SSL#certificate_key_data=(string)

Sets the string representation of the certificate key data used for the connection

```nginx
mruby_ssl_handshake_handler_code '
  ssl = Nginx::SSL.new
  certificate_data = File.read("/path/to/#{ssl.servername}.crt")
  key_data = File.read("/path/to/#{ssl.servername}.key")
  ssl.certificate_data = certificate_data
  ssl.certificate_key_data = key_data
';
```

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
  ssl.certificate = "/etc/ssl/#{ssl.servername}.crt"
  ssl.certificate_key = "/etc/ssl/#{ssl.servername}.key"
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
  ssl.certificate = "/etc/ssl/#{ssl.servername}.crt"
  ssl.certificate_key = "/etc/ssl/#{ssl.servername}.key"
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
See [Nginx::Headers_in Class](#nginxvar-class) for more details.

```ruby
r = Nginx::Request.new
in = r.headers_in
in.["User-Agent"] #=> curl/7.52.1
```

### Nginx::Request#headers_out -> headers_out

Returns a Headers_out instance of the request.
See [Nginx::Headers_out Class](#nginxheaders_out-class) for more details.

```ruby
r = Nginx::Request.new
out = r.headers_out
out.["X-NGX-MRUBY-INTERACTION-ID"] = Uuid.uuid
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
    'Basic ' + Base64.encode(backend_user + ':' + backend_pass)
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

### Nginx::Var#set(name, value)

Set the value to the nginx variable.

```ruby
v = Nginx::Request.new.var
v.set "backend", "http://192.168.0.9/"  # Set "http://192.168.0.9/" to $backend
```

## Nginx::Var#.exist? -> true or false

Returns true if the variable is defined.
If `backend` variable is not defined in nginx.conf, you will get false.

```ruby
v = Nginx::Request.new.var
v.exits? "backend" # => false
```

# Nginx::Headers_in Class

Headers_in class stores HTTP request headers.
The name comes from [ngx_http_headers_in_t](https://www.nginx.com/resources/wiki/extending/api/http/#ngx-http-headers-in-t).

## Instance Methods

### Nginx::Headers_in#[](string) -> string

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

### Nginx::Headers_out#[](string) -> string

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
It doesn't work in other handlers like `mruby_content_handler_code`.

__Notice__: You can *NOT* use `Nginx.rputs` and `Nginx.echo` in the output body handlers.

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

```ruby
f = Nginx::Filter.new
response = f.body.upcase
```

### Nginx::Filter#body=(string)

Sets the string to the response body

```ruby
f = Nginx::Filter.new
f.body = "The original body is removed"
```

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

```
u = Nginx::Upstream.new "YOUR_UPSTREAM_NAME"
s = u.server                                  #=> 127.0.0.1:80
u.server = "127.0.0.1:8080"                   #=> 127.0.0.1:8080
```

# Nginx::Async Class

## Instance Methods

### Nginx::Async#sleep(msec)

Sleeps in non-blocking way.
It's currently supported in the set, rewrite and access handlers.

```ruby
Nginx::Async.sleep 3000    # Sleep 3000 millisec
```

# Nginx::Async::HTTP Class

## Instance Methods

### Nginx::Async::HTTP#sub_request(location, string_or_hash=nil)

Sends a sub request in non-blocking way.
It's currently supported in the `set`, `rewrite` and `access` handlers.

```ruby
Nginx::Async::HTTP.sub_request "/example", "q1=foo&q2=bar" # Send a sub request with the parameters

res = Nginx::Async::HTTP.last_response                     # Get the response of the sub request

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

```ruby
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

Return status for `Nginx::Stream::Connection.stream_status`.

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

```ruby
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

## Nginx::Stream::Async Class
### Method
#### Nginx::Stream::Async#sleep
Do non-blocking sleep. Currently it supports only setcode and rewrite and access phases.
```ruby
# sleep 3000 millisec
Nginx::Stream::Async.sleep 3000
```

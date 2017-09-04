# Class for ngx_mruby 
### ngx_mruby HTTP module
- [Kernel Class](#kernel-class)
- [Nginx Class](#nginx-class)
- [Nginx::SSL Class](#nginxssl-class)
- [Nginx::Request Class](#nginxrequest-class)
- [Nginx::Server Class](#nginxserver-class)
- [Nginx::Connecntion Class](#nginxconnection-class)
- [Nginx::Var Class](#nginxvar-class)
- [Nginx::Headers_in Class](#nginxheaders_in-class)
- [Nginx::Headers_out Class](#nginxheaders_out-class)
- [Nginx::Filter Class](#nginxfilter-class)
- [Nginx::Upstream Class](#nginxupstream-class)
- [Process Class](https://github.com/iij/mruby-process)
- [IO Class](https://github.com/iij/mruby-io)
- [Array Class for pack](https://github.com/iij/mruby-pack)
- [Digest Class](https://github.com/iij/mruby-digest)
- [JSON Class](https://github.com/mattn/mruby-json)
- [Redis Class](https://github.com/matsumotory/mruby-redis)
- [Vedis Class](https://github.com/matsumotory/mruby-vedis)
- [Sleep Class](https://github.com/matsumotory/mruby-sleep)
- [Userdata Class](https://github.com/matsumotory/mruby-userdata)
- [ngx_mruby Extended Class](https://github.com/matsumotory/mruby-ngx-mruby-ext)
- [OnigRegexp Class and Regexp Engine](https://github.com/mattn/mruby-onig-regexp)
- [Uname Class](https://github.com/matsumotory/mruby-uname)
- [File::Stat Class](https://github.com/ksss/mruby-file-stat)

### ngx_mruby STREAM module(TCP/UDP Load Balancing)
- [Nginx::Stream class](#nginxstream-class)
- [Nginx::Stream::Connection class](#nginxstreamconnection-class)

### Extra(commented out in build_config.rb)
- [Discout Class for markdown](https://github.com/matsumotory/mruby-discount)
- [Capability Class for Linux Capability](https://github.com/matsumotory/mruby-capability)
- [Cgroup Class for Linux Cgroups](https://github.com/matsumotory/mruby-cgroup)

## Kernel Class
### Method
#### get_server_class
```ruby
Server = get_server_class

Server.echo "hello world"
```

#### server_name
get server software name
```ruby
if server_name == "NGINX"
  Server = Nginx
elsif server_name == "Apache" 
  Server = Apache
end
```
## Nginx Class
### Method
#### Nginx.rputs
create response text
```ruby
Nginx.rputs "hello ngx_mruby world!"
```
#### Nginx.echo
create response text which is terminated with a newline
```ruby
Nginx.echo "hello ngx_mruby world!"
```
is equal to
```ruby
Nginx.rputs "hello ngx_mruby world!\n"
```
#### Nginx.return
return [nginx status code](https://github.com/matsumotory/ngx_mruby/docs/class_and_method#const-for-http-status)
```ruby
return Nginx::HTTP_SERVICE_UNAVAILABLE
```
#### Nginx.send_header
alias ``Nginx.return``
#### Nginx.errlogger
logging to error.log with [log priority](https://github.com/matsumotory/ngx_mruby/docs/class_and_method#const-for-log)
```ruby
Nginx.errlogger Nginx::LOG_ERR, "ngx_mruby error!"
```
error.log example
```
2014/03/03 00:07:09 [error] 37667#0: *2 ngx_mruby error!, client: 192.168.12.9, server: localhost, request: "GET /log-test HTTP/1.1", host: "192.168.12.9:8001"
```
#### Nginx.log
alias of Nginx.errlogger

#### Nginx.module_name
```ruby
Nginx.echo Nginx.module_name #=> ngx_mruby
```
#### Nginx.module_version
```ruby
Nginx.echo Nginx.module_version #=> 0.0.1
```
#### Nginx.nginx_version
```ruby
Nginx.echo Nginx.nginx_version #=> 1.4.4
```
#### Nginx.configure
```ruby
Nginx.echo Nginx.configure #=>  --add-module=/home/matsumoto_r/DEV/ngx_mruby --add-module=/home/matsumoto_r/DEV/ngx_mruby/dependence/ngx_devel_kit --prefix=/usr/local/nginx-1.4.4
```
#### Nginx.redirect
normal redirect on mruby_rewrite_handler{,_code} phase
```ruby
Nginx.redirect "http://ngx.mruby.org/", Nginx::HTTP_MOVED_PERMANENTLY
```
internal redirect on mruby_rewrite_handler{,_code} phase
```ruby
Nginx.redirect "/inter-redirect/"
```
#### Nginx.remove_global_variable
```ruby
$a = 1
Nginx.echo global_variables #=> [:$stdout, :$$, :$/, :$stdin, :$?, :$a, :$stderr, :$1, :$2, :$3, :$4, :$5, :$6, :$7, :$8, :$9]
Nginx.remove_global_variable :$a
Nginx.echo global_variables #=> [:$stdout, :$$, :$/, :$stdin, :$?, :$stderr, :$1, :$2, :$3, :$4, :$5, :$6, :$7, :$8, :$9]
```
### Const
#### Const for log
Const|Description
-----|-----------
Nginx::LOG_STDERR|logging stderr
Nginx::LOG_EMERG|logging emergency priority
Nginx::LOG_ALERT|logging alert priority
Nginx::LOG_CRIT|logging critical priority
Nginx::LOG_ERR|logging error priority
Nginx::LOG_WARN|logging warning priority
Nginx::LOG_NOTICE|logging notice priority
Nginx::LOG_INFO|information log
Nginx::LOG_DEBUG|debug log
#### Const for HTTP status
Const|Value(status code)
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

## Nginx::SSL Class
### Method
#### Nginx::SSL#servername

SNI server name from client

```nginx
mruby_ssl_handshake_handler_code '
  ssl = Nginx::SSL.new
  ssl.certificate = "/path/to/#{ssl.servername}.crt"
  ssl.certificate_key = "/path/to/#{ssl.servername}.key"
';
```
#### Nginx::SSL#certificate=

set certificate file path for a request

```nginx
mruby_ssl_handshake_handler_code '
  ssl = Nginx::SSL.new
  ssl.certificate = "/path/to/#{ssl.servername}.crt"
  ssl.certificate_key = "/path/to/#{ssl.servername}.key"
';
```

#### Nginx::SSL#certificate_key=

set certificate key file path for a request

```nginx
mruby_ssl_handshake_handler_code '
  ssl = Nginx::SSL.new
  ssl.certificate = "/path/to/#{ssl.servername}.crt"
  ssl.certificate_key = "/path/to/#{ssl.servername}.key"
';
```

#### Nginx::SSL.errlogger
```ruby
Nginx::SSL.errlogger Nginx::LOG_ERR, "ngx_mruby error!"
```
#### Nginx::SSL.log
alias of Nginx::SSL.errlogger

#### Nginx::SSL#local_port

```nginx
location /local_port {
     mruby_content_handler_code "Nginx.rputs Nginx::SSL.new.local_port.to_s";
}
```

```
t.assert('ngx_mruby - ssl local port') do
  res = `curl -k #{base_ssl(58082) + '/local_port'}`
  t.assert_equal '58082', res
end

```

## Nginx::Request Class
### Method
#### Nginx::Request#scheme
```ruby
# curl https://127.0.0.1/
r = Nginx::Request.new
r.scheme #=> https
```
#### Nginx::Request#content_type=
```ruby
r = Nginx::Request.new
r.content_type = "text/plain"
```
```bash
$ curl -v http://127.0.0.1/
< Content-Type: text/plain
```
#### Nginx::Request#content_type
```ruby
r = Nginx::Request.new

r.content_type = "text/plain"
Nginx.echo r.content_type #=> text/plain
```
#### Nginx::Request#request_line
```ruby
r = Nginx::Request.new

# curl -v http://192.168.12.9:8001/hello?a=1
Nginx.echo r.request_line #=> GET /hello?a=1 HTTP/1.1
```
#### Nginx::Request#request_line=
set string to reqeust_line
#### Nginx::Request#sub_request?
```ruby
r = Nginx::Request.new

# location / { mruby_content_hadnler /path/to/hook.rb; }
Nginx.echo r.sub_request?.to_s #=> "false"
```
#### Nginx::Request#uri
```ruby
r = Nginx::Request.new

# curl -v http://192.168.12.9:8001/hello?a=1
Nginx.echo r.uri #=> /hello
```
#### Nginx::Request#uri=
set string to uri
#### Nginx::Request#unparsed_uri
```ruby
r = Nginx::Request.new

# curl -v http://192.168.12.9:8001/hello?a=1
Nginx.echo r.unparsed_uri #=> /hello?a=1
```
#### Nginx::Request#unparsed_uri=
set string to unparsed_uri
#### Nginx::Request#method
```ruby
r = Nginx::Request.new

# curl -v http://192.168.12.9:8001/hello?a=1
Nginx.echo r.method #=> GET
```
#### Nginx::Request#method=
set string to method
#### Nginx::Request#protocol
```ruby
r = Nginx::Request.new

# curl -v http://192.168.12.9:8001/hello?a=1
Nginx.echo r.protocol #=> HTTP/1.1
```
#### Nginx::Request#protocol=
set string to protocol
#### Nginx::Request#args
```ruby
r = Nginx::Request.new

# curl -v http://192.168.12.9:8001/hello?a=1
Nginx.echo r.args #=> a=1
```
#### Nginx::Request#args=
set string to args
#### Nginx::Request#var.method_missing
get nginx user difined variables or [core variables](https://github.com/matsumotory/ngx_mruby/docs/class_and_method#refs-nginx-core-variables), alias [Nginx::Var#method_missing](https://github.com/matsumotory/ngx_mruby/docs/class_and_method#nginxvarmethod_missing)
```ruby
r = Nginx::Request
Nginx.echo "$http_host core variable is #{r.var.http_host}"
```
#### Nginx::Request#var.set
set nginx variables
```ruby
# in nginx.conf
# location /proxy {
#     proxy_pass http://$backend;
# }

r = Nginx::Request
r.var.set "backend", "http://192.168.0.9/"
```
#### Nginx::Request#headers_in[]
```ruby
r = Nginx::Request.new
Nginx.rputs r.headers_in["User-Agent"] #=> curl/7.29.0
r.headers_in["hoge"] = "foo"
r.headers_in["hoge"] = [r.headers_in["hoge"], "fuga"]
Nginx.rputs r.headers_in["hoge"]          # => ["foo", "fuga"]
```
#### Nginx::Request#headers_in[]=
```ruby
r = Nginx::Request.new

Nginx.rputs r.headers_in["User-Agent"] #=> curl/7.29.0
r.headers_in["User-Agent"] = "test-agent"
Nginx.rputs r.headers_in["User-Agent"] #=> test-agent
r.headers_in["hoge"] = "foo"
r.headers_in["hoge"] = [r.headers_in["hoge"], "fuga"]
Nginx.rputs r.headers_in["hoge"]          # => ["foo", "fuga"]
```
#### Nginx::Request#headers_in.all
```ruby
r = Nginx::Request.new

r.headers_in.all.keys.each do |k|
  Server.echo "#{k}: #{r.headers_in[k]}"
end
# => $ curl -v http://192.168.12.9:8001/hello?a=1
# => Host: 192.168.12.9:8001
# => User-Agent: curl/7.29.0
# => Accept: */*
```
#### Nginx::Request#headers_out[]
```ruby
r = Nginx::Request.new

r.headers_out["X-NGX-MRUBY"] = "support"
Nginx.rputs r.headers_out["X-NGX-MRUBY"] #=> support
r.headers_out["X-NGX-MRUBY"] = ["support", "multi"]
Nginx.rputs r.headers_out["X-NGX-MRUBY"] #=> ["support", "multi"]
```
#### Nginx::Request#headers_out[]=
```ruby
r = Nginx::Request.new

r.headers_out["X-NGX-MRUBY"] = "support"
Nginx.rputs r.headers_out["X-NGX-MRUBY"] #=> support
r.headers_out["X-NGX-MRUBY"] = ["support", "multi"]
Nginx.rputs r.headers_out["X-NGX-MRUBY"] #=> ["support", "multi"]
```
#### Nginx::Request#headers_out.all
```ruby
r.headers_out["X-NGX-MRUBY"] = "support"

r.headers_out.all.keys.each do |k|
  Server.echo "#{k}: #{r.headers_out[k]}"
end
# => $ curl -v http://192.168.12.9:8001/hello?a=1
# => X-NGX-MRUBY: support
```
#### Nginx::Request#hostname
```ruby
r = Nginx::Request.new
# curl -v http://192.168.12.9:8001/hello?a=1
Nginx.echo r.hostname #=> "192.168.12.9"
```
#### Nginx::Request#authority
```ruby
r = Nginx::Request.new
# curl -v http://192.168.12.9:8001/hello?a=1
Nginx.echo r.authority #=> "192.168.12.9:8001"
```
#### Nginx::Request#filename
```ruby
r = Nginx::Request.new
# curl -v http://192.168.12.9:8001/hello?a=1
Nginx.echo r.filename #=> /usr/local/nginx-1.4.4/html/hello
```
#### Nginx::Request#user
```ruby
r = Nginx::Request.new
# curl -v http://192.168.12.9:8001/hello?a=1 -u matsumoto_r
Nginx.echo r.user #=> matsumoto_r
```
#### Nginx::Request#{read_body,get_body}

If you use request body as Ruby method, you must use `mruby_enable_read_request_body on;` on location config as the following:

##### nginx.conf

```nginx
location /issue-268 {
  mruby_enable_read_request_body on;    # here
  mruby_access_handler_code '
    req = Nginx::Request.new
    Nginx.log Nginx::LOG_ERR, "method:#{req.method}"
    rc = req.read_body
    body = req.get_body
    Nginx.log Nginx::LOG_ERR, "rc:#{rc}"
    Nginx.log Nginx::LOG_ERR, "body:#{body}"
    Userdata.new.req_body = body
  ';
  mruby_content_handler_code '
    Nginx.rputs Userdata.new.req_body
  ';
}
```

- test

```ruby
t.assert('ngx_mruby - BUG: request_body issue 268', 'location /issue-268') do
  res = `./test/t/issue-268-test.rb`.split("\r\n\r\n")[1]
  t.assert_equal %({\"hello\": \"ngx_mruby\"}\n), res
end
```

- issue-268-test.rb

```ruby
#!/usr/bin/env ruby

require 'socket'

request_body = %({"hello": "ngx_mruby"})
headers = <<HEAD.gsub("\n", "\r\n")
POST /issue-268 HTTP/1.0
Content-Type: application/json
User-Agent: issue-268-test
Content-Length: #{request_body.length}
HEAD

Socket.tcp("localhost", 58080) do |s|
  s.print headers
  s.print "\r\n"
  sleep 0.3 # <==== important!
  s.print request_body
  s.close_write
  puts s.read
end
```

#### Nginx::Request#body

If you use request body as Ruby method, you must use `mruby_enable_read_request_body`on; on location config as the following:

##### nginx.conf
```ruby
location /request_body {
    mruby_enable_read_request_body on;
    mruby_rewrite_handler_code '
      r = Nginx::Request.new
      Nginx.rputs r.body
      # or Nginx/rputs r.var.request_body
   ';
}
```
##### curl
```
$ curl -d "name1=value1" http://127.0.0.1:58080/request_body
name1=value1
```
##### more example
You may configure `client_body_buffer_size` in nginx.conf not to create temporary post file.
```bash
$ file ngx_modules.o
ngx_modules.o: ELF 64-bit LSB  relocatable, x86-64, version 1 (SYSV), not stripped

$ curl --data-binary "@ngx_modules.o" http://127.0.0.1:58080/request_body > ngx_modules_from_response.o
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0curl: (7) Failed to connect to 127.0.0.1 port 58080: Connection refused

$ curl --data-binary "@ngx_modules.o" http://127.0.0.1:58080/request_body > ngx_modules_from_response.o

$ md5sum ngx_modules*
f1abd03eaab90a06be0ed8ac13708e63  ngx_modules_from_response.o
f1abd03eaab90a06be0ed8ac13708e63  ngx_modules.o
```

## Nginx::Server Class
### Method
#### Nginx::Server#add_listener

```ruby
s = Nginx::Server.new
s.add_listener({address: "127.0.0.1:58101"})
s.add_listener({address: "58102"})
s.add_listener({address: "58103", ssl: true})
```

- nginx.conf example

```nginx
http {
    server {
        mruby_server_context_handler_code '
          s = Nginx::Server.new
          (20001..30000).each { |port| s.add_listener({address: (port * 2).to_s}) }
        ';

        location /mruby {
          mruby_content_handler_code 'Nginx.rputs "#{Nginx::Connection.new.local_port} sann hello"';
        }
    }
}
```

#### Nginx::Server#document_root
```ruby
s = Nginx::Server.new

# $ curl -v http://192.168.12.9:8001/hello?a=1
Nginx.echo s.document_root # => /usr/local/nginx-1.4.4/html
```
#### Nginx::Server#path
```ruby
s = Nginx::Server.new

# $ curl -v http://192.168.12.9:8001/hello?a=1
Nginx.echo s.path # => /usr/local/nginx-1.4.4/html
```
#### Nginx::Server#realpath_root
```ruby
s = Nginx::Server.new

# $ curl -v http://192.168.12.9:8001/hello?a=1
Nginx.echo s.realpath_root # => /usr/local/nginx-1.4.4/html
```
## Nginx::Connection Class
### Method
#### Nginx::Connection#remote_ip
```ruby
c = Nginx::Connection.new

# $ curl -v http://192.168.12.9:8001/hello?a=1
Nginx.echo c.remote_ip # => 192.168.12.9
```
#### Nginx::Connection#remote_port
```ruby
c = Nginx::Connection.new

# $ curl -v http://192.168.12.9:8001/hello?a=1
Nginx.echo c.remote_port # => 54430
```
#### Nginx::Connection#local_ip
```ruby
c = Nginx::Connection.new

# $ curl -v http://192.168.12.9:8001/hello?a=1
Nginx.echo c.local_ip # => 192.168.12.9
```
#### Nginx::Connection#local_port
```ruby
c = Nginx::Connection.new

# $ curl -v http://192.168.12.9:8001/hello?a=1
Nginx.echo c.local_port # => 8001
```
## Nginx::Var Class
### Method
#### Nginx::Var#method_missing
get nginx variables
```ruby
v = Nginx::Var.new
Nginx.echo "$http_host core variable is #{v.http_host}"
```

##### refs: nginx core variables
variables| | | |
---------|---------------|------------|--------
http_host|http_user_agent|http_referer|http_via
http_x_forwarded_for|http_cookie|content_length|content_type
host|binary_remote_addr|remote_addr|remote_port
server_addr|server_port|server_protocol|scheme
https|request_uri|uri|document_uri
request|document_root|realpath_root|query_string
args|is_args|request_filename|server_name
request_method|remote_user|bytes_sent|body_bytes_sent
pipe|request_completion|request_body|request_body_file
request_length|request_time|status|sent_http_content_type
sent_http_content_length|sent_http_location|sent_http_last_modified|sent_http_connection
sent_http_keep_alive|sent_http_transfer_encoding|sent_http_cache_control|limit_rate
connection|connection_requests|nginx_version|hostname
pid|msec|time_iso8601|time_local
tcpinfo_rtt|tcpinfo_rttvar|tcpinfo_snd_cwnd|tcpinfo_rcv_space
connections_active|connections_reading|connections_writing|connections_waiting

#### Nginx::Var#set
set nginx variables
```ruby
# in nginx.conf
# location /proxy {
#     proxy_pass http://$backend;
# }

v = Nginx::Var.new
v.set "backend", "http://192.168.0.9/"
```

## Nginx::Headers_in Class
### Method
#### Nginx::Headers_in#[]
```ruby
hin = Nginx::Headers_in.new
Nginx.rputs hin["User-Agent"] #=> curl/7.29.0
```
#### Nginx::Headers_in#[]=
```ruby
hin = Nginx::Headers_in.new

Nginx.rputs hin["User-Agent"] #=> curl/7.29.0
hin["User-Agent"] = "test-agent"
Nginx.rputs hin["User-Agent"] #=> test-agent
```
#### Nginx::Headers_in#all
```ruby
hin = Nginx::Headers_in.new

hin.all.keys.each do |k|
  Server.echo "#{k}: #{hin[k]}"
end
# => $ curl -v http://192.168.12.9:8001/hello?a=1
# => Host: 192.168.12.9:8001
# => User-Agent: curl/7.29.0
# => Accept: */*
```
#### Nginx::Headers_in#delete
```ruby
hin = Nginx::Headers_in.new

hin["X-Remove-Header"] = "to be deleted!"
hin.delete("X-Remove-Header")
Nginx.rputs hin["X-Remove-Header"] #=> nil
```
## Nginx::Headers_out Class
### Method
#### Nginx::Headers_out#[]
```ruby
hout = Nginx::Headers_out.new

hout["X-NGX-MRUBY"] = "support"
Nginx.rputs hout["X-NGX-MRUBY"] #=> support
```
#### Nginx::Headers_out#[]=
```ruby
hout = Nginx::Headers_out.new

hout["X-NGX-MRUBY"] = "support"
Nginx.rputs hout["X-NGX-MRUBY"] #=> support
```
#### Nginx::Headers_out#all
```ruby
hout = Nginx::Headers_out.new

hout["X-NGX-MRUBY"] = "support"
hout.all.keys.each do |k|
  Server.echo "#{k}: #{hout[k]}"
end
# => $ curl -v http://192.168.12.9:8001/hello?a=1
# => X-NGX-MRUBY: support
```
#### Nginx::Headers_in#delete
```ruby
hout = Nginx::Headers_in.new

hout["X-Remove-Header"] = "to be deleted!"
hout.delete("X-Remove-Header")
Nginx.rputs hout["X-Remove-Header"] #=> nil
```
## Nginx::Filter Class

__Warning!!__ Nginx::Filter Class can be used only at mruby_output_body_filter{,_code} phase. You can NOT use ``Nginx.rputs and Nginx.echo`` at the same phase.

### Example

```nginx
location /issue_172 {
  # or mruby_output_header_filter /path/to/code.rb
  mruby_output_header_filter_code '
    Nginx::Request.new.headers_out["x-add-new-header"] = "new_header"
  ';

  # or mruby_output_body_filter /path/to/code.rb
  mruby_output_body_filter_code '
     f = Nginx::Filter.new
     response = f.body
     f.body = (response + " world").upcase
  ';
}

# cat test/html/issue_172_2/index.html 
# hello

location /issue_172_2 {
  root   html;
  index  index.html index.htm;
  mruby_output_body_filter_code '
     Nginx::Request.new.headers_out["hoge"] = "fuga"
     f = Nginx::Filter.new
     response = f.body
     f.body = (response + " world").upcase
  ';
}
```

- test

```
t.assert('ngx_mruby - issue_172_2', 'location /issue_172_2') do
  res = HttpRequest.new.get base + '/issue_172_2/'
  expect_content = 'hello world'.upcase
  t.assert_equal expect_content, res["body"]
  t.assert_equal expect_content.length, res["content-length"].to_i
end
```

### Method
#### Nginx::Filter#body
index.html
```
hello
```
Reuqest to index.html
```bash
$ curl http://127.0.0.1/index.html
hello
```
output filter by ngx_mruby
```ruby
f = Nginx::Filter.new

response = f.body
f.body = (response + " world").upcase 
```
```bash
$ curl http://127.0.0.1/index.html
HELLO WORLD
```
#### Nginx::Filter#body=
See ``Nginx::Filter#body``
#### Nginx::Filter#output
alias ``Nginx::Filter#body=``

## Nginx::Upstream Class
### Method
###### Nginx::Upstream#{new,keepalive_cache,keepalive_cach=,server,server=}
```nginx
http {
    # defined upstream config for mruby
    upstream mruby_upstream {
      server 127.0.0.1:80;
      mruby_upstream_keepalive 16;
    }
    server {
        location /upstream-keepalive {
          # update server config of mruby_upstream config
          mruby_rewrite_handler_code '
            u = Nginx::Upstream.new "mruby_upstream"
            u.server = "127.0.0.1:58081"
            Nginx.errlogger Nginx::LOG_NOTICE, "front: keepalive_cache: #{u.keepalive_cache}"
            Nginx.errlogger Nginx::LOG_NOTICE, "front: #{u.hostname}: #{u.server}"
            Nginx.return Nginx::DECLINED
          ';

          # proxy to mruby_upstream which was update via mruby
          proxy_pass http://mruby_upstream/keepalive;

          # connect to backend with keepalive
          proxy_http_version 1.1;
          proxy_set_header Connection "";
          proxy_send_timeout 2s;
          proxy_read_timeout 2s;
          proxy_connect_timeout 2s;
        }
    }
}
```

## Nginx::Async Class
### Method
#### Nginx::Async#sleep
Do non-blocking sleep. Currenly it supports only rewrite and access phases.
```ruby
# sleep 3000 millisec
Nginx::Async.sleep 3000
```

## Nginx::Stream class
- example

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
### Nginx::Stream.add_listener

Listen port dynamicaly using Ruby on config phase

```ruby
Nginx::Stream.add_listener({address: "127.0.0.1:12350"})
Nginx::Stream.add_listener({address: "12351"})
```

- nginx.conf example

```nginx
stream {
  server {
      mruby_stream_server_context_code '
        (12360..12460).each { |local_port| Nginx::Stream.add_listener({address: local_port.to_s}) }
      ';
  }
}
```

### Nginx::Stream constants
#### stream_status code
```ruby
  Nginx::Stream::OK                                                                                                      
  Nginx::Stream::ERROR                                                                                                   
  Nginx::Stream::AGAIN                                                                                                   
  Nginx::Stream::BUSY                                                                                                    
  Nginx::Stream::DONE                                                                                                    
  Nginx::Stream::DECLINED                                                                                                
  Nginx::Stream::ABORT
```

#### log priority
```ruby                                                                                   
  Nginx::Stream::LOG_ALERT                                                                                               
  Nginx::Stream::LOG_CRIT                                                                                                
  Nginx::Stream::LOG_ERR                                                                                                 
  Nginx::Stream::LOG_WARN                                                                                                
  Nginx::Stream::LOG_NOTICE                                                                                              
  Nginx::Stream::LOG_INFO                                                                                                
  Nginx::Stream::LOG_DEBUG                                                                                               
```

### Nginx::Stream.log
```ruby
Nginx::Stream.log Nginx::Stream::LOG_NOTICE, "logging something"
```

### Nginx::Stream.errlogger
alias to `Nginx::Stream.log`

### Nginx::Stream.module_name
```ruby
Nginx::Stream.module_name #=> "ngx_mruby-stream-module"
```

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

## ngx_mruby HTTP module Writing Hooks by a Directive
### General
Hook your ruby script each phases. See [directives](https://github.com/matsumotory/ngx_mruby/docs/directives#directives).
#### Set file path
```nginx
location /hello {
    mruby_content_handler /path/to/hello.rb;
}
```
#### Set file path and code cached
```nginx
location /hello {
    mruby_content_handler /path/to/hello.rb cache;
}
```
#### Set inline code and code cached
```nginx
location /hello {
    mruby_content_handler_code '
        Nginx.rputs "hello"
        Nginx.echo "world!"
    ';
}
```
### Others
#### mruby_set or mruby_set_code
return value from ruby script into nginx variables. These directives are only wrote like following:
```nginx
location /proxy {
    mruby_set $backend /path/to/proxy.rb;
}
```
or
```nginx
location /proxy {
    mruby_set $backend /path/to/proxy.rb cache;
}
```
or
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
#### mruby_add_handler
run a request file on mruby VM. This directive is only wrote like following:
```nginx
location ~ \.rb$ {
    mruby_add_handler on;
}
```
#### mruby_init, mruby_init_code, mruby_init_worker, mruby_exit_worker
write those directives on __http{}__ config
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
## ngx_mruby HTTP module Directives
Context | Derective                    |Hook Phase               |Description
----|-----------------------------|----------------------------|---------------------
http | mruby_init /path/to/code.rb  |init main configuration phase|__[http conf]__ write file path in ngxin.conf 
http | mruby_init_code inline-code|init main configuration phase|__[http conf]__ write inline Ruby code in nginx.conf
http | mruby_init_worker /path/to/code.rb  |init worker process phase|__[http conf]__ write file path in ngxin.conf 
http | mruby_init_worker_code inline-code |init worker process phase|__[http conf]__ write inline Ruby code in ngxin.conf 
http | mruby_exit_worker /path/to/code.rb  |exit worker process phase|__[http conf]__ write file path in ngxin.conf 
http | mruby_exit_worker_code inline-code |exit worker process phase|__[http conf]__ write inline Ruby code in ngxin.conf 
server | mruby_ssl_handshake_handler /path/to/code.rb  |ssl handshake phase|__[server conf]__ write file path in ngxin.conf 
server | mruby_ssl_handshake_handler_code inline-code |ssl handshake phase|__[server conf]__ write inline Ruby code in ngxin.conf 
server | mruby_ssl_verify_client_handler /path/to/code.rb |ssl handshake phase| __server conf]__ write file path in nginx.conf
server | mruby_ssl_verify_client_handler_code inline-code |ssl handshake phase|__[server conf]__ write inline Ruby code in ngxin.conf 
server, location | mruby_add_handler|create location configuration phase|__[location conf]__  
server | mruby_post_read_handler /path/to/code.rb |NGX_HTTP_POST_READ_PHASE|__[location conf]__  write file path in ngxin.conf 
server | mruby_post_read_handler_code inline-code|NGX_HTTP_POST_READ_PHASE|__[location conf]__  write inline Ruby code in nginx.conf
server, location | mruby_server_rewrite_handle /path/to/code.rb r|NGX_HTTP_SERVER_REWRITE_PHASE|__[location conf]__  write file path in ngxin.conf 
server, location | mruby_server_rewrite_handler_code inline-code|NGX_HTTP_SERVER_REWRITE_PHASE|__[location conf]__  write inline Ruby code in nginx.conf
server, location | mruby_rewrite_handler /path/to/code.rb |NGX_HTTP_REWRITE_PHASE|__[location conf]__ write file path in ngxin.conf 
server, location | mruby_rewrite_handler_code inline-code|NGX_HTTP_REWRITE_PHASE|__[location conf]__ write inline Ruby code in nginx.conf
server, location | mruby_access_handler /path/to/code.rb |NGX_HTTP_ACCESS_PHASE|__[location conf]__ write file path in ngxin.conf 
server, location | mruby_access_handler_code inline-code|NGX_HTTP_ACCESS_PHASE|__[location conf]__ write inline Ruby code in nginx.conf
server, location | mruby_content_handler /path/to/code.rb |NGX_HTTP_CONTENT_PHASE|__[location conf]__ write file path in ngxin.conf 
server, location | mruby_content_handler_code inline-code|NGX_HTTP_CONTENT_PHASE|__[location conf]__ write inline Ruby code in nginx.conf
server, location | mruby_log_handler /path/to/code.rb |NGX_HTTP_LOG_PHASE|__[location conf]__ write file path in ngxin.conf 
server, location | mruby_log_handler_code inline-code|NGX_HTTP_LOG_PHASE|__[location conf]__ write inline Ruby code in nginx.conf
server, location | mruby_set /path/to/code.rb |NGX_HTTP_{REWRITE,SERVER_REWRITE}_PHASE|__[location conf]__ write file path in ngxin.conf 
server, location | mruby_set_code inline-code|NGX_HTTP_{REWRITE,SERVER_REWRITE}_PHASE|__[location conf]__ write inline Ruby code in nginx.conf
server, location | mruby_output_body_filter /path/to/code.rb |output body filter phase|__[location conf]__ write file path in ngxin.conf 
server, location | mruby_output_body_filter_code inline-code|output body filter phase|__[location conf]__ write inline Ruby code in nginx.conf
server, location | mruby_output_header_filter /path/to/code.rb |output header filter phase|__[location conf]__ write file path in ngxin.conf 
server, location | mruby_output_header_filter_code inline-code|output header filter phase|__[location conf]__ write inline Ruby code in nginx.conf
server, location | mruby_enable_read_request_body on | | enabled read request body feature



## ngx_mruby STREAM module Writing Hooks by a Directive
### General
Hook your ruby script each pahses. See [directives](https://github.com/matsumotory/ngx_mruby/docs/directives#directives).
#### Set file path
```nginx
server {
    mruby_stream /path/to/stream.rb;
}
```
#### Set inline code and code cached
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
### Others
#### mruby_stream_init, mruby_stream_init_code, mruby_stream_init_worker, mruby_stream_exit_worker
write those directives on __http{}__ config
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
```

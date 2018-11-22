# Overview

ngx_mruby enables you to run mruby scripts on nginx. For example, you can implement:

* [your own auth mechanism](../use_case#file-based-access-list) like nginx's [auth_basic](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-http-basic-authentication/)
* [reverse proxy with your own backend selection algorithm](../use_case#reverse-proxy)
* [content handler that returns any HTTP response](../use_case#hello-world)

See the [Use Cases](../use_case) page for more examples.
The scripts can be invoked at any of nginx HTTP phases. See nginx's [Phases doc](http://nginx.org/en/docs/dev/development_guide.html#http_phases) for more details of the phases.

ngx_mruby provides 2 modules. One is HTTP module for HTTP, the other is Stream module for TCP/UDP stream.
See [HTTP module directives](#http-module-directives) and [Stream module directive](#stream-module-directives) section for more details.

Here is an example of a content handler for HTTP.

#### nginx.conf
```nginx
location /hello {
    mruby_content_handler /path/to/hello.rb;
}
```

#### /path/to/hello.rb
```
Nginx.echo "Hello World"
```

```
$ curl http://127.0.0.1/hello
Hello World
```

'mruby_content_handler' is a directive to specify a mruby script file that is invoked at NGX_HTTP_CONTENT_PHASE to generate the response.
You will get 'Hello World' as a HTTP response body if you access '/hello' endpoint.

'Nginx.echo' is a method to creates a response body. ngx_mruby provides classes for accessing or manipulating nginx internal data structures. See [Class for ngx_mruby](../class_and_method) for more information.

## Caching compile code

By default, mruby script is compiled whenever it is invoked.
You can enable compiled code cache with 'cache' argument for performance.

#### nginx.conf
```nginx
location /hello {
    mruby_content_handler /path/to/hello.rb cache;
}
```

## Inline code

You can write mruby code in nginx.conf instead of creating a script file. The compiled code is cached.

#### nginx.conf
```nginx
location /hello {
    mruby_content_handler_code '
        Nginx.echo "Hello World"
    ';
}
```

## Nginx variables

You can set nginx variable by using a mruby script (Note: The script is invoked at NGX_HTTP_SERVER_REWRITE_PHASE or NGX_HTTP_REWRITE_PHASE).
The following example set a value returned from 'proxy.rb' to the variable '$backend'.

#### nginx.conf
```nginx
location /proxy {
    mruby_set $backend /path/to/proxy.rb;
}
```

Also you can enable caching, or write inline mruby code as same as other directives.

#### nginx.conf
```nginx
location /proxy {
    mruby_set $backend /path/to/proxy.rb cache;
}
```

#### nginx.conf
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

# HTTP module directives

* [mruby_init and mruby_init_code](#mruby_init-and-mruby_init_code)
* [mruby_init_worker and mruby_init_worker_code](#mruby_init_worker-and-mruby_init_worker_code)
* [mruby_exit_worker and mruby_exit_worker_code](#mruby_exit_worker-and-mruby_exit_worker_code)
* [mruby_ssl_handshake_handler and mruby_ssl_handshake_handler_code](#mruby_ssl_handshake_handler-and-mruby_ssl_handshake_handler_code)
* [mruby_add_handler](#mruby_add_handler)
* [mruby_post_read_handler and mruby_post_read_handler_code](#mruby_post_read_handler-and-mruby_post_read_handler_code)
* [mruby_server_rewrite_handler, mruby_server_rewrite_handler_code, mruby_rewrite_handler and mruby_rewrite_handler_code](#mruby_server_rewrite_handler-mruby_server_rewrite_handler_code-mruby_rewrite_handler-and-mruby_rewrite_handler_code)
* [mruby_access_handler and mruby_access_handler_code](#mruby_access_handler-and-mruby_access_handler_code)
* [mruby_content_handler and mruby_content_handler_code](#mruby_content_handler-and-mruby_content_handler_code)
* [mruby_log_handler and mruby_log_handler_code](#mruby_log_handler-and-mruby_log_handler_code)
* [mruby_set and mruby_set_code](#mruby_set-and-mruby_set_code)
* [mruby_output_body_filter, mruby_output_body_filter_code, mruby_output_header_filter and mruby_output_header_filter_code](#mruby_output_body_filter-mruby_output_body_filter_code-mruby_output_header_filter-and-mruby_output_header_filter_code)
* [ruby_enable_read_request_body](#mruby_enable_read_request_body)

TODO

* Add missing directives
  * mruby_server_context_handler_code
  * mruby_cache
* Add examples

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

## mruby_add_handler

```
Syntax:  mruby_add_handler on | off;
Default: off
Context: server, location
Phase:   initialize master process
```

When set to the value on, mruby scripts are added as handlers.
You can run the script files directly without endpoint definition.

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

# Stream module directives

ngx_mruby also supports TCP/UDP stream. The stream module directives are similar to The HTTP module directives.
Here are examples of the stream module directives.

#### nginx.conf
```nginx
server {
    mruby_stream /path/to/stream.rb;
}
```

#### nginx.conf
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

#### nginx.conf

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

TODO

* Add descriptions to the above examples
* Add directive references like HTTP module

## What's ngx_mruby
__ngx_murby is A Fast and Memory-Efficient Web Server Extension Mechanism Using Scripting Language mruby for nginx._
ngx_mruby is to provide an alternative to mod_mruby for nginx.

nginx modules can be implemeted by mruby scripts on nginx installed ngx_mruby.

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

## How to use

### 1. Download

    git clone git://github.com/matsumoto-r/ngx_mruby.git
    cd ngx_mruby
    git submodule init
    git submodule update

### 2. Build
* configure example

        ./configure --with-ngx-src-root=${NGINX_SRC} --with-ngx-config-opt="--prefix=/usr/local/nginx"

* mruby build

        make build_mruby

* ngx_mruby build

        make 
or  

        cd ${NGINX_SRC}
        ./configure --prefix=/usr/local/nginx --add-module=${NGX_MRUBY_SRC} --add-module=${SOME_MODULE}
        make


### 3. Install

    sudo make install

### 4. Add setting

    location /mruby {
        mruby_content_handler /usr/local/nginx122/html/hello.rb;
    }

### 5. Create mruby script /usr/local/nginx/html/hello.rb

    Nginx.rputs(Time.now.to_s + "hello mruby world for nginx.")

### 6. Start nginx

    /usr/local/nginx/sbin/nginx

### 7. Access http://example.com/mruby (sed/example.com/mydomain/)

    Sat Jul 28 18:05:51 2012 hello mruby world for nginx.

Display above. Welcome mruby world for nginx!!



# License
under the MIT License:

* http://www.opensource.org/licenses/mit-license.php


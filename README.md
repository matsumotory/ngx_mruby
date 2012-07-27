## What's ngx_mruby
ngx_mruby - to provide an alternative to mod_mruby for nginx.

nginx modules can be implemeted by mruby scripts on nginx installed ngx_mruby.

## How to use (experiment)
* Download
    git clone git://github.com/matsumoto-r/ngx_mruby.git

* Set mruby directory
    mruby_root=/usr/local/src/mruby

* Download nginx1.2.2stable
    wget http://nginx.org/download/nginx-1.2.2.tar.gz

* Build nginx with ngx_mruby
    ./configure --add-module=/usr/local/src/ngx_mruby --prefix=/usr/local/nginx122
    make
    sudo make install

* Add setting
    location /mruby {
        mrubyHandler /usr/local/nginx122/html/hello.mrb;
    }

* Create mruby script /usr/local/nginx122/html/hello.mrb
    Nginx.rputs("hello mruby world for nginx.")

* Start nginx
    /usr/local/nginx122/sbin/nginx

* Access http://example.com/mruby (sed/example.com/mydomain/¡Ë
    hello mruby world for nginx.

Display above. Welcome mruby world for nginx!!

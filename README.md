## What's ngx_mruby
ngx_mruby - to provide an alternative to mod_mruby for nginx.

nginx modules can be implemeted by mruby scripts on nginx installed ngx_mruby.

## How to use (experiment)

* まずはGithubからソースをダウンロードします。

    git clone git://github.com/matsumoto-r/ngx_mruby.git

* そして、configファイルを開いて、mrubyがインストールされているPathを変更して下さい。僕の場合は以下のようにしています。

    mruby_root=/usr/local/src/mruby

* nginx1.2.2stableをダウンロードします。

    wget http://nginx.org/download/nginx-1.2.2.tar.gz

* ダウンロード後、展開して以下のコマンドでngx_mrubyをモジュールとして指定してnginxそのものをコンパイルします。

    ./configure --add-module=/usr/local/src/ngx_mruby --prefix=/usr/local/nginx122
    make
    sudo make install

* コンパイル後、nginx.confの設定に以下のような設定を加えます。

    location /mruby {
        mrubyHandler /usr/local/nginx122/html/hello.mrb;
    }

* 指定したmrubyスクリプト（/usr/local/nginx122/html/hello.mrb）に以下のメソッドを記述します。

    Nginx.rputs("hello mruby world for nginx.")

* では、nginxを起動します。

    /usr/local/nginx122/sbin/nginx

* そして、http://example.com/mrubyにアクセスしてみましょう。（example.comを自ドメインに置き換えて下さい）

    hello mruby world for nginx.

と表示されたら成功です。ようこそ！mruby world for nginxへ！！

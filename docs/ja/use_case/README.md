# ユースケース

このページでは、ユースケースごとに、CIが実行するサンプルをこのページかリンク先のガイドに載せるか、テストしていないことと、その理由を書いています。サンプルは、このリポジトリのテストのファイルと、そのテストがCIのたびに比べるレスポンスを示します。サンプルの仕組みは、サイトの構想の3.5にあります。

## Hello world

contentハンドラがレスポンスを書きます。

```sample
case: test/t/cases/guides.rb
conf: test/conf/conf.d/72-guide-hello.conf
script: test/html/guide_hello.rb
request: test/html/guide_hello.request
response: test/html/guide_hello.response
```

「はじめに」の[ページ](../start/README.md)では、同じ種類のハンドラをDockerで動かします。

## リバース<wbr>プロキシ

スクリプトが、リクエストごとに`proxy_pass`のバックエンドを選びます。サンプルは、ガイドの[バックエンドへリクエストを振り分ける](../guides/routing.md)にあります。

## ファイルによる<wbr>アクセスリスト

accessハンドラは、ファイルに載ったクライアントに403を返します。サンプルは、ガイドの[ファイルに載せたクライアントを拒否する](../guides/access-control.md)にあります。

## Markdownを<wbr>HTMLに<wbr>変換する<wbr>出力フィルタ

ボディフィルタが、`.md`のファイルのボディをHTMLに変換します。フィルタの部分は、ガイドの[レスポンスのボディを変える](../guides/body-filter.md)のサンプルです。そのサンプルは、テキストファイルをHTMLのページで包みます。

**テストしていません**。Markdownの変換には、gemのmruby-discountが要ります。`build_config.rb`ではmruby-discountの行がコメントになっていて、このgemはビルドに入りません。このgemをビルドするCIのジョブもありません。試すには、`build_config.rb`のmruby-discountの行のコメントを外し、ビルドし直してください。

```nginx
location ~ \.md$ {
    mruby_output_body_filter /path/to/filter.rb cache;
}
```

```ruby
# /path/to/filter.rb
f = Nginx::Filter.new

css = "/css/markdown.css"   # a stylesheet that your server serves
md = Discount.new css, "markdown"

f.body = md.md2html f.body
```

## Redisで<wbr>メンテナンス<wbr>モードに<wbr>切り替える

accessハンドラが、Redisからフラグを読み、フラグが立っている間は503を返します。フラグが立っていなければ、nginxがリクエストをプロキシします。この例は、takeswimによる日本語の[記事](https://takeswim.hateblo.jp/entry/2013/10/03/182748)を元にしています。

**テストしていません**。CIのテストのジョブはRedisのサーバを動かさないので、この例を実行するサンプルはありません。デフォルトのビルドは、この例が使う`Redis`のクラスを持つgemのmruby-redisを含みます。

```nginx
location / {
    mruby_access_handler_code '
        redis = Redis.new "127.0.0.1", 6379
        maintenance = redis.get("maintenance") == "on"
        redis.close
        Nginx.return Nginx::HTTP_SERVICE_UNAVAILABLE if maintenance
    ';
    proxy_pass http://127.0.0.1:8080;
}
```

mruby-redisは、Redisのサーバの応答をワーカーの中で1つずつ待つので、その間ワーカーはほかのリクエストを処理しません。

## Markdownの<wbr>ウェブページ

このcontentハンドラは、MarkdownのテキストをHTMLのページに変換します。

**テストしていません**。gemのmruby-discountが要ります。`build_config.rb`ではmruby-discountの行がコメントになっていて、このgemはビルドに入りません。このgemをビルドするCIのジョブもありません。試すには、mruby-discountの行のコメントを外し、ビルドし直してください。

```nginx
location ~ \.rb$ {
    mruby_add_handler on;
}
```

```ruby
# md.rb, under the root of the location
r = Nginx::Request.new
r.content_type = "text/html"

md = Discount.new "/css/markdown.css", "md test"

body = <<DATA
# Section

- item 1
- item 2
DATA

Nginx.echo md.header + body.to_html + md.footer
```

## Dropboxの<wbr>リンクのような<wbr>ファイルサーバ

rewriteハンドラは、リクエストのパスをRedisで探し、リンクの期限が切れるまでそのファイルへリダイレクトします。

**テストしていません**。CIのテストのジョブはRedisのサーバを動かさないので、このユースケースを実行するサンプルはありません。デフォルトのビルドは、gemのmruby-redisを含んでいます。

```nginx
location /dropbox {
    mruby_rewrite_handler /path/to/dropbox.rb;
}
```

```ruby
# /path/to/dropbox.rb
redis = Redis.new "127.0.0.1", 6379
r = Nginx::Request.new
file = redis.hget r.uri, "file"
expire = redis.hget r.uri, "expire"
redis.close

if file && expire.to_i >= Time.now.to_i
  Nginx.redirect file
else
  Nginx.return Nginx::DECLINED
end
```

リンクはRedisのハッシュです。たとえば`redis-cli`でこう作ります。

```text
HSET /dropbox/aaabbbcccddd file /files/hoge.html
HSET /dropbox/aaabbbcccddd expire 1900000000
```

## 記事と<wbr>ほかの例

- 日本語の記事の[Dynamic Image Provider](https://techhey.hatenablog.com/entry/2014/04/19/162323)
- ロシア語の記事の[Research ngx_mruby and use output filter](https://habr.com/ru/articles/225313/)
- [Let's Encryptを使ったACMEのauto ssl](https://github.com/matsumotory/ngx_mruby/blob/v2.7.2/test/conf/auto-ssl/nginx.conf.client_example)(ngx_mruby 2.x)：auto-sslのmrbgemと、動いているRedisのサーバが要ります。ngx_mruby 3.0.0にはこのgemがありません。詳しくは[auto-sslのmrbgemと、それと一緒に入っていたクラス](../install/README.md#auto-sslのmrbgemとそれと一緒に入っていたクラス)にあります。この例のACMEのクライアントはACMEv1を使いますが、Let's EncryptはもうACMEv1を提供していません。

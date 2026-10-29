# バックエンドを選ぶ

nginxは、`proxy_pass`でリクエストをバックエンドへ渡します。[`mruby_set`](../../directives/README.md#mruby_set-and-mruby_set_code)を使うと、Rubyのスクリプトがリクエストごとにバックエンドを決め、`proxy_pass`はスクリプトが設定した変数を使います。その後、nginxがバックエンドに接続し、受け取ったレスポンスを中継します。スクリプトはリクエストごとに1回動き、文字列を返します。

## サンプル

スクリプトは、リクエストヘッダ`X-Tenant`と、テナントとバックエンドのアドレスのテーブルから、バックエンドを選びます。ヘッダの無いリクエストと、テーブルに無いテナントのリクエストには、どちらもバックエンド`a`を選びます。スクリプトの最後の行の値が、`$backend`の値になります。

```sample
case: test/t/cases/guides.rb
conf: test/conf/conf.d/73-guide-routing.conf
script: test/html/guide_routing.rb
request: test/html/guide_routing.request
response: test/html/guide_routing.response
```

ケースは`X-Tenant`の無いリクエストも送り、ポート18164のバックエンド`a`のレスポンスを期待します。

## 気を<wbr>つけること

- `mruby_set`は、locationのrewriteフェーズで、nginxがバックエンドに接続する前に動きます。フェーズの順は[リクエストのフェーズ](../concepts/request-phases.md)にあります。スクリプトは`Nginx::Request`でリクエストを読みます。レスポンスは見えません。
- 変数を使った`proxy_pass`は、アドレスをそのまま使います。値が`upstream`ブロックの名前なら、そのブロックを使います。それ以外のホスト名には、nginxの`resolver`ディレクティブが要ります。
- リクエストヘッダはクライアントの入力です。スクリプトはヘッダをテーブルのキーと比べるので、クライアントはテーブルにあるバックエンドにしか届きません。詳しくは[信頼境界](../../security/trust-boundary.md)にあります。
- `cache`が無いと、nginxはリクエストのたびにスクリプトのファイルを読みます。本番では、ディレクティブに`cache`を付けるか、`mruby_set_code`を使ってください。詳しくは[コンパイルしたコードのキャッシュ](../../directives/README.md#caching-compile-code)にあります。

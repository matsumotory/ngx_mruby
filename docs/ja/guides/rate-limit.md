# レートを制限する

nginxの`limit_req`は、すべてのワーカーが使う共有メモリのゾーンで、キーごとにリクエストを数え、レートを超えたリクエストを拒否します。キーには、nginxのどの変数でも使えます。Rubyのスクリプトが[`mruby_set`](../../directives/README.md#mruby_set-and-mruby_set_code)でキーを計算すれば、APIキーのような、Rubyがリクエストから取り出した値ごとに制限をかけられます。カウンタはnginxが持ちます。

## サンプル

スクリプトは、リクエストヘッダ`X-API-Key`のAPIキーを返します。ヘッダの無いリクエストではクライアントのアドレスを返し、キーが空のリクエストを作りません。`limit_req`は、キーが空のリクエストを数えないためです。ゾーンは、キーごとに1分に1リクエストを許します。nginxは、`limit_req_status 429`と`error_page 429 @limited`に従って、拒否したリクエストのレスポンスをステータス429とJSONのボディにします。

```sample
case: test/t/cases/guides.rb
conf: test/conf/conf.d/75-guide-rate-limit.conf
script: test/html/guide_rate_limit.rb
request: test/html/guide_rate_limit.request
response: test/html/guide_rate_limit.response
```

ケースはリクエストを2回送ります。1回目のレスポンスは、ボディが`accepted`の200です。同じ1分のうちに送った2回目のリクエストには、上のレスポンスが返ります。

## 気を<wbr>つけること

- `mruby_set`はrewriteフェーズで動き、`limit_req`はその後のpreaccessフェーズで動きます。そのため、nginxがリクエストを数えるときには、変数に値が入っています。フェーズの順は[リクエストのフェーズ](../concepts/request-phases.md)にあります。
- カウンタは、Rubyではなくnginxの共有メモリのゾーンにあります。各ワーカーは自分の`mrb_state`を持つので、Rubyのグローバル変数のカウンタでは、1つのワーカーのリクエストしか数えられません。
- `limit_req_zone`は`http`ブロックのディレクティブです。`limit_req`と`limit_req_status`は、`http`ブロック、`server`、`location`に書けます。

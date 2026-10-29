# アクセスを拒否する

accessハンドラは、locationのcontentの前に、nginxのaccessフェーズで動きます。そこで動くスクリプトは、403のようなステータスでリクエストを終えるか、ステータスを設定せずに戻ってリクエストを先へ進めます。詳しくは[`mruby_access_handler`](../../directives/README.md#mruby_access_handler-and-mruby_access_handler_code)にあります。このガイドでは、ファイルに載せたクライアントを、accessハンドラで拒否します。

## サンプル

accessハンドラは、変数`$deny_list`が指すファイルを読み、クライアントのアドレスがファイルの行のどれかと同じなら403を返します。location`/listed/`が指すリストには、テストのクライアントのアドレスである`127.0.0.1`があるので、リクエストは403になります。nginxは、`error_page 403 @denied`に従って、その403にボディを付けます。location`/open/`が指すリストには、そのアドレスがありません。

```sample
case: test/t/cases/guides.rb
conf: test/conf/conf.d/74-guide-access.conf
script: test/html/guide_access.rb
request: test/html/guide_access.request
response: test/html/guide_access.response
```

ケースは`GET /open/report`も送って、ボディが`welcome`の200を期待します。

## 気を<wbr>つけること

- スクリプトはリクエストのたびにリストのファイルを読むので、ディスクが答えるまでワーカーをブロックします。ワーカーごとに1回だけ読むには、`mruby_init_worker_code`でリストを定数に読み込み、ファイルを変えたらnginxをリロードしてください。詳しくは[ワーカーがリクエストをまたいで保つもの](../concepts/lifetimes.md#ワーカーがリクエストをまたいで保つもの)にあります。
- `r.var.remote_addr`の値は、TCPの接続相手のアドレスです。ロードバランサの後ろでは、nginxのrealipモジュールがロードバランサの送るヘッダからアドレスを設定しない限り、そのロードバランサのアドレスになります。
- `Nginx.return Nginx::HTTP_FORBIDDEN`はステータス403でリクエストを終えます。`Nginx.return`を呼ばずに戻るスクリプトでは、nginxはaccessフェーズの次のハンドラを実行し、その後contentへ進みます。

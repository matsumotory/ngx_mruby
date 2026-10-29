# TCPの接続を許可する

streamモジュールは、TCPの接続をプロキシし、`listen ... udp`ではUDPのセッションもプロキシします。`stream`ブロックの`server`では、[`mruby_stream`](../../directives/README.md#stream-module-directives)で指定したRubyのスクリプトが、streamモジュールのaccessフェーズで動きます。スクリプトは、nginxがupstreamに接続する前に、セッションごとに1回動きます。スクリプトは`Nginx::Stream::Connection`でセッションのアドレスを読み、`stream_status`を`Nginx::Stream::ABORT`にしてセッションを閉じます。

## サンプル

スクリプトは、リストにあるアドレスからのセッションだけを通します。その後、nginxは接続をupstreamへプロキシします。ここでのupstreamは、テストの設定にあるポート18168のHTTPのサーバです。リクエストとレスポンスは、クライアントがTCPの接続で送るバイト列と受け取るバイト列です。

```sample
case: test/t/cases/guides.rb
conf: test/conf/conf.d/stream/42-guide-tcp.conf
script: test/html/guide_tcp.rb
request: test/html/guide_tcp.request
response: test/html/guide_tcp.response
```

## 気を<wbr>つけること

- streamモジュールは、UDPのセッションでもスクリプトを実行します。テストスイートが送るのはTCPだけです。
- スクリプトはnginxがクライアントのデータを読む前に動くので、判断に使えるのは、クライアントが送る内容ではなく、セッションのアドレスとポートです。
- `stream`ブロックは、`http`ブロックとは別に自分専用の`mrb_state`を持ちます。起動時のコードにも、`stream`ブロック専用のディレクティブの`mruby_stream_init`と`mruby_stream_init_worker`があります。

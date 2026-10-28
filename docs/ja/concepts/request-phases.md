# リクエストのフェーズ

nginxは、HTTPのリクエストを決まった順のフェーズで処理します。ngx_mrubyは、そのうちの6つのフェーズにハンドラを加えます。また、rewriteモジュールの中で`mruby_set`を実行し、ヘッダとボディのフィルタをnginxのフィルタの連鎖の先頭に置きます。TLSのハンドシェイクの間にも、ハンドラを1つ実行します。TCPとUDPでは、nginxのstreamモジュールのaccessフェーズで、ハンドラを1つ実行します。

```diagram
request-phases
caption: nginxがHTTPのリクエストを処理するフェーズを順に並べ、各フェーズでRubyを実行するngx_mrubyのディレクティブを示します。TCPとUDPのセッションで実行するハンドラも示します。
source: src/http/ngx_http_mruby_module.c 431 638-721 1742-1824 1954-1965
source: src/stream/ngx_stream_mruby_module.c 787
nginx: 1.31.6 src/http/ngx_http_core_module.h 111-128
at: 0c72e3970 2026-10-19
h-phase: nginxが<wbr>処理する<wbr>順
h-handler: ngx_mrubyが<wbr>Rubyを<wbr>実行する<wbr>場所
tls: TLSの<wbr>ハンドシェイク
tls-h: `mruby_ssl_handshake_handler`
post-read: post-read
post-read-h: `mruby_post_read_handler`
server-rewrite: server rewrite
server-rewrite-h: `mruby_server_rewrite_handler`
server-rewrite-set: rewriteモジュールの<wbr>`mruby_set`
find-config: find config
rewrite: rewrite
rewrite-h: `mruby_rewrite_handler`
rewrite-set: rewriteモジュールの<wbr>`mruby_set`
post-rewrite: post-rewriteと<wbr>preaccess
access: access
access-h: `mruby_access_handler`
post-access: post-accessと<wbr>precontent
content: content
content-h: `mruby_content_handler`
header-filter: ヘッダの<wbr>フィルタ
header-filter-h: `mruby_output_header_filter`
body-filter: ボディの<wbr>フィルタ
body-filter-h: `mruby_output_body_filter`
log: log
log-h: `mruby_log_handler`
stream: TCPか<wbr>UDPの<wbr>access
stream-h: `mruby_stream`
```

表の各ディレクティブは、Rubyのスクリプトのパスを受け取ります。どのディレクティブにも、`mruby_access_handler_code`のように名前の最後に`_code`が付く形があります。その形は、Rubyのコードを直接受け取ります。

| 実行する時点 | ディレクティブ |
|---|---|
| TLSのハンドシェイク | `mruby_ssl_handshake_handler` |
| post-read | `mruby_post_read_handler` |
| server rewrite | `mruby_server_rewrite_handler` |
| rewrite | `mruby_rewrite_handler` |
| access | `mruby_access_handler` |
| content | `mruby_content_handler` |
| レスポンスのヘッダを送るとき | `mruby_output_header_filter` |
| レスポンスのボディを送るとき | `mruby_output_body_filter` |
| log | `mruby_log_handler` |
| rewriteモジュールが動くserver rewriteとrewrite | `mruby_set` |
| streamモジュールのaccess | `mruby_stream` |

nginxは、リクエストを読む前にTLSのハンドシェイクを済ませます。find config、post-rewrite、preaccess、post-access、precontentの各フェーズでは、ngx_mrubyのハンドラは動きません。`mruby_set`は、rewriteモジュールが`set`を実行するところで、Rubyで変数を設定します。`server`ブロックに書いた`mruby_set`はserver rewriteフェーズで動き、`location`に書いた`mruby_set`はrewriteフェーズで動きます。ヘッダのフィルタとボディのフィルタは、contentフェーズかupstreamのレスポンスをnginxが送る間に動くので、logフェーズより前に来ます。`mruby_post_read_handler`は`http`と`server`のブロックに、`mruby_ssl_handshake_handler`は`server`ブロックに書けます。ほかのハンドラは`location`にも書けます。

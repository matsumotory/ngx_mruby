# フィルタ

nginxは、レスポンスのヘッダとボディを2つのフィルタチェーンに通して送ります。レスポンスを作ったのがどのハンドラでも、upstreamでも同じです。ngx_mrubyは、それぞれのチェーンにフィルタを1つずつ加えます。ヘッダに対してRubyを実行するのは`mruby_output_header_filter`とその`_code`の形で、ボディに対して実行するのは`mruby_output_body_filter`とその`_code`の形です。設定に2つのディレクティブのどちらかがあると、ngx_mrubyはヘッダフィルタを加えます。ボディフィルタは、設定にボディフィルタのディレクティブがあるときに加えます。

```diagram
filter-chain
caption: nginxが呼ぶ順にヘッダフィルタとボディフィルタを並べ、ngx_mrubyのフィルタと、ngx_mrubyの各フィルタが受け取るものを示します。
source: src/http/ngx_http_mruby_module.c 591-595 1676-1677 1955-1965 2041-2054 2085-2122 2135-2154
source: config.in 48-69
nginx: 1.31.6 auto/modules 165-187 386-427 1494-1495
nginx: 1.31.6 auto/module 23-30
at: 0c72e3970 2026-10-19
h-header: ヘッダフィルタ
hn: nginxの<wbr>not modifiedの<wbr>ヘッダフィルタ
hm: `mruby_output_header_filter`：<wbr>ステータスと<wbr>ヘッダを<wbr>受け取る。<wbr>ボディフィルタが<wbr>あると、<wbr>ヘッダは<wbr>その後まで<wbr>待つ
ho: nginxの<wbr>ほかの<wbr>モジュールの<wbr>ヘッダフィルタ
hw: nginxが<wbr>ヘッダを<wbr>書き出す
h-body: ボディフィルタ
bn: nginxの<wbr>rangeと<wbr>copyの<wbr>ボディフィルタ
bm: `mruby_output_body_filter`：<wbr>`Content-Length`の<wbr>ある<wbr>ボディ全体を<wbr>受け取る。<wbr>ほかの<wbr>ボディは<wbr>読まれずに<wbr>通る
bo: nginxの<wbr>ほかの<wbr>モジュールの<wbr>ボディフィルタ
bw: nginxの<wbr>writeフィルタが<wbr>ボディを<wbr>送る
```

- nginxは、各チェーンのフィルタを先頭から順に呼びます。ngx_mrubyのフィルタは、nginxのnot modifiedのヘッダフィルタと、rangeとcopyのボディフィルタの後に動きます。また、`gzip`やchunkedのフィルタのような、nginxのほかのモジュールのフィルタより先に動きます。そのため、ngx_mrubyのフィルタは、nginxが圧縮したりチャンクに分けたりする前のレスポンスを受け取ります。nginxは、`auto/modules`に並んだモジュールの順にチェーンを組みます。その順では、ngx_mrubyはnginx自身のフィルタのモジュールの後、copy、range body、not modified、sliceの各フィルタの前にあります。チェーンを組むとき、nginxは各フィルタを、それより前に並んだフィルタの手前に入れます。sliceのフィルタは、`--with-http_slice_module`を付けたビルドにだけあります。
- ヘッダフィルタは、`Nginx::Request`と`Nginx::Headers_out`でステータスとヘッダを読み、書き換えます。ヘッダフィルタはボディを読む前に動くので、そこでは`Nginx::Filter#body`は空の文字列を返します。
- ボディフィルタの処理には、レスポンスの長さが要ります。`Content-Length`のあるレスポンスでは、ngx_mrubyはボディ全体を1つのバッファに集め、そのボディを`Nginx::Filter#body`に入れてスクリプトを1回実行します。そして、スクリプトが`Nginx::Filter#body=`に入れたものを送ります。upstreamのチャンク形式のレスポンスのような、`Content-Length`の無いレスポンスは、読まれずにフィルタを通ります。ngx_mrubyは、そのことを`notice`のレベルでログに書きます。
- locationにボディフィルタがあると、ngx_mrubyは、ボディフィルタが動き終わるまでヘッダを送らずに待ちます。こうして、`Content-Length`を新しいボディの長さにします。
- どちらのフィルタでも待てません。フィルタの中では、`Nginx::Async.sleep`と`Nginx::Async::HTTP.sub_request`は`RuntimeError`を起こし、`Nginx.rputs`と`Nginx.echo`は使えません。

ガイドの[レスポンスのボディを変える](../../guides/body-filter.md)には、CIが実行する両方のフィルタのサンプルがあります。フィルタの構文は、[ディレクティブのリファレンス](../../directives/README.md#mruby_output_body_filter-mruby_output_body_filter_code-mruby_output_header_filter-and-mruby_output_header_filter_code)にあります。

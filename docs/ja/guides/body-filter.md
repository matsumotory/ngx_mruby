# ボディを書き換える

ボディフィルタは、nginxがレスポンスを送る間に動きます。レスポンスを作ったのがどのハンドラでも、upstreamでも同じです。[`mruby_output_body_filter`](../../directives/README.md#mruby_output_body_filter-mruby_output_body_filter_code-mruby_output_header_filter-and-mruby_output_header_filter_code)を使うと、Rubyのスクリプトは`Nginx::Filter#body`でボディを読み、`Nginx::Filter#body=`でボディを置き換えます。ヘッダフィルタの`mruby_output_header_filter`はその前に動き、レスポンスのヘッダを変えられます。

## サンプル

このlocationは、ディスクにあるテキストファイルを送ります。ヘッダフィルタは`Content-Type`を`text/html`にし、ボディフィルタは`&`、`<`、`>`をエスケープして、テキストをHTMLのページで包みます。

```sample
case: test/t/cases/guides.rb
conf: test/conf/conf.d/76-guide-body-filter.conf
script: test/html/guide_body_filter.rb
request: test/html/guide_body_filter.request
response: test/html/guide_body_filter.response
```

## 気を<wbr>つけること

- ボディフィルタは、ディスクのファイルのような長さの分かるレスポンスを、1つのバッファとして読みます。`Content-Length`の無いレスポンスは、フィルタが読まないまま、nginxが先へ渡します。詳しくは[Nginx::Filter](../../class_and_method/README.md#nginxfilter-class)にあります。
- ngx_mrubyは、新しいボディの長さを`Content-Length`に入れて送ります。
- [ユースケース](../use_case/README.md)の[MarkdownをHTMLに変換する出力フィルタ](../use_case/README.md#markdownをhtmlに変換する出力フィルタ)は、同じ場所で、gemのmruby-discountを使ってMarkdownを変換します。

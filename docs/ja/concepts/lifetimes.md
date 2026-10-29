# ライフタイム

nginxは、設定を読む間に、`http {}`ブロックに1つ、`stream {}`ブロックに1つの`mrb_state`を作ります。nginxがワーカープロセスをforkすると、各ワーカーはその状態の自分のコピーを持ちます。ワーカーは、自分のすべてのリクエストのRubyのコードを、そのコピーで実行します。状態はリクエストごとには作らないので、あるリクエストが状態の中に残したものを、同じワーカーの次のリクエストが見ます。

```diagram
worker-lifetime
caption: `http {}`ブロックの`mrb_state`を、nginxが設定を読むときからワーカーが終わるまで示します。
source: src/http/ngx_http_mruby_module.c 575-598 600-632 727-730 1136-1142 1282-1300 1421-1450
at: 0c72e3970 2026-10-19
open: masterプロセスで、<wbr>`mrb_open`が<wbr>`mrb_state`を<wbr>作る。<wbr>nginxは<wbr>ディレクティブを<wbr>読む間に<wbr>そのコードを<wbr>コンパイルし、<wbr>serverの<wbr>コンテキストの<wbr>コードを<wbr>実行する。<wbr>その後に<wbr>`mruby_init`が<wbr>動く
fork: nginxが<wbr>ワーカーを<wbr>起動する。<wbr>各ワーカーは<wbr>`mrb_state`の<wbr>自分の<wbr>コピーを<wbr>持つ
init-worker: ワーカーが<wbr>`mruby_init_worker`を<wbr>実行する
requests: ワーカーの<wbr>すべての<wbr>リクエストが、<wbr>その<wbr>`mrb_state`で<wbr>ハンドラと<wbr>フィルタを<wbr>実行する。<wbr>グローバル変数、<wbr>定数、<wbr>メソッド、<wbr>クラスは<wbr>残り、<wbr>ngx_mrubyは<wbr>実行が<wbr>終わる<wbr>たびに<wbr>例外の<wbr>`mrb->exc`<wbr>だけを<wbr>消す
exit-worker: ワーカーが<wbr>止まり、<wbr>`mruby_exit_worker`を<wbr>実行する
```

## ワーカーが<wbr>リクエストを<wbr>またいで<wbr>保つもの

nginxは、設定を読む間に、`http {}`ブロックに1つの`mrb_state`を作り、`stream {}`ブロックにも1つ作ります。nginxは、ワーカーを起動する前に、masterプロセスで、その状態を使って初期化のコードを実行します。初期化のコードは`mruby_init`と`mruby_stream_init`、serverの設定のコードは`mruby_server_context_handler_code`です。nginxがワーカープロセスをforkすると、各ワーカーは自分のコピーを持ちます。ワーカーは、そのブロックのほかのmrubyのコードを、すべてそのコピーで実行します。init_workerとexit_workerのコードと、すべてのserverとlocationのハンドラとフィルタを、すべてのクライアントについて実行します。リロードや再起動では、新しい状態を持つ新しいワーカーが起動します。

グローバル変数、定数、`main`のインスタンス変数、`def`で定義したメソッド、定数を含むクラスとモジュール、`Userdata`が持つ値は、リクエストをまたいでワーカーに残ります。`main`は、ハンドラのコードの`self`のことです。`Userdata`は、値を1つのグローバル変数に入れて保持します。あるリクエストが残したものは、同じワーカーが後に処理するすべてのリクエストから見えます。変更の後にコードが例外を起こした場合も同じです。各ワーカーは自分のコピーを持つので、あるワーカーから、ほかのワーカーの値は見えません。ngx_mrubyは、実行が終わるたびに例外の`mrb->exc`を消します。また、`cache`の無いスクリプトのファイルを、次の実行のときに読み直してコンパイルします。インラインのコードとキャッシュしたスクリプトは、起動時にコンパイルしたバイトコードのままです。ガベージコレクタは、参照されなくなったオブジェクトを解放します。ローカル変数は残りません。ハンドラのコードは、実行のたびにローカル変数の無い状態から始まります。

1つのリクエストのデータを、グローバル変数、定数、`main`のインスタンス変数、`Userdata`に置かないでください。そのワーカーの次のリクエストが、どのクライアントからのものでも、そのデータを見ます。ローカル変数を使い、リクエストは`Nginx::Request`、`Nginx::Var`、`Nginx::Headers_in`、`Nginx::Headers_out`で読み書きしてください。`stream {}`ではコードがセッションごとに動くので、`Nginx::Stream::Connection`で読み書きしてください。同じリクエストの後のハンドラへデータを渡すには、`set $name "";`でnginxの変数を宣言し、`Nginx::Var`で読み書きします。または、`Userdata`の値を、読む前にすべてのリクエストで設定します。locationの`set`は`mruby_rewrite_handler`の後に動き、変数を空に戻します。そのため、rewriteハンドラが書く変数は、`server {}`ブロックの`set`で宣言してください。グローバル変数と定数には、initやinit_workerのコードが用意する設定のような、ワーカーのすべてのリクエストで共有するものだけを置いてください。グローバル変数は、[`Nginx.remove_global_variable`](../../class_and_method/README.md#nginxremove_global_variable)で消せます。

`stream {}`ブロックのRubyのコードも、自分の`mrb_state`で同じように動きます。そこで動くのは、`mruby_stream_init`、`mruby_stream_init_worker`、各セッションのコードと、`mruby_stream_exit_worker`です。

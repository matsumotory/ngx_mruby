# ブロックせずに待つ

nginxのワーカーは、1つのイベントループで多くの接続を同時に処理します。`sleep`やソケットの読み込みのような、ブロックする呼び出しでハンドラが待つと、ワーカー全体が止まります。`Nginx::Async.sleep`と`Nginx::Async::HTTP.sub_request`を使うと、ハンドラはnginxを通して待ちます。ハンドラのRubyのコードはファイバーの中で動きます。このファイバーはnginxに制御を返し、nginxがイベントループからそのファイバーを再開します。

```diagram
async-sleep
caption: accessハンドラが`Nginx::Async.sleep`を呼んでから、ハンドラのコードが先へ進むまでに起きることを示します。
source: mrbgems/ngx_mruby_mrblib/mrblib/mrb_nginx.rb 100-106
source: src/http/ngx_http_mruby_async.c 415-430 503-591 615-630 659-693
source: src/http/ngx_http_mruby_module.c 942-959 1099-1132
source: src/http/ngx_http_mruby_core.h 30-35
at: 819212d88 2026-11-01
call: accessハンドラの<wbr>コードが、<wbr>ファイバーの<wbr>中で<wbr>`Nginx::Async.sleep(500)`を<wbr>呼ぶ
timer: `__sleep`が<wbr>nginxの<wbr>イベントループに<wbr>500ミリ秒の<wbr>タイマーを<wbr>加え、<wbr>`Fiber.yield`が<wbr>ファイバーを<wbr>中断する
done: ハンドラは<wbr>`NGX_DONE`を<wbr>返す。<wbr>nginxは<wbr>リクエストを<wbr>保ったまま、<wbr>ハンドラを<wbr>離れる
serve: タイマーが<wbr>動いている<wbr>間、<wbr>ワーカーは<wbr>ほかの<wbr>接続を<wbr>処理する
fire: タイマーが<wbr>切れると、<wbr>`ngx_mrb_timer_handler`が<wbr>ファイバーを<wbr>再開できる<wbr>状態に<wbr>して、<wbr>リクエストを<wbr>nginxに<wbr>戻す
resume: nginxが<wbr>ハンドラを<wbr>もう一度<wbr>呼び、<wbr>ハンドラが<wbr>ファイバーを<wbr>再開する。<wbr>コードが<wbr>終わると、<wbr>accessフェーズは<wbr>待たなかった<wbr>ときと<wbr>同じように<wbr>結果を<wbr>扱う
```

- ngx_mrubyは、`ngx_mrb_start_fiber`で、各ハンドラのコードをmrubyのファイバーの中で実行します。`Nginx::Async.sleep`は、nginxのタイマーをセットしてファイバーを中断します。ファイバーが中断している間、ハンドラは既に`NGX_DONE`を返していて、ワーカーはほかの接続を処理します。
- タイマーが切れると、`ngx_mrb_timer_handler`はファイバーを再開できる状態にして、`ngx_http_post_request`でリクエストをnginxに戻します。nginxはハンドラをもう一度呼び、ハンドラはコードを始めずにファイバーを再開します。コードが終わると、ハンドラは待たなかったハンドラと同じように結果をフェーズに返します。結果の無いaccessハンドラの後、nginxは次のaccessハンドラへ進みます。`satisfy any`で403を返すと、nginxは次のaccessハンドラを試します。ファイバーが待っている間、nginxはコードをもう一度実行しません。
- `mruby_set`のハンドラはrewriteモジュールのスクリプトの中で動くので、nginxはこのハンドラをもう一度呼びません。ngx_mrubyがファイバーを再開し、コードが終わると変数に値を入れ、次のハンドラからフェーズを進めます。
- `Nginx::Async::HTTP.sub_request`は、nginxのサブリクエストを始めてファイバーを中断します。サブリクエストが終わると、ファイバーが再開します。
- `mruby_set`とpost-read、server rewrite、rewrite、access、contentのハンドラは待機して再開できます。中断したハンドラは`NGX_DONE`を返し、サブリクエストの処理中は`NGX_AGAIN`を返します。
- 2.7.3の修正以降、nginxは`Nginx::Async.sleep`で待つcontentハンドラのリクエストを保持します。3.xもこの修正を含みます。コードの応答や戻り値のステータスでリクエストが完了します。2.7.2までは、sleepの時点で応答せずにリクエストが終わりました。
- Rubyの`Nginx.redirect`から呼ばれたcontentハンドラには、sleep時点で終了する制限が残ります。呼び出し元も処理を続け、その場で応答する場合があります。
- contentハンドラで`Nginx::Async.sleep`の待機後に`Nginx::Async::HTTP.sub_request`を呼ぶと、例外は`RuntimeError`。
- `mruby_set`のサブリクエストはリクエストを保持しません。変数の完了を待たず、nginxはcontentフェーズへ進みます。
- ヘッダフィルタ、ボディフィルタ、logハンドラでは、両メソッドが`RuntimeError`を起こします。
- mruby-sleepの`sleep`、mruby-socketのソケット、ファイル、シェルのコマンド、Redisの呼び出しで待つコードは、その間ワーカーをブロックします。詳しくは[信頼境界](../../security/trust-boundary.md)にあります。

リファレンスの[Nginx::Async](../../class_and_method/README.md#nginxasync-class)に、両方のメソッドの説明があります。

関連する制約の資料：

- [2.7.3の挙動変更](../../releases/v2.7.3.ja.md)
- [Nginx::Async#sleep](../../class_and_method/README.md#nginxasyncsleepmsec)

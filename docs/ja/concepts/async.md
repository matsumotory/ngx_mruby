# ブロックせずに待つ

nginxのワーカーは、1つのイベントループで多くの接続を同時に処理します。`sleep`やソケットの読み込みのような、ブロックする呼び出しでハンドラが待つと、ワーカー全体が止まります。`Nginx::Async.sleep`と`Nginx::Async::HTTP.sub_request`を使うと、ハンドラはnginxを通して待ちます。ハンドラのRubyのコードはファイバーの中で動きます。このファイバーはnginxに制御を返し、nginxがイベントループからそのファイバーを再開します。

```diagram
async-sleep
caption: accessハンドラが`Nginx::Async.sleep`を呼んでから、ハンドラのコードが先へ進むまでに起きることを示します。
source: mrbgems/ngx_mruby_mrblib/mrblib/mrb_nginx.rb 100-106
source: src/http/ngx_http_mruby_async.c 187-239 241-314 316-348 363-410
source: src/http/ngx_http_mruby_module.c 1061-1074
source: src/http/ngx_http_mruby_core.h 30-35
at: 0c72e3970 2026-10-19
call: accessハンドラの<wbr>コードが、<wbr>ファイバーの<wbr>中で<wbr>`Nginx::Async.sleep(500)`を<wbr>呼ぶ
timer: `__sleep`が<wbr>nginxの<wbr>イベントループに<wbr>500ミリ秒の<wbr>タイマーを<wbr>加え、<wbr>`Fiber.yield`が<wbr>ファイバーを<wbr>中断する
done: ハンドラは<wbr>`NGX_DONE`を<wbr>返す。<wbr>nginxは<wbr>リクエストを<wbr>保ったまま、<wbr>ハンドラを<wbr>離れる
serve: タイマーが<wbr>動いている<wbr>間、<wbr>ワーカーは<wbr>ほかの<wbr>接続を<wbr>処理する
fire: タイマーが<wbr>切れると、<wbr>`ngx_mrb_timer_handler`が<wbr>ファイバーを<wbr>再開する
resume: コードは<wbr>`sleep`の<wbr>後から<wbr>続く。<wbr>コードが<wbr>終わると、<wbr>リクエストは<wbr>次の<wbr>ハンドラへ<wbr>進むか、<wbr>nginxが<wbr>ハンドラの<wbr>結果で<wbr>リクエストを<wbr>終える
```

- ngx_mrubyは、`ngx_mrb_start_fiber`で、各ハンドラのコードをmrubyのファイバーの中で実行します。`Nginx::Async.sleep`は、nginxのタイマーをセットしてファイバーを中断します。ファイバーが中断している間、ハンドラは既に`NGX_DONE`を返していて、ワーカーはほかの接続を処理します。
- タイマーが切れると、`ngx_mrb_timer_handler`が、ファイバーを、それが属するリクエストとともに再開します。コードが終わると、ngx_mrubyはハンドラの結果をnginxに渡します。結果が`Nginx::DECLINED`ならそのフェーズの次のハンドラが動き、ほかの結果ならnginxはリクエストを終えます。
- `Nginx::Async::HTTP.sub_request`も同じように動きます。このメソッドはnginxのサブリクエストを始めてファイバーを中断し、サブリクエストが終わるとnginxがファイバーを再開します。
- `mruby_set`とpost-read、server rewrite、rewrite、accessのハンドラは待機して再開できます。中断したハンドラは`NGX_DONE`を返し、サブリクエストの処理中は`NGX_AGAIN`を返します。
- 2.7.3の修正以降、通常のcontentハンドラも`Nginx::Async.sleep`で待てます。この修正は3.xにも統合されています。nginxがリクエストを保持し、タイマーでファイバーを再開します。その応答や戻り値のステータスでリクエストが完了します。リリース済みの2.7.2までは、sleepの時点で応答せずに終了していました。
- Rubyの`Nginx.redirect`から呼ばれたcontentハンドラには、sleep時点で終了する制限が残ります。呼び出し元の処理が続き、その処理が応答する場合があるためです。
- contentハンドラで`Nginx::Async.sleep`の待機後に`Nginx::Async::HTTP.sub_request`を呼ぶと、`RuntimeError`になります。`mruby_set`のサブリクエストはリクエストを保持せず、nginxは変数を待たずにcontentフェーズへ進みます。ヘッダフィルタ、ボディフィルタ、logハンドラでは、両メソッドが`RuntimeError`になります。[2.7.3の挙動変更](../../releases/v2.7.3.ja.md)と[Nginx::Async#sleep](../../class_and_method/README.md#nginxasyncsleepmsec)も参照してください。
- mruby-sleepの`sleep`、mruby-socketのソケット、ファイル、シェルのコマンド、Redisの呼び出しで待つコードは、その間ワーカーをブロックします。詳しくは[信頼境界](../../security/trust-boundary.md)にあります。

リファレンスの[Nginx::Async](../../class_and_method/README.md#nginxasync-class)に、両方のメソッドの説明があります。

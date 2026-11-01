# ngx_mrubyの開発

人とコーディングエージェントがngx_mrubyを開発する手順です。

Cのモジュールの`src/`、`mrbgems/`のgem、ビルドを変える前に、AGENTS.mdの[Design principles](../../AGENTS.md#design-principles)を読んでください。そこには、オーナーの決定と、セッションがその決定を当てはめる方法が書いてあります。オーナーの決定は、ワーカーごとに1つの`mrb_state`を持つこと、ブロックしないこと、今の性能を保ち、性能を測ることです。当てはめる方法には、どの変更をどう測るかも含まれます。

## 共同作業を引き継ぐ

共有の引き継ぎルールは[AGENTS.md](../../AGENTS.md#session-handoff)にあります。現在の作業一覧は`next`の[HANDOFF.md](https://github.com/matsumotory/ngx_mruby/blob/next/docs/HANDOFF.md)、詳細な検証結果は作業中のPRに記録します。ClaudeやCodexの非公開メモリは補足情報であり、作業を再開するための必須条件ではありません。

1. AGENTS、関連する計画、コード、テストを読み、続いてHANDOFF、PRの最新本文、レビューコメント、CI結果を確認します。`origin`をfetchし、記録されたbaseとheadが今のものと合うかを確かめてください。日付の付いた記録はその日の状態で、今のブランチの先頭とは限りません。着手する前に、開いているPRと、`claude/*`や`codex/*`を含むすべての作業ブランチを調べます。サイト、ナビゲーション、利用者向けドキュメントの変更では、編集前に[Site design acceptance](../proposals/site.md#site-design-acceptance)を読みます。影響する場合は生成される2.xの入口ページも含め、読者がたどる流れ全体を確認します。トップページだけのスクリーンショットでは不十分です。
2. `git worktree list`、対象worktreeのブランチ、`git status --short`を確認します。可能なら既存の作業用worktreeを使います。前の担当者とローカルのビルド・プレビュープロセスが停止したことを確かめてから引き継ぎます。外部CIは実行中でも構いません。再起動せず状態を確認してください。未コミットの変更は保持します。別の作業にworktreeが必要なら、AGENTSのブランチ規則に従い、適切なbaseから専用の`<tool>/<topic>`ブランチを作ります。引き継ぎの記録に合わせるために、共有のcheckoutをresetしないでください。
3. 既存PRを引き継ぐときは、引き継ぐheadをコメントに記します。新規作業では、対象差分がレビューできる状態になったらDraft PRを作り、実装と手元の検査が終わったらReady for reviewにします。AGENTSの「Branches and pull requests」のとおり、DraftではCIを実行せず、Readyへの変更で起動します。Readyは承認ではありません。headや検証結果が変わったらテンプレートの各節を更新し、AGENTSに従ってHANDOFFの作業一覧も更新します。コミットメッセージには問題、判断理由、主なトレードオフ、検証結果を残し、未検証の範囲も明示します。
4. 停止や引き継ぎの前に、PRへ日付付きの記録を残します。**範囲と決定**には採用した決定へのリンクと未決事項、**状態**にはブランチ、head/base、DraftかReadyかとその理由、headのCIの有無、進行段階、残る差分を書きます。**根拠**にはコマンド、環境とnginxのバージョン、検証したコミット、結果、実行・レビューへのリンク、**未完了の作業**には未実行、実行中、失敗、拒否、結果不明の操作、**次の手順**には具体的な操作と前提条件を書きます。どの担当者が作業を止めたかも確認します。まだPRがなければ、通常のドキュメントPRで公開可能な作業範囲と次の手順をHANDOFFに記録します。未完成のファイルはローカルに保持し、生の作業メモは公開しません。後任は、未pushの作業が別のマシンにもあると考えてはいけません。
5. 一時ログ、スクリーンショット、PRの下書き、個人用の参考資料は、リポジトリの外か、範囲を限定してignoreしたディレクトリに置きます。コミット前に`git status --short --untracked-files=all`、`git check-ignore -v <generated-path>`、`git ls-files <generated-path>`、`git diff --cached --name-status`と`git diff --cached`を確認します。ソース、テスト、公開ドキュメントを隠してはいけません。statusをきれいにするだけのために広いディレクトリをignoreしないでください。[リポジトリに入れてはいけないファイル](../test/README.md#files-that-do-not-belong-in-the-repository)の追加ファイル検査を実行し、公開文面に非公開情報がないか確認します。
6. 再開時には、実行中のCIと結果不明の操作を確認してから再試行します。ビルド、テストポートの分離、独立レビュー、マージ条件はAGENTSに従います。引き継ぎ記録があっても免除されません。checkoutしたブランチのハーネスを使い、`next`のポートオフセット機能が2.xにもあると仮定しないでください。macOSでLinuxのスイート、sanitizer、callgrindを検証するには、[.github/workflows/test.yml](../../.github/workflows/test.yml)と同じパッケージを持つLinuxコンテナを使います。ルートのDockerfileは実行用のイメージで、テストの環境ではありません。

## 推奨する開発環境

私たちは、ngx_mrubyの開発にvagrantを使っています。

開発するときは、同じ開発環境を使うとよいでしょう。

### 開発環境を用意する

```
cd ngx_mruby
vagrant up       # run provisioner automatically
vagrant ssh
```

### ubuntu 18.04でテストする

```
cd ngx_mruby/
sh test.sh
```

### Cのソースをフォーマットする

スクリプトの`apply-clang-format`を実行してください。

```
cd ngx_mruby
sh apply-clang-format
```

## ハンドラが待つ仕組み

この節は、`Nginx::Async.sleep`、`Nginx::Async::HTTP.sub_request`、`Nginx::Stream::Async.sleep`を支えるコードを説明します。`src/common/ngx_mruby_fiber.c`、`src/http/ngx_http_mruby_async.c`、`src/stream/ngx_stream_mruby_async.c`か、これらを呼ぶハンドラを変えるときに読んでください。スクリプトから見える動きは、[ブロックせずに待つ](concepts/async.md)と、リファレンスの[Nginx::Async](../class_and_method/README.md#nginxasync-class)にあります。

### レコード

ハンドラは、実行のたびにコードを新しいmrubyのファイバーで動かし、そのファイバーのレコードを確保します。HTTPではリクエストのプールから確保し（`ngx_http_mrb_fiber_t`）、サブリクエストはメインのリクエストのプールを使います。streamでは、セッションの接続のプールから確保します（`ngx_stream_mrb_fiber_t`）。どちらのレコードも、プロトコルに依らない部分である`src/common/ngx_mruby_fiber.h`の`ngx_mrb_fiber_t`で始まります。この部分には、ファイバー、`mrb_state`、GCのルートの保持の中のファイバーのスロット（`src/http/ngx_http_mruby_gc_roots.h`）、状態、1つのタイマーのイベントがあります。タイマーは、sleepのたびにセットし直します。

- HTTPのレコードには、ほかにハンドラの種類、sleepの再開のデータ、wakeで使うpostされたリクエストのエントリ、コードが設定した結果、`Nginx.redirect`のローカルのURI、`sub_request`が返した`Nginx::Async::HTTP::Response`があります。サブリクエストのレスポンスのステータス、ヘッダ、ボディは、親のリクエストのモジュールのコンテキスト（`sub_response_*`）に置きます。
- モジュールのコンテキストの`ctx->fiber_proc`は、いま動いている実行のレコードを指します。`ctx->wait`（HTTP）と`ctx->sleeping`（stream）は、nginxがハンドラをもう一度呼ぶのを待つレコードを指します。
- コードの`RProc`は、コードをコンパイルするときか読み込むときに1回だけ用意します（`ngx_mrb_fiber_prepare_proc`）。実行のたびには変えません。

| 状態 | 入るとき | 出るとき |
|---|---|---|
| `RUNNING` | ファイバーを作ったか、再開したとき | ファイバーがyieldしたとき（`WAITING`）、返ったとき（`DONE`）、例外を出したとき（`FAILED`） |
| `WAITING` | コードがタイマーをセットするかサブリクエストをpostして、yieldしたとき | タイマーが切れるかサブリクエストが終わったとき（`READY`）、所有者が終わったとき（`CANCELLED`） |
| `READY` | wakeのとき | ハンドラがファイバーを再開したとき（`RUNNING`）、所有者が終わったとき（`CANCELLED`） |
| `DONE`、`FAILED` | ファイバーが終わったときで、スロットを解放する | 出ない。レコードはプールと一緒に解放する |
| `CANCELLED` | ファイバーが`WAITING`か`READY`のときに、所有者のフックが動いたとき | 出ない。ファイバーを再開しないので、`ensure`節を含め、コードの残りは動かない |

### 何が何を持つか

- リクエストかセッションがレコードを持ち、レコードがスロットとタイマーを持ちます。
- レコードが初めて待つとき、待ちをセットする前に、コードは所有者のフックを足します。HTTPではリクエストのクリーンアップで、nginxはこれをメインのリクエストに置きます。streamでは接続のプールのクリーンアップです。同じときに、postされたリクエストのエントリを確保し（HTTP）、スロットを取ります（`ngx_mrb_fiber_hold`）。失敗したときはRubyのコードで例外を出し、何もセットしません。待たない実行は、スロットを取らず、クリーンアップも足しません。
- 所有者のフックは`ngx_mrb_fiber_cancel`を呼びます。この関数は、解放したプールの上でタイマーが切れないように、残っているタイマーを消します。次にスロットを解放し（HTTPでは`sub_request`のレスポンスのスロットも解放します）、`WAITING`か`READY`のレコードを`CANCELLED`にします。
- スロットは1回だけ解放します。解放するのは、ファイバーが普通に終わるか例外で終わったときか、所有者のフックが動いたときです。

### 再開

`ngx_mrb_fiber_resume`は、ファイバーを始めるか再開し、ファイバーが待つか、返ったか、例外を出したかを返します。ほかのmrubyの呼び出しが動いているとき（`mrb->jmp`がセットされているとき）は、`mrb_protect_error`を通して再開します。レコードが`DONE`、`FAILED`、`CANCELLED`のときは、ファイバーに触れずに断ります。ファイバーが例外を出したときは、そのリクエストかセッションのために例外を1回だけログに書き、返る前に`mrb->exc`を消します。ワーカーのすべてのリクエストが`mrb_state`を共有するためです。プロトコルの部分である`ngx_mrb_run_fiber`と`ngx_stream_mrb_run_fiber`は、ファイバーが動く間だけ、いまのリクエストかセッションを設定します。HTTPではハンドラの種類も設定します。サブリクエストのレスポンスは、ファイバーの`Fiber.yield`の値として渡します。

### HTTP：待ちとその終わり

- `Nginx::Async.sleep`はレコードのタイマーをセットします。`Nginx::Async::HTTP.sub_request`は、メモリの中で動くサブリクエストをpostし、そのpostハンドラは`ngx_mrb_async_http_sub_request_done`です。その後、コードはyieldします。logハンドラとフィルタでは、両方とも`RuntimeError`を出します。`mruby_set`のハンドラでは、nginxがサブリクエストを待たないので、`sub_request`も`RuntimeError`を出します。
- ハンドラは`NGX_DONE`を返し、リクエストのwriteイベントのハンドラを`ngx_http_mrb_wait_handler`にします（`ngx_http_mrb_fiber_wait_on_nginx`）。このハンドラは、レコードが`WAITING`の間はイベントを無視します。contentフェーズのチェッカーは`NGX_DONE`ごとに参照を1つ外すので、contentハンドラは先に参照を1つ取ります（`r->main->count++`）。
- wakeはレコードを`READY`にします。タイマーのときは、`ngx_http_mrb_fiber_wake`がレコードに持つエントリでリクエストをpostし、接続のpostされたリクエストを処理します。サブリクエストのときは、postハンドラが最初の呼び出しでレスポンスをコピーします。どの呼び出しでも、`ngx_http_auth_request_done`と同じように、nginxの`rc`を変えずに返します。その後、nginxが親のリクエストを起こします。
- `ngx_http_mrb_wait_handler`は`READY`を見ると、writeイベントのハンドラを`ngx_http_core_run_phases`に戻し、フェーズを進めます。`r->phase_handler`は動いていないので、チェッカーは同じmrubyのハンドラを呼びます。`ngx_http_mrb_fiber_call_again`は、コードを始めずにファイバーを再開します。ハンドラは、待たなかったハンドラと同じように、コードの結果を`ngx_mrb_finalize_rputs`でチェッカーへ返します。
- レコードが`WAITING`の間にnginxがハンドラを呼ぶと、ハンドラはもう一度`NGX_DONE`を返し、コードは始まりません。contentハンドラは、このときも参照を1つ取ります。レコードが`CANCELLED`なら、ハンドラは`NGX_ERROR`を返します。
- `mruby_set`のハンドラは、rewriteモジュールのスクリプトの中で動きます。このスクリプトは呼ばれるたびに最初のディレクティブから始まるので、nginxはこのハンドラをもう一度呼びません。代わりにwaitハンドラから`ngx_http_mrb_resume_set`がファイバーを再開し、値を変数に入れ、`r->phase_handler`を次のハンドラへ進めてフェーズを進めます。例外のときは、リクエストを500で終えます。待った後にngx_mrubyがリクエストを自分で終えるのは、この場合だけです。
- nginxがほかのmrubyの呼び出しの中で動かすハンドラで始まった待ちは、wakeを使いません。これは、`mruby_set`のハンドラ、logハンドラ、フィルタがRubyの呼び出しの中で内部リダイレクトしたときの、リダイレクト先のロケーションのハンドラです。内部リダイレクトがハンドラのモジュールのコンテキストを置き換えた後の待ちも同じです。この場合はタイマーかpostハンドラがファイバーを自分で再開し、`ngx_mrb_post_fiber`がハンドラを終えます。そこのcontentハンドラはリクエストを保たず、サブリクエストが動いている間、ハンドラは`NGX_AGAIN`を返します。

### HTTP：ハンドラの結果と`Nginx.redirect`

- `Nginx.return`、`Nginx.send_header`、`Nginx.status_code=`、URLを渡した`Nginx.redirect`は、動いているファイバーのレコードに結果を保存し（`ngx_http_mrb_fiber_set_result`）、HTTPのステータスは`r->headers_out.status`にも保存します。`ngx_mrb_finalize_rputs`はレコードの結果を読みます。そのため、結果を設定しないハンドラには、前のハンドラが何を保存していても結果がありません。例外は、呼び出しの中の内部リダイレクトでリクエストを別の場所へ送ったハンドラです。このハンドラは、自分の結果が無ければ、リダイレクト先が保存したステータスを返します。
- post_read、server rewrite、rewrite、access、contentのハンドラのうち、`ngx_mrb_post_fiber`が再開しないものでは、ローカルのURIを渡した`Nginx.redirect`がURIをレコードに保存します（`ngx_http_mrb_fiber_defer_redirect`）。ハンドラが終わると、`ngx_mrb_run_request`がハンドラの出力を捨て、呼び出しの後にコードが出力を書くかステータスを設定していれば`warn`のレベルで1行書きます。その後、`ngx_http_internal_redirect`を呼び、contentフェーズ以外では、取った参照を`ngx_http_finalize_request(r, NGX_DONE)`で外し、`NGX_DONE`を返します。この呼び出しの中でリクエストが解放されることがあるので、その後はリクエストのものを何も使いません。ほかのハンドラでは、リダイレクトは呼び出しの中で動きます。

### stream：待ちとその終わり

- セッションの1つのmrubyのハンドラは、accessフェーズで動きます。`Nginx::Stream::Async.sleep`はレコードのタイマーをセットして`ctx->sleeping`を設定し、ハンドラは`NGX_DONE`を返します。コードが待つ間、接続のreadのハンドラは`ngx_stream_session_handler`です。`listen ... proxy_protocol`では、このハンドラがPROXYのヘッダを読むハンドラにコードの再開まで代わり、readイベントでフェーズが進むようにします。
- タイマーはレコードを`READY`にして、セッションのフェーズを進めます。accessフェーズのチェッカーがハンドラをもう一度呼び、`ngx_stream_mrb_fiber_call_again`がファイバーを再開します。ハンドラは、待たなかったハンドラと同じように`Nginx::Stream::Connection.stream_status`を返します。
- レコードが`WAITING`の間にnginxがハンドラを呼ぶと、ハンドラは`NGX_DONE`を返し、コードは始まりません。UDPのセッションのデータグラムや、TCPのセッションのクライアントからのバイトがこれに当たり、バイトはコードの後のフェーズのために残ります。バイトを読むまでreadイベントを知らせ続けるイベントの方式（`select`、`poll`）では、ハンドラはコードの再開までreadイベントを消します。
- `c->close`がセットされた接続では、`WAITING`のレコードを取り消します。nginxは、`worker_shutdown_timeout`が切れたときに`c->close`をセットします。ハンドラは`shutdown timeout`を`info`のレベルでログに書き、`NGX_STREAM_OK`を返すので、セッションが終わります。

### 外から待ちを終えるもの

| 出来事 | HTTP | stream |
|---|---|---|
| クライアントが接続を閉じる | HTTP/1.xでは、フェーズが進む間nginxはクライアントから読まないので（`ngx_http_block_reading`）、待ちは続き、コードは再開します。nginxは、レスポンスを書けないときにリクエストを終えます | TCPでは、readイベントでハンドラが動き、読まずに`NGX_DONE`を返すので、待ちは続きます。閉じたことは、コードの再開の後に分かります。UDPには閉じる操作がありません |
| リロードかSIGQUIT | 古いワーカーは待ちを最後まで進めます。待ちのタイマーはキャンセルできないので、ワーカーはタイマーを待ちます | 同じです |
| `worker_shutdown_timeout`が切れる | nginxがリクエストを打ち切ります。そのクリーンアップで所有者のフックが動き、タイマーを消してレコードを取り消します | ハンドラが待ちを取り消し、セッションを終えます（上記） |
| SIGTERM | フックは動きません。サイクルのプールのクリーンアップの`mrb_close`がファイバーを解放します | 同じです |

HTTP/2とHTTP/3は、まだどのテストでも確かめていません。ハーネスにそのクライアントがないためです。

### テストとカウンタ

このモデルを確かめるケースは、`test/t/cases/`の`async_resume_result.rb`、`async_result_isolation.rb`、`async_subrequest_return.rb`、`async_set_var.rb`、`redirect_async.rb`、`stream_async_sleep_udp_once.rb`、`stream_proxy_protocol_wait.rb`、`workers.rb`です。それぞれ`test/conf/conf.d/`に専用の設定の断片があります。`async_resume_result.rb`は、フェーズごとに待つ場合と待たない場合の終わりを比べます。`async_result_isolation.rb`は、ハンドラの結果がそのハンドラのものであることを確かめます。`workers.rb`は、リロードと`worker_shutdown_timeout`を確かめます。soakのビルド（`-DNGX_MRUBY_DEBUG_STATS`）では、`Nginx::Debug.stats`が4つの値を返し、`test/soak/soak.rb`がそれを確かめます。4つの値は、HTTP（`timers`）とstream（`stream_timers`）の残っているタイマー、スロットを持つstreamのファイバー（`stream_fibers`）、GCのルートの保持の中のファイバー（`gc_root_fibers`）です。

## 新しいバージョンのnginxをサポートする

[nginx_version](../../nginx_version)と[.travis.yml](../../.travis.yml)を編集します。例は[コミット02ddb38](https://github.com/matsumotory/ngx_mruby/commit/02ddb38b68702d9abe8fb0a8c172ee1d80ad2b2d)です。

TODO：古いバージョンのnginxへの対応を終える方針は、まだ書いていません。

## mrubyを更新する

このリポジトリのツリーにある[mruby](../../mruby)を最新のバージョンに更新するには、スクリプトの[update-mruby-subtree](../../update-mruby-subtree)を使えます。このスクリプトは、mrubyのupstreamのリポジトリをdep-mrubyとして加え、すべての変更を、現在のブランチへpullします。

```
git checkout -b BRANCH
sh update-mruby-subtree
```

特定のコミットに更新するときは、refを指定できます。

```
sh update-mruby-subtree REF
```

このスクリプトは`git subtree pull --prefix=mruby --squash dep-mruby REF`を実行します。そのため、マージは、`mruby/`の履歴にある最後のsubtreeのsquashから始まります。そのsquashが古いときや、subtreeのpullでないコミットが`mruby/`を変えていたときは、pullは`mruby/`の下のコンフリクトで止まります。コンフリクトを手で解決しないでください。`mruby/`の下のファイルは、決して手で編集しません。代わりに、止まったマージの中で、次のコマンドでsubtreeをrefのツリーと同じ内容に置き換え、マージをコミットします。

```
git rm -r -q --cached mruby
rm -rf mruby
git read-tree --prefix=mruby/ -u REF^{tree}
```

タグをローカルのタグとしてfetchしていないときは、ここでは`REF`にコミットのidを使ってください。`update-mruby-subtree`は、refを`FETCH_HEAD`にだけfetchします。`git read-tree`は、ツリーのすべてのファイルを書きます。このリポジトリの`.gitignore`が`git add`から外すファイルも書きます。たとえば、`mruby/Makefile`と、`mruby/lib/mruby/build/`の下のファイルです。コミットする前に、インデックスの`mruby/`の下にrefのツリーがあることを確かめてください。次の2つのコマンドは、同じidを出力しなければなりません。

```
git write-tree --prefix=mruby/
git rev-parse REF^{tree}
```

それから、マージをコミットし、2つのidをコミットメッセージに書いてください。

```
git commit
```

コミットの後は、`git rev-parse HEAD:mruby`も同じidを出力します。

`git subtree`が作ったsquashのコミットは、マージの2つ目の親です。このコミットは`git-subtree-split: <commit of REF>`を記録するので、次の更新は、古いsquashではなく、このコミットからマージします。マージは、`mruby/`の外を何も含めずに、単独でコミットしてください。ビルドの変更は、その後に続くコミットでします。

### Prism

mruby 4.1以降のコンパイラは[Prism](https://github.com/ruby/prism)を使い、mrubyのツリーには`mrbgems/mruby-compiler/lib/prism`がgit submoduleとして含まれます。subtreeのマージで入るのはそのgitlinkだけなので、マージ直後の`mruby/`にはPrismのソースがなく、ビルドは`git submodule update --init lib/prism`で止まります。マージコミットの直後に[vendor-mruby-prism](../../vendor-mruby-prism)を実行し、その結果だけをコミットしてください。

```
sh vendor-mruby-prism
git commit
```

スクリプトは`HEAD`のgitlinkからruby/prismのコミットを読み、そのコミットをfetchします。そのコミットのファイルのうち、mruby-compilerのビルドが読むファイルでgitlinkを置き換え、stageします。対象は`src/`、`include/`、`config.yml`、`templates/template.rb`と、それがレンダリングするファイルのテンプレート、`LICENSE.md`です。stageした各ファイルのblobが取得したコミットと一致しなければ停止します。コミットメッセージにruby/prismのコミットを記してください。別のコミットを取り込むには、`sh vendor-mruby-prism COMMIT`のように引数で指定します。

次に`update-mruby-subtree`を実行すると、mruby側にgitlinkがある場所に、このリポジトリでは取り込んだファイルがあります。新しいrefが同じruby/prismのコミットを指すなら、マージはファイルを保持します。異なるコミットなら、一方ではgitlink、他方ではファイルが変更されるため、そのパスでコンフリクトすることがあります。どちらの場合も、先ほどの`git read-tree`の手順でマージを完了し、`mruby/`をgitlinkを含むrefのツリーと一致させてから、再び`vendor-mruby-prism`を実行します。

[build_config.rb](../../build_config.rb)の`NGX_MRUBY_CORE_GEMS`は、ngx_mrubyがビルドするmrubyのコアのgemを、名前で挙げます。そのため、mrubyを更新しただけでは、ビルドするコアのgemは変わりません。一覧のgemが新しい`mruby/mrbgems`に無いと、mrubyのビルドは止まります。そのgemを一覧から消すか置き換えるかは、別の決定として決めてください。更新の作業中にビルドを続けるには、`NGX_MRUBY_ALLOW_MISSING_CORE_GEMS=1`を設定します。ビルドは、無いgemを、通知を出して読み飛ばします。新しいmrubyが加えたgemは、一覧に加えるまでビルドしません。

更新の後は、`mruby/build`を消して`sh test.sh`でビルドし、rakeが更新とともに書いた`build_config.rb.lock`をコミットしてください。ロックは、mrubyのバージョンを記録します。rakeはビルドの最後にロックを書きます。一方、`NGX_MRUBY_CORE_GEMS`のチェックは、rakeが`build_config.rb`を読み込む間にビルドを止めます。そのため、一覧のすべてのgemが見つかるか、`NGX_MRUBY_ALLOW_MISSING_CORE_GEMS=1`を設定するまで、rakeは新しいロックを書きません。新しいmrubyが自分のgemとして持つようになった依存先は、もうクローンしません。しかし、rakeはロックにそのエントリーを残すので、そのエントリーを消してください。詳しくは、[インストール](install/README.md#gemのコミットとbuild_configrblock)のページの「gemのコミットとbuild_config.rb.lock」に書いてあります。

## ngx_devel_kitを更新する

このリポジトリのツリーにある[ngx_devel_kit](../../dependence/ngx_devel_kit)を最新のバージョンに更新するには、スクリプトの[update-devkit-subtree](../../update-devkit-subtree)を使えます。このスクリプトは、ngx_devel_kitのupstreamのリポジトリをdep-ngx_devel_kitとして加え、すべての変更を今のブランチへpullします。

```
git checkout -b BRANCH
sh update-devkit-subtree
```

特定のコミットに更新するときは、refを指定できます。

```
sh update-devkit-subtree REF
```

## v3をmasterへ昇格する

v3を昇格するまでは、`master`が2.xの系列です。v3は`next`で開発し、`v2.x`は`master`を自動でコピーしたブランチです。`master`へのpushのたびに、ワークフローの[mirror-v2x.yml](../../.github/workflows/mirror-v2x.yml)が、`v2.x`を`master`へfast-forwardします。昇格では、v3.0.0の時点で`next`を`master`へマージします。こうすると、`master`は3.xの系列になり、`v2.x`が2.xの系列を引き継ぎます。詳しくは[Branch strategy](../../README.md#branch-strategy)にあります。この節は、昇格の手順です。

エージェントがプルリクエストを用意し、チェックを実行し、オーナーの許可の後に、リリースとそのタグを公開します。[AGENTS.md](../../AGENTS.md#branches-and-pull-requests)に書いてあります。下の手順では、昇格を始める許可と、手順2と3のリポジトリの設定も、オーナーに任せています。これらは推奨です。下の「決まっていないこと」を見てください。

2026-10-04の時点で、リポジトリにはルールセットが4つあります。手順3は、そのうち最初の2つを変えます。

- `protected-lines`は、`master`と`next`に掛かります。変更は、プルリクエストを通してだけ入ります。`ci-ok`のチェックが通らなければなりません。削除とforce pushはできません。
- `v2x-mirror`は、`v2.x`に掛かります。削除とforce pushはできません。プルリクエストのルールはありません。そのルールがあると、ミラーのワークフローのpushが拒まれるからです。
- `release-tags`は、`v*`のタグに掛かります。タグを作り、動かし、消せるのは、リポジトリの管理者だけです。
- `no-branch-shaped-tags`は、`v*.x`、`next`、`master`、`main`のタグに掛かります。だれもこれらのタグを作れません。そのため、`v2.x`のような名前は、いつもブランチを指します。

### 条件

手順1の前に、オーナーは次のすべてが成り立つことを確かめ、昇格を始める許可を出します。

1. `next`に`v3.0.0-rc.N`のプレリリースのタグを付けてあります。そのタグでCIが通り、そのタグに対して報告された不具合のうち、リリースを止めるものはありません。最後のリリース候補をどれだけの期間公開しておくかは、決まっていません。下の「決まっていないこと」を見てください。
2. v3の移行ガイドと、v3.0.0のリリースノートが完成しています。
3. 昇格する前に出す2.xの最後のリリースには、`master`でタグを付けてあります。そのリリースノートのエントリーも記録してあります。そのタグの後にマージした2.xの修正は、`v2.x`から出す次の2.xのリリースに入ります。
4. 下の決まっていないことを決め、v3の計画かこの節に記録してあります。手順4では、昇格した後のブランチの状態を説明します。その説明は、`next`が何になるか、修正が系列の間をどう移るか、サイトがどのバージョンを表示するかによって変わります。

### 手順

1. **最後に`master`を`next`へマージします。エージェントの作業です**。ほかの`master`から`next`へのマージと同じく、プルリクエストで`master`を`next`へマージします。こうすると、`next`にすべての2.xの修正が入ります。ここから手順5まで、`master`へはほかに何もマージしません。2.xの修正が待てないときは、手順2の前にその修正をマージし、この手順を繰り返します。
2. **ミラーを止めます。オーナーの作業です**。`v2.x`と`master`が同じコミットを指すことを確かめます。このとき、`git ls-remote origin refs/heads/master refs/heads/v2.x`は、1つのidを2回出力します。idが違うときは、`gh workflow run mirror-v2x.yml --ref master`で、`master`でワークフローを実行します。`gh run list --workflow=mirror-v2x.yml`で実行が終わるまで待ち、もう一度確かめます。実行が失敗したときは、そのジョブのログに`v2.x`の直し方が書いてあります。たとえば、`master`に無いコミットが`v2.x`にあるときや、`workflows`の権限が無いためにpushが拒まれたときです。idが一致するまで、ワークフローを無効にしないでください。一致したら、`gh workflow disable mirror-v2x.yml`で無効にします。これ以降、`v2.x`は2.xの最後のコミットに留まります。この手順は、手順5の前にしてください。手順5で作るマージコミットの最初の親は`v2.x`の先頭なので、そのpushでワークフローが動くと、`v2.x`が3.xへfast-forwardされます。手順4は手順5のマージコミットからワークフローのファイルを消すので、それでもワークフローは動きません。ここで無効にすると、手順4に頼らずに、`v2.x`を守れます。
3. **ほかの系列と同じように`v2.x`を保護します。オーナーの作業です**。`protected-lines`の対象に`refs/heads/v2.x`を加え、`v2x-mirror`を消します。それ以降、`v2.x`は、`ci-ok`が通ったプルリクエストを通してだけ変わります。CIを変える必要はありません。[test.yml](../../.github/workflows/test.yml)は、既に`v*.x`へのpushとプルリクエストで動きます。
4. **`next`を準備します。エージェントの作業です**。`next`への2つのプルリクエストを、次の順番にマージします。
   - 1つ目のプルリクエストは、`.github/workflows/mirror-v2x.yml`を消し、昇格の後のブランチを説明します。説明するのは、README.mdのブランチの運用、AGENTS.mdのブランチのテーブルとルール、SECURITY.mdのサポートするバージョン、`.github/PULL_REQUEST_TEMPLATE.md`の「Target branch」です。2.xの修正は`v2.x`を対象にし、v3の修正は`master`を対象にします。README.mdのバッジは、画像の`branch=next`とリンクの`query=branch%3Anext`を、`master`へ変えます。このプルリクエストは、`.github/dependabot.yml`に、`target-branch: "v2.x"`を持つ2つ目の`github-actions`のエントリーも加えます。こうすると、手順5からは、`master`のこのファイルにそのエントリーがあります。Dependabotはこのファイルをデフォルトブランチからだけ読み、`target-branch`の無いエントリーではデフォルトブランチだけを更新します。そのため、新しいエントリーが無いと、2.xをサポートする間、`v2.x`のワークフローでSHAに固定したactionが更新されません。このプルリクエストではサイトも系列に合わせて移します。未リリースの3.1が現行版として表示されないようにするためです。[サイトの計画](https://github.com/matsumotory/ngx_mruby/blob/next/docs/proposals/site.md#52-repository-layout)の5.2節に従い、`.github/workflows/site.yml`を`master`で実行して`master`からデプロイするようにし、`/v2/`を`v2.x`の`docs/`からビルドするようにします。`site-v2.yml`と`site-dispatch.yml`の2つのファイルは削除します。
   - 2つ目は、`docs/releases/v3.0.0.md`についての、[「タグの前に」](releases/README.md#タグの前に)のチェックのプルリクエストです。その節が`next`について書くとおり、範囲は最後の`v3.0.0-rc.N`のタグから始まります。このプルリクエストは、そのタグの後に`master`を`next`へマージしたことで入った2.xのプルリクエストに、2.xのファイルのエントリーがあることを確かめます。そのマージには、手順1のマージも含まれます。また、タグがまだ無い2.xのリリースについて、そのエントリーを`v3.0.0.md`へコピーします。それらは、条件3で書いた2.xの最後のリリースより後にマージした、2.xの修正のエントリーです。v3.0.0がそれらの修正を最初に出すので、コピーします。このプルリクエストの後は、手順5まで、`next`ブランチへほかに何もマージしません。
5. **昇格します。エージェントの作業で、その日にオーナーが許可を出してから始めます**。headが`next`でベースが`master`のプルリクエストを作ります。ほかのすべてのプルリクエストと同じく、[AGENTS.md](../../AGENTS.md#review-and-merge)の「Review and merge」の条件が成り立ったときに、マージコミットでマージします。ただし、マージするのは、手順6のリリースをすぐに出す許可を、オーナーがその日に出した後だけです。こうすると、`master`がタグの無い3.xの系列になる時間がありません。手順1で`master`を`next`へマージしたので、このプルリクエストにコンフリクトはありません。`master`はデフォルトブランチのままです。デフォルトブランチについては、何も変わりません。マージ直前に、オーナーは`github-pages`環境のデプロイブランチ規則を`next`から`master`へ変更します。GitHubのSettings、Environments、`github-pages`、Deployment branchesで設定します。こうすると、マージのpushで、サイトが`master`からデプロイされます。
6. **タグを付けてリリースします。エージェントの作業で、オーナーの許可を得て、手順5の直後にします**。手順5のマージコミットで`v3.0.0`のGitHubのリリースを、リリースノートとともに公開します。`gh release create`がタグを作ります。リリースには、プレリリースの印を付けません。チェックのプルリクエストのマージコミットではなくこのコミットでリリースを公開するのは、[「タグの前に」](releases/README.md#タグの前に)にある「後のコミット」の場合です。チェックのプルリクエストの後にマージしたプルリクエストについて、チェックを繰り返します。そのようなプルリクエストは手順5の昇格だけで、エントリーは要りません。手順1の後は`master`が`next`の祖先なので、手順5で作るマージコミットのツリーは`next`と同じです。そのため、設定、スクリプト、ビルドから見えるものは何も変わりません。
7. **告知します。エージェントの作業です**。`master`へのプルリクエストで、v3.0.0をリリースした日と、その12か月後に2.xのサポートが終わる日を、README.mdとSECURITY.mdに加えます。`v2.x`へのプルリクエストでは、次のことをします。
   - `v2.x`のREADME.md、AGENTS.md、SECURITY.md、プルリクエストのテンプレートで、`v2.x`を2.xの系列として説明します。
   - `v2.x`にある`mirror-v2x.yml`のコピーを消します。このワークフローを起動するのは`master`へのpushだけなので、そのコピーは動きません。
   - `v2.x`のファイルにある`master`への絶対のリンクを、`v2.x`へ向けます。`v2.x`では、これらのリンクの先が3.xのファイルになるからです。対象は、このリポジトリの`tree/master`と`blob/master`のURL、README.mdにあるCIのバッジの`badge.svg?branch=master`、`docs/install/README.md`にあるダウンロードのリンクの`archive/master.zip`です。URLは、2026-10-04の時点で、README.md、`docs/`、プルリクエストのテンプレートに24個あります。
   - `docs/install/README.md`、`Dockerfile`、`misc/provision.sh`にある、デフォルトブランチのクローンに`-b v2.x`を加えます。対象は、`-b`の無い`git clone https://github.com/matsumotory/ngx_mruby.git`です。これが無いと、`v2.x`のインストールガイドに従った2.xの利用者も、`v2.x`のチェックアウトからDockerfileをビルドした利用者も、3.xを得ます。
   - `master`でだけ実行する`site-v2.yml`と`site-dispatch.yml`のコピーを`v2.x`向けに変え、dispatchで`site.yml`を`--ref master`で起動するようにします。こうすると、2.xのドキュメントを変えたときも、`/v2/`に反映されます。

   リンク、バッジ、クローンは、次のコマンドで一覧できます。`git grep -n -E 'ngx_mruby/(tree|blob|archive)/master|branch=master|clone https://github\.com/matsumotory/ngx_mruby'`。
8. **昇格の後の運用です**。2.xの修正は`v2.x`を対象にし、v3の修正は`master`を対象にします。2.xの各リリースは、リポジトリの最新のリリースにならないように公開します。最新のリリースは3.xのままにします。コマンドは`gh release create <tag> --latest=false`です。REST APIでは、公開したリリースの`make_latest`のデフォルトは`true`です。Webのフォームでは、「Set as latest release」を選ばないでください。

### 決まっていないこと

v3の計画は、次のことをまだ決めていません。どれにも推奨があります。条件4は、手順1の前にこれらを決めることを求めています。

- **昇格の後に`next`が何になるか**。推奨：次のマイナーリリースの3.1を開発するブランチとして残し、プレリリースのタグを付けます。こうすると、`master`は、デフォルトブランチの利用者がビルドする、リリースした3.xの系列のままになります。今の`master`が、リリースした2.xの系列であるのと同じです。もう1つの選択肢は、`next`をやめて、3.1を`master`で開発することです。
- **v3.0.0の前に、最後のリリース候補をどれだけの期間公開しておくか**。推奨：リリースを止める新しい報告が無いまま、少なくとも2週間公開しておきます。
- **昇格の後、両方の系列に要る修正をどう移すか**。推奨：先に`master`を直し、その修正を`backport/v2.x/<topic>`のブランチで`v2.x`へバックポートします。この名前は、AGENTS.mdが既にバックポートに付けている名前です。`v2.x`を`master`へマージすると、2.xのためだけの変更も入ります。
- **昇格の許可を出し、手順2と3でリポジトリの設定を変えるのはだれか**。推奨：オーナーです。条件1が成り立つかは判断です。手順6のリリースの許可はオーナーが出し、設定には管理者の権限が要ります。設定を誤ると、`v2.x`が3.xへ動くおそれがあります。AGENTS.mdは、昇格の許可とリポジトリの設定をまだ扱っていません。

昇格後にサイトが表示するバージョンは、`next`の[`docs/proposals/site.md`](https://github.com/matsumotory/ngx_mruby/blob/next/docs/proposals/site.md#7-decisions-2026-10-15)の7節、Q1とQ4で決まっています。オーナーが2026-10-15に決定しました。ngx.mruby.orgは、`next`の`.github/workflows/site.yml`が`docs/`からビルドし、GitHub Actionsでデプロイします。現在はプレフィックスなしのパスに`next`の3.x、`/v2/`に`master`の2.xを表示します。昇格後は、プレフィックスなしのパスに`master`のリリース済み3.x、`/v2/`に`v2.x`の2.xを表示します。手順4、5、7でワークフローとデプロイブランチ規則を移します。

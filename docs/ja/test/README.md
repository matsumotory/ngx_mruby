ngx_mrubyのテストは、mrubyのテストを使います。ngx_mrubyのテストは、まだごく初期の実験的なバージョンです。

プルリクエストを歓迎します。
## テストを追加する
##### ``test/conf/nginx.conf``にlocationの設定を追加する
```nginx
# Nginx.hello test
location /mruby {
    mruby_content_handler build/nginx/html/unified_hello.rb cache;
}
```
##### locationの設定にスクリプトが要るなら、``test/html/``にフックのスクリプトを追加する
```ruby
# test/htdocs/unified_hello.rb
if server_name == "NGINX"
  Server = Nginx
elsif server_name == "Apache"
  Server = Apache
end

Server::rputs "Hello #{Server::module_name}/#{Server::module_version} world!"
```
##### ``test/t/ngx_mruby.rb``にテストのコードを追加する
```ruby
assert('ngx_mruby', 'location /mruby') do
  res = HttpRequest.new.get base + '/mruby'
  assert_equal 'Hello ngx_mruby/0.0.1 world!', res["body"]
end
```

テストのクライアントは、`build_config.rb`の`test`のビルドです。このクライアントは`NO_SSL`でビルドするので、`HttpRequest`と`SimpleHttp`は`https`のリクエストを送れません。HTTPSのリクエストを送るには、既存のテストと同じように、`base_ssl(port)`が返すURLで`curl -k`を実行するか、`openssl s_client -connect localhost:<port>`を実行してください。例は、`test/t/ngx_mruby.rb`のテストにある`` `curl -s -k #{base_ssl(18082) + '/'}` ``です。

## フラグメントとケースのファイルでテストを追加する

`test/conf/nginx.conf`と`test/t/ngx_mruby.rb`を編集する代わりに、テストを専用のファイルに置くこともできます。

- `test/conf/conf.d/<name>.conf`：`http {}`ブロックの最後でインクルードするフラグメントです。フラグメントは、専用のポートの`server {}`を持ちます。ポートは18110から18199です。ただし18116は、`test/t/cases/_second_instance.rb`が起動する2つ目のnginxが使います。`stream {}`のフラグメントは`test/conf/conf.d/stream/`に置きます。そのポートは12353から12399で、12357は2つ目のnginxが使います。各ポートは、これらの範囲の5桁の数で書いてください。そう書くと、`TEST_SH_PORT_OFFSET`で、そのポートがずれます。説明は下の「ポート」にあります。
- `test/t/cases/<name>.rb`：`test/t/ngx_mruby.rb`の後に実行するテストのファイルです。`test.sh`は、このファイルの先頭に`test/t/cases/_prelude.rb`を付けて実行します。`_prelude.rb`は、`base`、`base_ssl`、`http_host`、`html_path`、`nginx_t`、`tcp_client`、`second_instance`、`suite_path`を定義します。`nginx_t`は、生成した設定で`nginx -t`を実行します。`suite_path`は、`test.sh`が実行するスイートのコピーの中で、スイートのファイルのパスを返します。CRubyのヘルパーは、`` `ruby #{suite_path('test/t/cases/_x.rb')}` ``のように実行してください。説明は下の「ポート」にあります。ケースのファイルは`SimpleTest.new`で始まり、`t.report`で終わります。名前が`_`で始まるファイルはヘルパーで、ケースとしては実行しません。`_tcp_client.rb`、`_filter_connection_client.rb`、`_request_body_client.rb`、`_second_instance.rb`は、`_prelude.rb`のヘルパーとケースが`ruby`で実行するCRubyのスクリプトです。`_wait_for_listen.rb`は、test.shがnginxを待つために実行するCRubyのスクリプトです。説明は下の「nginxがlistenするまで待つ」にあります。`_agent_proxy_client.rb`は、`agent_proxy.rb`が自分で実行するCRubyのスクリプトで、CRuby 3.0以降が要ります。このスクリプトは`test/soak/mock_llm.rb`と`test/soak/http_client.rb`を読み込み、リクエストを送る間、LLMのモックのupstreamを12372と12373で動かします。説明は下の「LLMのモックのupstream」にあります。このスクリプトは、`key=value`の行を出力します。
- フックのスクリプトは、これまでどおり`test/html/`に置きます。フラグメントは、そのスクリプトを`build/nginx/html/<name>.rb`として参照します。

`test.sh`は、スイートのコピーにあるフラグメントに`nginx.conf`と同じ置き換えをして、ビルドしたnginxの`conf/conf.d/`にコピーします。スイートのコピーの説明は、下の「ポート」にあります。そして、ケースのファイルを1つずつ順に実行します。ケースが失敗すると、`test/t/ngx_mruby.rb`のアサーションが失敗したときと同じく、`test.sh`は0以外のステータスで終了します。

nginxを自分で起動するケースは、CIのsanitizerのセルでも動きます。そうしたケースは`nginx_t`か`second_instance`を使います。sanitizerのセルでは、リークしたプロセスがあると、LeakSanitizerがそのプロセスの出力にレポートを書き足し、終了ステータスを変えます。そのため、そうしたケースは、プルリクエストを開く前に、sanitizerのビルドで1回実行してください。手順は下の「2つのsanitizerの下でテストを実行する」にあります。`nginx_t`は、`nginx -t`の実行ではリークの検出を切ります。`nginx -t`は読んだ設定を解放せずに戻るので、検出を切らないと、nginx自身のメモリの確保がすべて報告されるからです。`test/t/ngx_mruby.rb`の最後にあるstreamだけのテストも、自分が起動したnginxを止める`nginx -s quit`で、同じように検出を切ります。そのプロセスは、`main()`が最初に作るプールを解放せずに、nginxの`main()`から戻ります。検出を切らないと、そのレポートはテストのランナーの`stderr.log`に入ります。`second_instance`は、2つ目のnginxの`error.log`か`stderr.log`にある、sanitizerの最初の行を、`sanitizer`として返します。その行があると、ケースは2つ目のnginxの`error.log`を出します。

## 必須のステータスチェック

`.github/workflows/test.yml`は、`master`、`next`、`v*.x`へのプルリクエスト、これらのブランチと`v*`タグへのpush、「Run workflow」で起動します。ルールセットが必須とするステータスチェックは`ci-ok`です。`ci-ok`は、`needs`にある各ジョブが成功したか、`changes`の判定でスキップされた場合だけ成功します。対象は`changes`、`build`マトリクスの全ジョブ、`files`で、`next`では`soak`も含みます。マトリクスを実行する場合はvalgrindのセルも対象なので、そのエラーは`ci-ok`を失敗させます。[CIのvalgrind](#ciのvalgrind)を参照してください。`perf`はまだ`needs`に含まれません。

プルリクエストの実行は、作成、再オープン、headへのpush、readyへの変更で始まります。イベントは`pull_request`の`opened`、`synchronize`、`reopened`、`ready_for_review`です。Draftでは`changes`と`ci-ok`以外は動かず、ジョブ名も`ci-ok (draft)`になります。この実行ではテストしません。GitHubはDraftをマージしません。このジョブは別の名前なので、成功してもheadに`ci-ok`は付きません。そのため、readyにして始まる実行が成功するまで、headは必須チェックを満たしません。他のPR用ワークフローもDraftではスキップします。

readyのheadへpushすると、前のheadの実行をキャンセルして新しく実行します。baseが動くだけでは実行されません。`gh api -X PUT repos/<owner>/<repo>/pulls/<number>/update-branch`でブランチを更新すると、headへマージコミットがpushされて実行が始まります。その実行の結果は、そのときのheadのコミットと、merge refのbaseのコミットに対するものです。PRにはこの2つを記録します。[AGENTS.md](../../../AGENTS.md)の「Review and merge」の条件2は、この記録と、baseの更新によって再実行が必要になる条件を定めています。

キャンセルしたDraftの実行は、結果を報告しません。readyにすると、数える対象の実行が始まり、まだ動いているDraftの実行は`cancel-in-progress`でキャンセルされます。キャンセルされた実行の`ci-ok`は動かず、未完了の他のジョブと同様にcancelledになります。cancelledは成功ではありません。[#692](https://github.com/matsumotory/ngx_mruby/pull/692)の[実行41193944190](https://github.com/matsumotory/ngx_mruby/actions/runs/41193944190)がその例です。以前は`always()`で`ci-ok`が動いて失敗し、[#678](https://github.com/matsumotory/ngx_mruby/pull/678)では有効な実行の成功した`ci-ok`の横に、Draftの失敗した`ci-ok (draft)`が残りました。[実行41191594780](https://github.com/matsumotory/ngx_mruby/actions/runs/41191594780)を参照してください。開始前にキャンセルされたジョブの名前には`name`の式がそのまま残り、`gh pr checks`はcancelledを`fail`と表示します。どちらも有効な実行の`ci-ok`ではありません。

それ以外の実行では`ci-ok`に`always()`を使います。必要なジョブが終わる前に、新しいpushか「Cancel workflow」で実行がキャンセルされると、`ci-ok`は動いて失敗します。その実行はコミットを最後までテストしていないからです。新しいpushによる失敗は、置き換えられた古いheadに残ります。GitHubの説明では`cancelled()`はワークフローがキャンセルされたことを示しますが、必要なジョブの`timeout-minutes`超過でも真になるかは明記されていません。真になるなら`!cancelled()`の`ci-ok`はスキップされ、そのスキップが必須チェックを満たしてしまいます。ルールセットが要求しない`site.yml`の`site-ok`には`!cancelled()`を使います。実行がキャンセルされると`site-ok`はfailedでなくcancelledになり、`site-ok`の成功を必要とする`deploy`は実行されません。

CIはクリーンな環境での最終確認であり、変更を初めて試す場所ではありません。これは2026年10月31日のオーナーの規則で、AGENTS.mdの「Branches and pull requests」にあります。readyにする前に作者が対象のチェックをローカルで実行し、PRの「How was this tested」にコマンドと結果を記載します。`test/ci/changes.sh`が`build`を`standard`か`full`と判定したら、テストスイートも対象です。レビュアーは記録を確認します。ローカルで動く検査をCI任せにしません。

readyのPRは必要なジョブだけを実行し、全体を約15分で終えます。2026年10月31日の#678では、buildのセルに6〜14分、マトリクス全体に15分かかりました。[実行41191594773](https://github.com/matsumotory/ngx_mruby/actions/runs/41191594773)がその記録です。`site.yml`のブラウザの系統は並列に動き、1つの系統に3〜8分、実行の全体に10分かかりました。[実行41191594863](https://github.com/matsumotory/ngx_mruby/actions/runs/41191594863)を参照してください。CIに検査を加える提案では、その検査をローカルで実行できるか、なぜCIでも要るか、実行が何分延びるかを書きます。

### 実行するジョブの選択

`test/ci/changes.sh BASE HEAD`が変更ファイルを分類します。変更の種類で実行を決めるワークフローはすべてこのファイルを読み、方針を一か所に集約します。`sh test/ci/changes_test.sh`で検査できます。出力はキーごとに1行で、分類は`code`、`tests`、`docs`、`site`、`examples`、`workflows`、続いて`soak`と`perf`がそれぞれ`true`か`false`になります。最後の`build`は、`build`マトリクスのどのセルを実行するかを表します。`code`か`tests`が真なら`standard`、それ以外は`none`です。renameは`git diff --no-renames`で旧パスと新パスの両方を分類するため、ソースを`docs/`へ移してもビルドします。`test.yml`の`changes`ジョブは、実行の種類もスクリプトに渡します。渡すのは、Draftかどうか、readyのPRのラベル、push、タグ、「Run workflow」とその`valgrind`入力です。下の2つ目の表の実行では、スクリプトは`build`を、全セルを表す`full`か、`none`にします。

| 分類 | パス | readyのPRが実行するワークフロー |
|---|---|---|
| `code` | `src/`、`mrbgems/`、`mruby/`、`dependence/`、`build_config.rb`、`build_config.rb.lock`、`configure`、`configure.in`、`config.in`、`Makefile.in`、`build.sh`、`nginx_version`、他の分類にない全パス | `test.yml`の`build`マトリクスのうち下の表の標準の4セル、`soak`、`perf`。`nginx-tests`、`examples`、`site`、`codeql`は各パスフィルタに従って動く |
| `tests` | `test/`、`test.sh`、`.github/workflows/test.yml` | `test.yml`の標準の4セル。`soak`が真ならソーク、`perf`が真なら比較 |
| `docs` | `docs/`、トップレベルにあるMarkdownのファイル、`AUTHORS`、`LEGAL`、`LICENSE`、`MITL` | siteのビルドと静的検査。`ci-plan.mjs`がページを選んだらブラウザ検査 |
| `site` | `.github/workflows/site.yml`と`site/` | siteのビルド、静的検査、全部のブラウザ検査 |
| `examples` | `examples/` | examplesとsiteのビルド・静的検査 |
| `workflows` | `.github/`のうち`test.yml`と`site.yml`を除いたもの | zizmorは全ワークフローを検査。`.github/workflows/`と`.github/codeql/`はCodeQLも対象 |

標準の4セルは、静的モジュールと動的モジュール、nginxのmainline 1.31とstable 1.30を、それぞれ少なくとも1回ビルドします。メモリの検査も、2種類とも実行します。

| セル | nginx | モジュール | OpenSSL | nginxの動かし方 |
|---|---|---|---|---|
| nginx 1.31.8、静的モジュール | 1.31.8 | 静的 | `--with-openssl-src` | 直接動かす |
| nginx 1.30.6、動的モジュール | 1.30.6 | 動的 | システムのOpenSSL | 直接動かす |
| sanitizerのセル | 1.31.8 | 静的 | システムのOpenSSL | AddressSanitizerとUndefinedBehaviorSanitizerを付けてビルドする。[2つのsanitizerの下でテストを実行する](#2つのsanitizerの下でテストを実行する)を参照 |
| valgrindのセル | 1.31.8 | 静的 | システムのOpenSSL | valgrindの下で実行する。[CIのvalgrind](#ciのvalgrind)を参照 |

PRで全セルでなくこの4セルを実行することは、2026年11月1日にオーナーが決めました。セッションの問いに対して、オーナーは、セッションが推奨とした4セルに減らす選択肢を選びました。オーナーの言葉は[docs/HANDOFF.md](../../HANDOFF.md)の「Decisions」にあります。どのセルも、nginxをビルドする前にOpenSSL 1.1.1wをビルドしてインストールします。1つ目のセルは、`--with-openssl-src`でOpenSSLをnginxにも組み込み、`configure.in`と`Makefile.in`のこの経路を通ります。valgrindのセルは同じnginxとモジュールをシステムのOpenSSLでビルドするので、この経路を通りません。

全セルは、nginx 1.31.8、1.30.6、1.28.3、1.26.3と、静的モジュールか動的モジュールか、`--with-openssl-src`を付けるかどうかを組み合わせた16セルに、sanitizerのセルを加えたものです。valgrindのセルは16セルの1つです。全セルは引き続き、夜間のvalgrindの実行、タグのpush、`base`入力のない「Run workflow」で実行します。タグの前のチェックのPRでも実行し、このPRにはラベル`full-matrix`を付けます。[docs/releases/README.md](../releases/README.md)の「タグの前に」を参照してください。ほかのセルでしか確かめられない変更、たとえばnginx 1.26.3向けの変更は、そのバージョンでローカルで確かめます。バージョンは`nginx_version`かセルの`NGINX_VERSION`で選び、モジュールは`BUILD_DYNAMIC_MODULE`で選びます。そのPRにラベル`full-matrix`を付けて、全セルを実行することもできます。

`soak`は`code`が真か、`test/soak/`または`test/build_release.sh`の変更時に真になります。`perf`は`code`が真か、性能測定に使う`test/perf/`、`test/build_release.sh`、`test/soak/`のシナリオファイルの変更時に真になります。未分類のファイルは`code`として全検査を実行し、理由を記載したPRで分類を追加するまでそのままです。複数の分類を変えるPRは、それぞれの分類に必要なジョブを実行します。

| 実行の種類 | 3つのジョブ`build`、`soak`、`perf` |
|---|---|
| DraftのPR | `files`とともにスキップ。ジョブ名は`ci-ok (draft)` |
| readyのPR | merge refの第1親であるbaseとの差を上の表で分類。`perf`は`build`が`standard`か`full`なら起動し、`perf`が真かラベル`perf`で比較 |
| `full-matrix`のラベルを付けたreadyのPR | ファイルにかかわらず、全セルと`soak`を実行。`perf`はラベルのないPRと同じ |
| `master`、`next`、`v*.x`ブランチへのpush | スキップ |
| `v*`タグのpush | 全セルと`soak`。`perf`はPRのみ |
| `base`入力が無いか`valgrind`入力がある手動実行。夜間の実行はこれにあたる | 全セルと`soak`。`perf`はPRのみ |
| `base`だけの実行 | ラベルのないPRとして`base`との差を分類する。`perf`はPRでだけ実行する |

`changes`ジョブは、実行のイベントからラベルを読みます。readyのPRに付けたラベルは、次の実行から効きます。次の実行は、headへのpushか、PRをDraftに戻してreadyにし直す操作で始まります。戻す操作は`gh pr ready --undo`、readyにする操作は`gh pr ready`です。ジョブを再実行してもイベントは変わらないので、読むラベルも前の実行と同じです。ラベル`full-matrix`はPRを開くときに`gh pr create --draft --label full-matrix`で付け、readyにしたときに全セルの実行が始まるようにします。リポジトリにこのラベルがなければ、`gh label create full-matrix`で作ります。

`test.yml`だけの変更は`tests`なので、標準の4セルは実行しますが、全セル、`soak`、性能比較は実行しません。それらのジョブを変えるPRは、ラベル`full-matrix`を付けるか、ブランチで`gh workflow run test.yml --ref <branch>`を実行して、それらのジョブを動かします。性能比較はラベル`perf`で動かします。手動実行のジョブ名は`ci-ok (manual)`で、PRに補足の検証結果として記録します。「Review and merge」の条件2が求めるPR自身の実行とは別です。

「Run workflow」で`base`入力にブランチかコミットIDを渡すと、スクリプトは、ブランチが`base`とのmerge baseから変えたファイルを分類します。こうすると、ブランチのPRで何が動くかを確かめられます。

```console
$ gh workflow run test.yml --ref claude/topic -f base=next
```

この実行のジョブ名は`ci-ok (dry run)`で、`ci-ok`ではありません。`base`は実行する人が選ぶので、その結果は、ルールセットがコミットに求めるチェックにならないからです。同じように、`valgrind`入力のある実行のジョブ名は`ci-ok (valgrind)`です。この実行は始まった時点のブランチの先頭をビルドするので、キャンセルされると、そのコミットに失敗した`ci-ok`が残るからです。そのほかの「Run workflow」のジョブ名は`ci-ok (manual)`です。この実行はPRのマージコミットでなくブランチのheadを検査します。そのため、headに`ci-ok`として付くと、PR自身の実行が成功する前に、PRの必須チェックを満たしてしまいます。`valgrind-nightly.yml`は、ジョブの名前でなく、実行の結果を読みます。

`master`と`next`へのpushでは、`changes`、`files`、`ci-ok`だけが動きます。どちらのブランチも、PRを通してだけ変更を受け付けます。[AGENTS.md](../../../AGENTS.md)の「Review and merge」の条件2により、セッションがPRをマージできるのは、PRの実行がまだそのマージに当てはまる間だけです。つまり、その実行の後に、PRが変える分類のファイルをbaseが受け取っていない間です。ルールセットは`ci-ok`を求めますが、ブランチがbaseに追いついていることは求めません。ブランチの先頭を単独でビルドしてテストするには、`gh workflow run test.yml --ref next`のように「Run workflow」を使います。夜間のvalgrindの実行もこの形の実行で、`master`の`valgrind-nightly.yml`のスケジュールが、`master`と`next`で起動します。説明は[CIのvalgrind](#ciのvalgrind)にあります。ほかのワークフローは、それぞれの条件で動きます。`site`は`next`へのすべてのpushでデプロイします。`codeql`は、`src/`、`mrbgems/`、ワークフロー、CodeQLの設定を変える`master`と`next`へのpushを検査します。説明は[CodeQL](#codeql)にあります。`nginx-tests`、`examples`、`zizmor`はPRでだけ動きます。

`build`、`soak`、`files`がスキップされたとき、`ci-ok`がそれを成功と数えるのは、`changes`が成功し、その実行にそのジョブは要らないと判定した場合だけです。`changes`の失敗のような別の理由でスキップされたジョブがあると、`ci-ok`は失敗します。必要なジョブが成功しなかったときも失敗します。ファイルに要らないジョブをスキップしたPRは、その実行によって「Review and merge」の条件2を満たします。

<a id="files-that-do-not-belong-in-the-repository"></a>

### リポジトリに置かないファイル

`files`ジョブは、`test/check_added_files.sh BASE HEAD TIP`を実行します。このスクリプトは、ファイルの2つの一覧を調べます。

- 変更が加えるファイル：`HEAD`にあって`BASE`に無いパスです。スクリプトは`git diff --no-renames --diff-filter=A`でこの一覧を作るので、名前を変えたファイルや移動したファイルは、新しいパスに加わったものとして数えます。
- 変更のコミットが加えるファイル：`TIP`からfirst parentをたどって`BASE`まで戻る各コミットを、そのコミットのfirst parentと比べます。コミットの範囲は`git log --first-parent BASE..TIP`です。あるコミットが加え、後のコミットが消したファイルは、マージの後も履歴に残るので、これも調べます。

どちらの一覧のファイルも、`test/forbidden_paths.txt`のパターンに一致すると、終了ステータス1で失敗します。パターンに一致するのは、次のファイルです。

- `.claude/`の下にある、AIのコーディングエージェントが作るセッションのディレクトリと、そのエージェントのローカルの設定。`.claude/`の下で通るのは、`.claude/settings.json`、`.claude/commands/`、`.claude/skills/`だけです。この3つも、別の`.claude/`の下にあると失敗します。
- 最上位に作るビルドのディレクトリの`build/`、`build_dynamic/`、`build_soak/`、`build_perf/`と、`mruby/build/`
- サイトのビルドの`site/dist/`、`site/build-screenshots/`、`site/generated/`、`site/.astro/`
- `./configure`かMakefileが最上位に書くファイル。`Makefile`、`config`、`config.status`、`autom4te.cache/`、`mrbgems_config`、`.mruby_version`と、`.openssl_*_done`のファイルです。
- `.vagrant/`
- GNU Globalかctagsが作るタグのファイル
- `.log`のファイル
- `.env`と`.env.*`
- 秘密鍵の素材
- エディタやOSが残したファイル
- `node_modules/`、`__pycache__/`、`.pyc`のファイル
- コアダンプ

1つ目の一覧のファイルは、空のとき、つまり0バイトのときにも失敗します。ただし、名前が`.gitkeep`か`.keep`のファイルは除きます。どちらの一覧にも、サブモジュールのエントリー、つまりgitlinkが入ります。gitの設定や`.gitmodules`がサブモジュールを無視すると書いていても、同じく入ります。

スクリプトは、失敗した各パスを出力します。パスには、一致したパターンと、パターンのファイルでのその行か、「empty file」が付きます。また、そのファイルを加えたコミットも付きます。すべてのファイルが通ると、スクリプトは調べたファイルの数を出力し、0で終了します。次のときは、2で終了します。

- パターンのファイルが無いとき
- パターンが正しくないとき
- リビジョンがリポジトリに無いとき
- リポジトリがshallowクローンであるとき
- gitのコマンドが失敗したとき

スクリプトが読むのは、パターンのファイルとgitのリポジトリだけです。

スクリプトは、コミットをfirst parentだけでたどります。その中のマージコミットは、そのコミットのfirst parentと比べます。そのため、2つ目の親が持ち込むファイルは、リポジトリでのパスで調べ、2つ目の親のコミットは1つずつは調べません。こうすると、`./update-mruby-subtree`によるサブツリーのマージの、squashしたコミットを調べずに済みます。そのコミットのパスには、`mruby/`のプレフィックスがありません。一方で、マージしたサイドブランチのあるコミットが加え、同じサイドブランチの後のコミットが消したファイルは、このチェックからは見えません。

プルリクエストでは、ジョブは、プルリクエストのマージコミットを、`fetch-depth: 0`で履歴ごとチェックアウトします。そして、マージコミットを、そのfirst parentと比べます。first parentは、プルリクエストをマージした先のベースブランチです。また、プルリクエストのheadのコミットから、そのベースまでのコミットを調べます。headのコミットは、マージコミットの2つ目の親です。そのため、ブランチがベースより遅れているプルリクエストでも、その間にベースが消したファイルでは失敗しません。ブランチへのpushでは、ジョブは、ブランチの前の先頭の`github.event.before`を、pushしたコミットと比べます。そして、その間のコミットを調べます。タグのpush、ブランチを作るpush、手動の実行には比べるものが無いので、ジョブは成功します。スクリプトかパターンのファイルを変えるプルリクエストは、そのプルリクエストにあるバージョンのスクリプトとパターンで調べます。そのため、その変更はプルリクエストのレビューの対象になります。

`test/forbidden_paths.txt`は、1行に1つずつ、POSIXの拡張正規表現を持ちます。形式は`grep -E`が読むものと同じです。スクリプトは、各パターンが、リポジトリの最上位からのパスに一致するかを見ます。`!`で始まる行は例外です。`.gitignore`と同じく、パスが一致した最後の行が結果を決めます。たとえば`.claude/skills/a/SKILL.md`は、`(^|/)\.claude/`に一致し、その後で例外の`!(^|/)\.claude/skills/`に一致するので、通ります。一方、`.claude/skills/a/.DS_Store`は、さらに下の`(^|/)\.DS_Store$`にも一致するので、失敗します。空の行と、`#`で始まる行はコメントです。パターンは一般的なものにしてください。ほかのプロジェクト、人、ホストの名前は、入れないでください。

プルリクエストを開く前にこのチェックを実行するには、変更をコミットし、ベースブランチと比べてください。`next`への変更なら、ベースは`origin/next`です。引数が2つでも、スクリプトは`HEAD`からベースまでのコミットも調べます。スクリプトには履歴のすべてが要るので、shallowでないクローンで実行してください。

```console
$ git fetch origin master
$ sh test/check_added_files.sh origin/master HEAD
check_added_files.sh: 2 added file(s) checked between origin/master and HEAD and in the 2 commit(s) of origin/master..HEAD, none forbidden or empty
```

ファイルが失敗したら、そのファイルを変更から外してください。`git rm --cached <path>`で外すと、ファイルはディスクに残ります。そのファイルがリポジトリに要るものなら、同じプルリクエストで`test/forbidden_paths.txt`を変え、プルリクエストの説明に理由を書いてください。空のファイルなら、変えるのはスクリプトです。あるコミットが加え、後のコミットが消したファイルは、履歴に残ります。そのファイルは、加えたコミットから取り除くか、コミットをsquashしてください。取り除くには、たとえば`git rebase -i`のコマンドを使います。

## サイトの2.xページ

ngx.mruby.orgは`next`の`site/`でビルドします。計画は同ブランチの`docs/proposals/site.md`にあります。`/v2/`の2.xページは`master`の`docs/`から作り、次の2つのワークフローで更新します。

- `.github/workflows/site-v2.yml`は`master`への全PRで動きます。2.xページは`.travis.yml`、`nginx_version`、ワークフローなどリポジトリ全体にリンクするため、パスフィルタはありません。PRの隣に`next`をチェックアウトし、`next`のsiteと3.xページ、PRの`docs/`の2.xページを組み合わせてビルドします。`next`の`node site/scripts/build-v2.mjs --tree DIR`を使います。次のときに失敗します。2.xのページのソースに解決できない相対リンクかアンカーがあるとき、gitが追跡しないファイルへのリンクがあるとき、ビルドしたサイトのリンクが壊れているとき、2.xのバナーの無い2.xのページがあるとき、あるバージョンの検索がもう一方のバージョンのページを表示するときです。成果物は`site-v2`です。
- `.github/workflows/site-dispatch.yml`は`master`への全pushで、`gh workflow run site.yml --ref next`を実行します。新しい2.xページを使ってsiteを再ビルドするためです。GitHubがdispatchを拒否した場合や、起動した実行を特定できない場合は失敗します。

どちらも`ci-ok`の`needs`には含まれません。

## サプライチェーンの検査

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16057/badge)](https://www.bestpractices.dev/projects/16057)

上はプロジェクトのOpenSSF Best Practicesのpassingバッジです。以下のScorecardとは別の評価です。

4つのワークフローがビルドのサプライチェーンとコードを検査します。どれも`ci-ok`の`needs`にはなく、ルールセットを通じてマージを止めるものではありません。ただし、AGENTS.mdの「Review and merge」は、headのすべてのCIのチェックが成功することを求めます。そのPRで動いた`zizmor`と`codeql`も、このチェックに含まれます。PRで動くワークフローはDraftではスキップし、readyにすると始まります。

### ワークフローの静的解析

`.github/workflows/zizmor.yml`は、[zizmor](https://docs.zizmor.sh/)を実行します。動くのは、`.github/workflows/`、`.github/dependabot.yml`、`.github/zizmor.yml`を変えるreadyのプルリクエストと、「Run workflow」です。pushでは動きません。PRの実行で同じファイルを検査済みだからです。zizmorは、`.github/`の下のファイルを、デフォルトのpersonaで監査します。この監査には、GitHubに問い合わせる監査も入ります。たとえば、既知の脆弱性があるアクションや、アクションのリポジトリに無いコミットを調べる監査です。指摘が1つでもあると、ジョブは失敗します。同梱した`mruby/`のツリーには、mruby自身のワークフローがあり、ngx_mrubyはそれらを実行しません。それらのワークフローは監査しません。zizmorのバージョンは、ワークフローの`version:`で固定しています。Dependabotは、アクションの固定は更新しますが、この入力は更新しません。

指摘は、ワークフローを直すか、理由を添えて受け入れます。受け入れるには、指摘のある行に`# zizmor: ignore[<audit>]`のコメントを付け、その上のコメントに理由を書きます。または、`.github/zizmor.yml`に`ignore`のルールを書き、その隣に理由を書きます。プルリクエストを開く前に同じチェックを実行するには、次のようにします。オンラインの監査には、GitHubのトークンが要ります。

```console
$ python3 -m venv .claude/tmp/zizmor && .claude/tmp/zizmor/bin/pip install zizmor==1.31.1
$ GH_TOKEN=$(gh auth token) .claude/tmp/zizmor/bin/zizmor --config .github/zizmor.yml .github
```

### OpenSSF Scorecard

`.github/workflows/scorecard.yml`は、[OpenSSF Scorecard](https://github.com/ossf/scorecard-action)を実行します。動くのは、`master`へのpush、毎週の定期の実行、「Run workflow」です。Scorecardはデフォルトブランチにしか対応しないので、プルリクエストでは動きません。このワークフローは、結果を、Scorecard APIの<https://api.scorecard.dev/projects/github.com/matsumotory/ngx_mruby>に公開し、code scanningにアップロードします。code scanningの結果は、リポジトリのSecurityのタブにあります。また、このワークフローは、SARIFのファイルを、実行のアーティファクトとして5日間保存します。結果を公開すると、Scorecard APIがワークフロー自身を調べます。そのため、このワークフローにはrunのステップも`defaults`もありません。制限の一覧は、ワークフローのファイルの先頭のコメントにあります。

GitHubは、公開リポジトリで60日間活動が無いと、そのリポジトリで定期に動くワークフローを無効にします。そうなると、このワークフローも次の節のワークフローも定期には動かず、何も失敗しません。「Run workflow」で実行するか、ワークフローを有効に戻すと、再び動きます。有効に戻すコマンドは、`gh workflow enable scorecard.yml`と`gh workflow enable gem-heads.yml`です。

### CodeQL

`.github/workflows/codeql.yml`は[CodeQL](https://codeql.github.com/)で`c-cpp`、`ruby`、`actions`の3言語を解析し、結果をリポジトリのSecurityタブのcode scanningへ送ります。`src/`、`mrbgems/`、`.github/workflows/`、`.github/codeql/`を変更する`master`と`next`向けのreadyのPRと両ブランチへのpush、毎週水曜日04:37 UTC、「Run workflow」で実行します。GitHubの定期実行は`master`のファイルから動くため、週次の対象は`master`です。

これは全PRと全pushで動いていたGitHubのdefault setupを置き換えます。default setupはオーナーが管理するリポジトリ設定で無効にしています。ワークフローのファイルは`master`と`next`で共通です。

3言語とも`build-mode: none`です。CとC++はnginxやmrubyをビルドせずソースを解析するため、ビルドは不要です。CodeQLの[Build options for compiled languages](https://docs.github.com/en/code-security/reference/code-scanning/codeql/build-options-for-compiled-languages)では、ビルドなしで作ったデータベースはビルドから作るものより精度が低い可能性があると説明しています。このワークフローも、ほかのワークフローと同じく、アクションをコミットIDで固定し、zizmorの検査を受けます。

vendoringした`mruby/`と`dependence/`は解析しません。前者にはmruby自身がvendoringしたコードも含み、後者はngx_devel_kitです。`init`が`config-file`として読む`.github/codeql/codeql-config.yml`の`paths-ignore`に指定しています。これらはgit subtreeで取り込むupstreamのコードで、手で編集しません。そのため、警告をこのリポジトリでは直さず、upstreamの変更は次のsubtreeの更新で取り込みます。[AGENTS.md](../../../AGENTS.md)の「Do not」を参照してください。

2026年10月31日にオーナーは、この除外、既存警告をvendored upstream codeとしてdismissすること、upstreamへ報告しないことを決めました。GitHubの[Workflow configuration options for code scanning](https://docs.github.com/en/code-security/reference/code-scanning/workflow-configuration-options)では、`paths-ignore`がRubyなどのインタープリタ言語と、ビルドなしで解析するCとC++に適用されると説明しています。

### GitHubから取るgemの先頭のコミット

`.github/workflows/gem-heads.yml`は、`test/gem_heads.sh`を実行します。動くのは、毎週月曜日、「Run workflow」、`build_config.rb`かスクリプトかワークフローを変えるreadyのプルリクエストです。スクリプトは、`build_config.rb`の`conf.gem github:`の各行について、次のことを報告します。

- ビルドがクローンするブランチの先頭のコミット。ブランチは、その行の`branch:`です。行に`branch:`が無ければ、mrubyのデフォルトの`master`です。
- gemのデフォルトブランチが、別のブランチかどうか
- リポジトリの名前が変わったか、リポジトリがアーカイブされたか
- 前のレポートから、先頭が動いたかどうか

`conf.gem mgem:`の行の`mruby-secure-random`は調べません。mrubyは、このgemをmgem-listのリポジトリを通して解決します。

前のレポートは、このワークフローを`master`で実行して成功した、定期の実行か手動の実行のうち、いちばん新しい実行が残したアーティファクト`gem-heads`です。アーティファクトは90日間残ります。`master`は`build_config.rb.lock`をコミットしないので、以前のビルドがどの先頭のコミットを取ったかを記録するのは、このレポートだけです。前のレポートが無い実行は、すべてのgemを`new`と報告します。先頭が動いたgemは、警告のアノテーションと、ジョブのサマリーにあるテーブルのエントリーになり、2つのコミットを比べるリンクが付きます。それでも、ジョブは成功します。リポジトリかブランチを読めないgemがあると、ジョブは失敗します。以前の実行を一覧にできないときも、ジョブは失敗します。前のレポートを取得できないときは、警告になり、すべてのgemを`new`と報告します。

チェックアウトでスクリプトを実行するには、次のようにします。スクリプトには、トークンを持つ`gh`のコマンドが要ります。

```console
$ bash test/gem_heads.sh build_config.rb "" .claude/tmp/gem-heads.tsv
```

実行が先頭の移動を報告したら、セッションは次のようにします。これはセッションの手順で、オーナーの決定ではありません。

- 比較のリンクの先にあるコミットを読みます。CIを含む`master`のすべてのビルドと、リリースした2.xのタグからのすべてのソースのビルドは、既に新しい先頭を取ります。移動だけではCIは動かないので、`master`で`test`ワークフローを実行し、その結果を読みます。コマンドは、`gh workflow run test.yml --ref master`です。
- 新しい先頭でビルドかテストスイートが壊れるときや、2.xの設定、スクリプト、ビルドから見える挙動が変わるときは、その実行を添えてオーナーに報告します。そして、`master`へのプルリクエストを提案します。プルリクエストの中身は、修正か、gemを最後の正常なコミットに固定する`checksum_hash:`で、リリースノートのエントリーも入れます。エントリーの書き方は`docs/releases/README.md`にあります。オーナーのgemの`matsumotory/mruby-*`には、`AGENTS.md`の「Other repositories」が当てはまります。
- `next`では`build_config.rb.lock`が各gemを固定するので、移動が`next`に届くのは、固定を動かすプルリクエストを通したときだけです。`perf`ジョブは、ロックのほかの変更と同じく、そのプルリクエストを測ります。

## テストを実行する
##### ``./build/nginx``にnginxをビルドし、``./build/nginx``でテストする
```
sh test.sh
```

`test.sh`は、`--with-debug`、`--with-http_stub_status_module`、`--with-http_ssl_module`、`--with-http_auth_request_module`、`--with-stream`を付けて、nginxをconfigureします。これらのオプションは、`test.sh`の`NGINX_DEFAULT_OPT`と`NGINX_CONFIG_OPT`にあります。そのため、テストの設定は、これらのモジュールのディレクティブを使えます。CIは、新しいチェックアウトで同じ`test.sh`を実行します。手元のビルドのディレクトリは、nginxを最初にconfigureしたときのオプションを保ちます。Makefileがnginxを再びconfigureするのは、`build/nginx-X.Y.Z/objs/Makefile`が無いときだけだからです。`BUILD_DYNAMIC_MODULE`のビルドでは、このファイルは`build_dynamic/...`にあります。これらのオプションを変えたら、そのファイルを消し、`ONLY_BUILD_NGX_MRUBY`を付けずに`test.sh`を1回実行してください。そうしないと、nginxは、テストの設定で「unknown directive」のエラーを出して止まります。`nginx_version`か`BUILD_DYNAMIC_MODULE`を変えた後も、`ONLY_BUILD_NGX_MRUBY`を付けずに`test.sh`を1回実行してください。そのとき`test.sh`は、新しいバージョンの`build/nginx-X.Y.Z`か`build_dynamic/`という、別のビルドのディレクトリを使います。そのディレクトリにそのファイルが無ければ、そこでnginxをconfigureします。

valgrindの下でnginxを動かすには、環境変数`NGINX_RUNNER`に値を設定します。

```console
$ NGINX_RUNNER=valgrind sh test.sh
```

valgrindは、`test.sh`の最後にnginxが終了するときに、レポートを書きます。`test.sh`は、valgrindのエラーを自分の終了ステータスに含めません。`test.sh`が出力するのは、nginxの終了ステータスです。下のコマンドのように`--error-exitcode=99`を付けると、valgrindがエラーを数えたときの終了ステータスは99になります。CIと同じように実行を確かめるには、valgrindにCIのオプションを渡し、ログの`ERROR SUMMARY`の行を読んでください。詳しい説明は[CIのvalgrind](#ciのvalgrind)にあります。

```console
$ rm -rf build/valgrind && mkdir -p build/valgrind
$ NGINX_RUNNER="valgrind --error-exitcode=99 --leak-check=full --show-leak-kinds=definite,indirect,possible --errors-for-leak-kinds=definite,indirect --suppressions=$PWD/test/valgrind.supp --log-file=$PWD/build/valgrind/valgrind.%p.log" sh test.sh
$ grep 'ERROR SUMMARY' build/valgrind/valgrind.*.log
```

### nginxがlistenするまで待つ

`test.sh`は、テストのnginxを`$NGINX_RUNNER build/nginx/sbin/nginx &`でバックグラウンドで起動します。そして、nginxがTCPの接続を受け付けるようになってから、最初のリクエストを送ります。そのために、`test.sh`は`test/t/cases/_wait_for_listen.rb`をCRubyで2回実行します。

- nginxを起動する前に、このスクリプトは、下に挙げるポートで接続を受け付けるプロセスが無くなるまで待ちます。別のプロセスがlistenするポートがあると、起動の後の待ちが、nginxがいなくても成功してしまいます。そのため、`NGINX_HEATTIME`秒の後もまだ接続を受け付けるポートがあると、実行は、そのポートを挙げて失敗します。

  ```text
  wait_for_listen: before nginx starts, 1 of 33 ports still accept connections after 60.05 seconds (limit 60.00): 18080; another process listens on them
  ```

- nginxを起動した後に、このスクリプトは、すべてのポートが1回ずつ接続を受け付けるまで、0.1秒ごとに各ポートへ接続します。そして、かかった時間を出力します。時間は、nginxを起動した直後のスクリプトの開始から数えます。

  ```text
  wait_for_listen: nginx (pid 1234) accepted connections on all 33 ports after 0.21 seconds (limit 60.00)
  ```

  nginxのプロセスが先に終わったときと、`NGINX_HEATTIME`秒が過ぎたときは、スクリプトは失敗し、まだ接続を拒んだポートを挙げます。

  ```text
  wait_for_listen: nginx (pid 1234) ended after 0.47 seconds, before it accepted connections on 33 of 33 ports: 18080, 18081, ...; see its output above and logs/error.log
  wait_for_listen: nginx (pid 1234) did not accept connections within 60.00 seconds (NGINX_HEATTIME) on 33 of 33 ports: 18080, 18081, ...
  ```

対象のポートは、`http {}`のサーバーのポートです。具体的には、下の「ポート」で説明するコピーの`test/conf/nginx.conf`と`test/conf/conf.d/*.conf`にある、すべての`listen`ディレクティブのポートを、`TEST_SH_PORT_OFFSET`でずらしたものです。2026年10月30日の時点で、`next`には57個あります。nginxは、設定をすべて読んだ後に、listenするソケットをすべて1つのループで開きます。このループは`ngx_open_listening_sockets()`です。そのため、1つのポートが開いていれば、ほとんどの場合、ほかのポートも開いています。それでも、1つのポートにかかるのは1回の接続で、1ミリ秒を大きく下回ります。すべてのポートを調べると、最初のソケットと最後のソケットの間に隙間が残りません。また、インストールした設定に届かなかった`conf.d`のフラグメントも見つけられます。`test/conf/nginx.stream.conf`と`test/conf/conf.d/stream/`にある、`stream {}`のポートは対象から外します。streamのサーバーに接続すると、そのサーバーのセッションのコードが動くからです。たとえば、12352のサーバーの`Nginx::Stream::Async.sleep 3000`が動きます。そして、ケースは、そのコードが`error.log`に書くものを読みます。nginxは、streamのソケットを同じループで、`http {}`のソケットの直後に開きます。また、streamのポートに接続する最初のテストは、`test/t/ngx_mruby.rb`の多くのHTTPのテストが通った後に動きます。`Nginx::Server#add_listener`と`Nginx::Stream.add_listener`が加えるポートも、同じループで開きます。これらのポートは調べません。

`NGINX_HEATTIME`は、2つの待ちのそれぞれの上限で、単位は秒です。デフォルトは60で、CIはこの変数を設定しません。`NGINX_RUNNER=valgrind NGINX_HEATTIME=10 sh test.sh`のように設定したコマンドは、最大でその秒数まで待ちます。nginxがlistenすると、実行はすぐに先へ進みます。10秒で失敗するのは、そのときまでにnginxがlistenしていない場合だけです。その場合、その時点で最初のリクエストを送っていたら、そのリクエストは拒否され、`Errno::ECONNREFUSED`になっていたはずです。

デフォルトの値は、次の測定に基づきます。2026年10月19日に、`master`の03aad7031からビルドしたテストのnginxを、`test.sh`と同じ方法で起動しました。nginxは1.31.6で、ngx_mrubyは静的なモジュールです。環境は、Ubuntu 22.04のコンテナです。コンテナを動かしたaarch64のホストにはCPUが11個あり、ほかのビルドのためにロードアベレージが約15でした。そして、上のスクリプトを使って、すべてのポートが接続を受け付けるまでの時間を測りました。

- `NGINX_RUNNER=exec`で10回起動すると、各回0.10から0.11秒でした。つまり、すべてのポートが、2巡目の試行で接続を受け付けました。スクリプトは0.1秒ごとに接続を試します。
- `NGINX_RUNNER=valgrind`で5回起動すると、2.27から2.61秒でした。valgrindは3.18.1です。

CIでは、valgrindの下のセルが、起動から10秒たってもまだ設定を読んでいました。そのセルは、x86_64のランナーでnginx 1.28.3を動かしていました。`test.sh`がSIGTERMを送ったときのvalgrindのレポートでは、nginxは`ngx_conf_parse()`の中にいました。[その実行](https://github.com/matsumotory/ngx_mruby/actions/runs/37181065564)の報告は、[#564](https://github.com/matsumotory/ngx_mruby/pull/564#issuecomment-5977252444)にあります。この時間は、次のときに長くなります。CIのランナーの負荷が高いとき、valgrindの下で動かすとき、sanitizerのビルドを使うとき、読む設定が多いときです。valgrindの下では、ここではvalgrindなしの20倍を超える時間がかかりました。sanitizerのビルドの時間は、ここでは測っていません。60秒は、そのCIの実行で見た10秒の6倍で、上のvalgrindの下でいちばん遅かった起動の約23倍です。

上限があると、次のような競合が起きることがあります。

- 起動が上限より遅いと、nginxがいずれ起動するはずでも、実行は失敗します。遅い環境では、`NGINX_HEATTIME`を上げてください。待ちはnginxがlistenした時点で終わるので、上限を上げて時間が余計にかかるのは、nginxが終了せずにハングしたときだけです。nginxが終了したときは、スクリプトがすぐに報告します。
- listenしているソケットは、まだ動いているハンドラではありません。nginxがlistenすると、カーネルはすぐに接続を受け付けます。テストのnginxは`master_process off`の1つのプロセスで、どの接続を読むよりも前に、`init_worker`のフックを実行します。その間、最初のリクエストは、nginxが読むまでソケットのbacklogで待ちます。テストのクライアントのmruby-simplehttpはタイムアウトなしで読むので、クライアントも同じく待ちます。
- nginxは後で、スクリプトが待つ間に試した接続を1つずつ読みます。そして、接続がリクエストの無いまま閉じられていると分かると、その接続を閉じます。これらの接続ではハンドラは動きません。nginxは、これらの接続について、`error.log`に`debug`の行だけを書きます。

### nginxを止める

`test.sh`は、自分が起動したnginxのプロセスだけを、そのpidで止めます。`test.sh`は、`killall`や`pkill`のようにプロセスの名前でシグナルを送りません。そのため、ほかのチェックアウト、ソークテスト、nginx-tests、ほかのユーザーのnginxのプロセスは動き続けます。1台のマシンで`test.sh`を2つ実行するには、別々のポートが要ります。説明は下の「ポート」にあります。同じポートを使うと、上の「nginxがlistenするまで待つ」にあるように、2つ目の実行は起動の前の待ちで失敗します。

- `test.sh`は終了するときに、テストのnginxにSIGTERMを送って止め、そのプロセスが終わるまで待ちます。終了するのは、最後のケースの後、失敗の後、SIGHUP、SIGINT、SIGTERMを受けたときです。その後、`test.sh`は、止めるのにかかった時間と、nginxの終了ステータスを出力します。nginxの終了ステータスは、`test.sh`の終了ステータスを変えません。

  ```text
  test.sh: nginx (pid 374) ended within about 0.1 seconds of the first SIGTERM; SIGTERM sent 1 times
  test.sh: nginx (pid 374) exit status 0
  ```

  シェルは、シグナルのtrapを、そのとき動いているコマンドが終わった後にだけ実行します。そのコマンドは、nginxを待つ処理、`test/t/ngx_mruby.rb`、実行中のケースのファイルなどです。そのため、nginxを止める処理は、そのコマンドが終わったときに始まります。また、対話的でないシェルは、`&`で実行するコマンドを、SIGINTを無視する状態で起動します。そのため、`sh test.sh &`はSIGINTでは止まりません。代わりにSIGTERMを送ってください。

- `test.sh`は、シグナルを送る前に毎回、そのpidがまだこのチェックアウトの`build/nginx/sbin/nginx`を動かしているかを確かめます。`ps -ww -o args=`で読んだそのpidのコマンドラインにその絶対パスが含まれていれば、`test.sh`は、そのpidがnginxを動かしていると判断します。valgrindの下でも同じです。シェルは、終わったバックグラウンドのプロセスを回収します。そのため、nginxがクラッシュした後は、止める時点で、そのpidが別のプロセスのものになっていることがあります。`test.sh`は、そのようなpidを終わったプロセスとして扱い、シグナルを送りません。

  ```text
  test.sh: nginx (pid 374) had ended before the stop; no signal sent
  ```

- `test.sh`は、nginxを起動する前に`build/nginx/logs/nginx.pid`を読みます。`BUILD_DYNAMIC_MODULE`では、このファイルは`build_dynamic/...`にあります。前の実行がnginxを止める前にkillされると、そのnginxは動き続けます。このファイルは、そのnginxのpidを持っています。上の確認で、そのプロセスがこのチェックアウトの`build/nginx/sbin/nginx`を動かしていれば、`test.sh`は同じ方法でそのプロセスを止めます。ほかのプロセスには触れません。

  ```text
  test.sh: stopping the nginx (pid 7) that an earlier run left running
  test.sh: logs/nginx.pid names pid 7, which does not run /path/to/build/nginx/sbin/nginx; left running
  ```

テストのnginxは`master_process off`の1つのプロセスです。このプロセスは、`ngx_single_process_cycle()`のループで、イベントを処理した後にだけシグナルを調べます。シグナルハンドラが`ngx_terminate`を設定し、ループは`ngx_process_events_and_timers()`が戻った時点で終わります。シグナルを調べた後、次の`epoll_wait()`の前にSIGTERMが届くと、そのSIGTERMは待ちを中断しません。タイマーも接続も無いと、`epoll_wait()`は時間の制限なしに待ちます。そのときnginxは、`signal 15 (SIGTERM) received`をログに書き、動き続けます。マスタープロセスには、この隙間がありません。マスタープロセスは、`sigsuspend()`でシグナルを待ちます。SIGTERMの後もワーカーがまだ動いていると、マスタープロセスは、終了のコマンドをワーカーに送り直します。送り先は各ワーカーのソケットペアで、ワーカーのイベントループがこのソケットペアを監視しています。この書き込みに失敗したときだけ、マスタープロセスはSIGTERMを送ります。送り直す間隔は50ミリ秒から始まって2倍ずつ延び、間隔が1秒を超えると、マスタープロセスはSIGKILLを送ります。SIGKILLを送るのは、最初のシグナルから約1.6秒後です。この処理は`ngx_master_process_cycle()`にあります。`test.sh`は、1つのプロセスのnginxにシグナルを送り直して、マスタープロセスと同じように止めます。プロセスがまだ動いていれば、`test.sh`は、最初のSIGTERMの1、3、7、15、31秒後にSIGTERMを送り直します。`epoll_wait()`の間にSIGTERMが届くと、待ちは終わります。`test.sh`がSIGKILLまでマスタープロセスより長く待つのは、テストのnginxがvalgrindの下で動くことがあるからです。valgrindは終了時にリークを調べるので、SIGKILLを送ると、そのレポートが失われます。`NGINX_STOPTIME`秒の後に、`test.sh`はSIGKILLを送ります。`NGINX_STOPTIME`のデフォルトは60です。そして、`test.sh`は次の行を出力します。

```text
test.sh: nginx (pid 374) did not end within 60 seconds (NGINX_STOPTIME) after 6 SIGTERM; sent SIGKILL
```

その後、`test.sh`は終了ステータス1で終了します。`test.sh`は、これらの時間を、`sleep 0.1`と`ps`の繰り返しで数えます。そのため、実際の時間は、出力する時間より少し長くなります。`test/t/cases/_second_instance.rb`の2つ目のnginxも1つのプロセスで、このnginxはSIGQUITで止め、シグナルを同じように送り直します。

実行がこの隙間に当たる頻度を、2026年10月29日に測りました。テストのnginxは、`next`の`c9c49023e`からビルドしました。nginxは1.31.6で、ngx_mrubyは静的なモジュールです。このnginxを、`test.sh`と同じ方法で起動しました。環境は、CPUが11個あるaarch64のホストで動かした、Ubuntu 22.04のコンテナの中でした。

- テストのnginxを800回起動し、それぞれに1回SIGTERMを送りました。400回は、1つのリクエストにレスポンスが返った直後に送りました。残りの400回は、3つのリクエストを送ってから0から20ミリ秒後に送りました。nginxは毎回、1回のSIGTERMで終わりました。隙間は、`ngx_terminate`の確認から`epoll_wait()`の呼び出しまでです。その間にあるのは、デバッグのログを1行書く処理と、タイマーのツリーを検索する処理だけです。そのため、この規模のループでは、隙間に当たりません。
- gdbをテストのnginxにアタッチし、nginxがリクエストの接続を閉じるまで待ちました。そして、次の`ngx_epoll_process_events()`の呼び出しでnginxを止め、そこでSIGTERMを届けました。そのとき、イベントもタイマーも残っていませんでした。その呼び出しは`timer=-1`でした。nginxは`signal 15 (SIGTERM) received from ..., exiting`をログに書き、続けて`epoll timer: -1`を書きました。そして、10秒後もまだ動いていました。2回目のSIGTERMで、nginxは0.1秒以内に終わりました。これは、[#600](https://github.com/matsumotory/ngx_mruby/pull/600)の`7926f72`で`test.sh`を実行したときと同じ状態です。その実行では、nginxはSIGTERMをログに書き、20分間`epoll_wait()`の中に留まりました。

### ポート

スイートのポートは、12345から12399までと、18080から18199までの数です。次のポートがこれにあたります。

- `test/conf/`にある`listen`ディレクティブのポート
- `add_listener`に渡すアドレスのポート
- `test/t/cases/_second_instance.rb`が起動する2つ目のnginxが使う、18116と12357
- `test/t/cases/config_hooks.rb`が起動するnginxが使う18158
- `test/t/cases/_agent_proxy_client.rb`が動かすLLMのモックのupstreamが使う、12372と12373
- `test/t/ngx_mruby.rb`にあるstreamだけのテストが使う12399
- テストと、`test/html/`にあるフックのスクリプトと期待する出力が挙げるポート

`TEST_SH_PORT_OFFSET`は整数で、デフォルトは0です。この変数を設定すると、これらのポートがすべて同じ数だけずれます。そのため、2つのチェックアウトが、それぞれ別のオフセットで、1台のマシンで同時に`test.sh`を実行できます。

```console
$ TEST_SH_PORT_OFFSET=1000 sh test.sh    # 13345 to 13399 and 19080 to 19199
```

`test.sh`は、設定をインストールする前に`test/t/cases/_stage.rb`を実行します。このスクリプトは、`test/t`、`test/conf`、`test/html`、`test/soak/mock_llm.rb`、`test/soak/http_client.rb`を`build/nginx/harness/test/`にコピーします。`BUILD_DYNAMIC_MODULE`では、コピー先は`build_dynamic/...`です。コピーにあるすべてのテキストファイルで、2つの範囲の数は、その数にオフセットを足した数になります。対象は5桁で書いた数で、その隣に数字、英字、`_`が無いものです。

```text
stage: copied 164 files to /path/to/build/nginx/harness/test; 593 port numbers moved by 1000
```

その後、`test.sh`は、コピーから設定とフックのスクリプトをインストールし、コピーのポートを待ちます。そして、コピーの`test/t/ngx_mruby.rb`とケースのファイルを実行します。テストは、`suite_path`を使って、コピーのCRubyのヘルパーを実行します。`suite_path`は`test/t/cases/_prelude.rb`にあり、`test/t/ngx_mruby.rb`にも自分で使う`suite_path`があります。`suite_path`は、スイートのパスを`TEST_SH_STAGE_DIR`につなげます。`TEST_SH_STAGE_DIR`は、`test.sh`が設定するディレクトリです。ケースを`test.sh`の外で実行するときのように、この変数が無いと、`suite_path`はチェックアウトのパスを返します。テストは今も、チェックアウトの最上位から実行します。設定が、フックのスクリプトを、最上位からの相対パスの`build/nginx/html/<name>.rb`で指すからです。オフセットが0なら、コピーは元のファイルと同じです。

ポートをずらす規則はテキストの置き換えなので、新しいテストでは、次のことを守ってください。

- ポートは、2つの範囲のどちらかの5桁の数で書いてください。また、これらの範囲の数は、ポートか、テストが同じファイルの集まりにある数と比べる値にだけ使ってください。このような数を`18_132`のように`_`を入れて書くと、置き換えの規則では見つからないので、`_stage.rb`はファイルと行を挙げて失敗します。計算で作るポートは、その5桁の部分が範囲にあるときだけずれます。オフセットが1000なら、`18110 + 1`は`19110 + 1`になります。一方、`18000 + 110`と、文字列から作るポートはそのままです。ポートの数をそのまま書いてください。
- 範囲の中の数で、ポートでないものが1つあります。`test/conf/conf.d/20-filter-connection.conf`は`f.output 12345`を出力し、`test/t/cases/filter_connection.rb`は、ボディを`'12345'`と、その長さを`'5'`と比べます。両方のファイルが同じようにずれるので、このケースは今も、`Filter#output`がIntegerを`to_s`で5バイトに変換することを確かめます。
- オフセットは、すべてのポートを10000から65535の間に保ち、すべての数を5桁のままにする値にしてください。そのようなオフセットは-2345から47336までで、それ以外のオフセットでは`_stage.rb`が失敗します。また、オフセットは、ポートをほかの実行のポートから離しておく値にしてください。ソークテストのポートは12360から12362で、`SOAK_PORT_BASE`で決まります。性能の比較のポートは12370から12372で、`PERF_PORT_BASE`で決まります。nginx-testsのポートは8000から8999です。オフセットが0だと、`test.sh`と性能の比較は、どちらも12372を使います。

2つの実行には、2つのオフセットのほかに、2つのチェックアウトが要ります。1つのビルドのディレクトリには、1つのテストのnginxと、そのログと、そのスイートのコピーが入るからです。2つのオフセットは、2つの実行の範囲を離しておく必要があります。18080から18199の範囲には120個の数があるので、オフセットの差は120以上にします。オフセットの差が5681から5854のとき、一方の実行の12345から12399の範囲は、もう一方の実行の18080から18199の範囲に重なります。差の符号は問いません。5681は18080 - 12399で、5854は18199 - 12345です。そのため、差はこの区間に入らないようにします。オフセットが14568を超えると、18080から18199のポートは、Linuxがデフォルトでエフェメラルポートに使う範囲に入ります。14568は32767 - 18199で、その範囲は32768から60999です。その範囲では、nginxがbindする前に、クライアントのソケットがそのポートを取ることがあります。例のオフセットの0と1000は、3つの条件をすべて満たします。

### CIのvalgrind

`.github/workflows/test.yml`の`build`のマトリクスは、各セルで`test.sh`を実行します。どのセルがvalgrindの下でnginxを動かすかは、実行の種類によって違います。

- `build`マトリクスを実行する場合、全セルを動かす場合も標準の4セルだけの場合も、1つのセルがvalgrindの下でnginxを動かします。[実行するジョブの選択](#実行するジョブの選択)を参照してください。そのセルは、ngx_mrubyを静的なモジュールとして組み込んだnginx 1.31.8を、`--with-openssl-src`なしでビルドします。全マトリクスでは、このセルのジョブの名前は`build (1.31.8)`です。マトリクスは、このセルに`VALGRIND_ON_EVERY_RUN`を与えます。sanitizerを使わないほかのセルは、`NGINX_RUNNER=exec`でnginxを直接動かします。sanitizerのセルは、AddressSanitizerとUndefinedBehaviorSanitizerを付けてビルドしたnginxを動かします。説明は次の節にあります。
- `test.yml`を入力`valgrind`を付けて手動で実行すると、sanitizerのセルを除くすべてのセルが、valgrindでnginxを動かします。

  ```console
  $ gh workflow run test.yml --ref next -f valgrind=true
  ```

- 夜間の実行：`.github/workflows/valgrind-nightly.yml`が毎日18:23 UTC、日本時間03:23に`test.yml`を起動し、終了を待って、その実行が失敗したら失敗します。GitHubの定期実行はデフォルトブランチのファイルから動くため、#674で入った`master`のファイルが`master`と`next`の実行を起動します。PRでは起動しません。`test.yml`か`test/valgrind.supp`を変えるPRは、PR自身の実行で、valgrindのセルを1つ動かします。すべてのセルをvalgrindの下で動かすには、次の夜間の実行を待つか、そのブランチで`valgrind-nightly.yml`か、`valgrind`入力を付けた`test.yml`を「Run workflow」で実行します。この実行は必須チェックの`ci-ok`を出さず、ジョブの名前は`ci-ok (valgrind)`です。[実行するジョブの選択](#実行するジョブの選択)を参照してください。

valgrindを使っても、セルの時間はあまり増えません。入力`valgrind`を付けた実行[40824932917](https://github.com/matsumotory/ngx_mruby/actions/runs/40824932917)では、valgrindの下の16のセルで、`test.sh`のうちnginxの起動から`test.sh ... successful`までの部分に、67から94秒かかりました。同じコミットのプルリクエストの実行[40824899601](https://github.com/matsumotory/ngx_mruby/actions/runs/40824899601)では、nginxを直接動かした15のセルで57から75秒でした。どちらも2026年10月29日の実行です。1つのセルは全体で4から13分かかり、その大部分はOpenSSL、mruby、nginxのビルドの時間です。

valgrindの下のセルは、次のオプションでnginxを動かします。

```text
valgrind --error-exitcode=99 --leak-check=full --show-leak-kinds=definite,indirect,possible --errors-for-leak-kinds=definite,indirect --suppressions=test/valgrind.supp --log-file=$RUNNER_TEMP/valgrind/valgrind.%p.log
```

valgrindは、起きたメモリのエラー1つごとに、エラーを1つ数えます。メモリのエラーは、不正な読み込みか書き込み、初期化していない値による条件分岐かシステムコール、不正な解放か対応しない解放です。また、valgrindは、種類が`definite`か`indirect`のloss recordのうち、`test/valgrind.supp`がsuppressしないもの1つごとに、エラーを1つ数えます。nginxが終了するとき、valgrindは、エラーの数と、異なるスタックの数を、`ERROR SUMMARY`の行に出力します。valgrindは、異なるスタックをcontextsと呼びます。たとえば、20のリクエストが動かしたハンドラで不正な読み込みがあると、この行は`20 errors from 1 contexts`になります。`--error-exitcode=99`を付けると、エラーの数が0でないとき、valgrindは99で終了します。`test.sh`は、nginxを止めたときに、nginxの終了ステータスを出力します。valgrindがエラーを数えた後は、`test.sh: nginx (pid 374) exit status 99`です。説明は[nginxを止める](#nginxを止める)にあります。しかし、`test.sh`は、この終了ステータスを自分の終了ステータスに含めません。そのため、ステップ「Check the valgrind reports」は、代わりにログを読みます。このステップは各ログを出力します。そして、少なくとも1つのログに`ERROR SUMMARY`があり、すべての`ERROR SUMMARY`でエラーの数が0のときだけ通ります。それ以外では失敗します。`ERROR SUMMARY`が1つも無いセルも失敗します。そのセルでは、valgrindがレポートを書き終えていません。

possibly lostのブロックは、スタックとともに出力されますが、エラーにはなりません。`master_process off`のテストのnginxが終了する時点で、nginxはcycleのプールを破棄しています。残るのは、`ngx_event_process_init()`が確保した接続とイベントの配列、`ngx_crc32_table_init()`のテーブル、まだ開いている接続のプールです。valgrindは、これらのブロックの途中を指すポインタしか見つけないので、これらをpossibly lostとして報告します。その数は、nginxが終了するときに開いている接続によって変わります。2026年10月29日のCIの実行[40819115837](https://github.com/matsumotory/ngx_mruby/actions/runs/40819115837)、[40820233191](https://github.com/matsumotory/ngx_mruby/actions/runs/40820233191)、[40821209339](https://github.com/matsumotory/ngx_mruby/actions/runs/40821209339)では、valgrindの下の16のセルが、それぞれ5ブロックの85,440バイトから8ブロックの86,208バイトまでを報告しました。ngx_mrubyを静的なモジュールとして組み込んだnginx 1.31.6のセルは、この3つの実行で、5、7、7ブロックを報告しました。ngx_mruby、mruby、gemのどれかがブロックを指す最後のポインタを失うと、そのリークはdefinitely lostになります。そのため、そのセルは失敗します。ngx_mrubyがfinalizeしないリクエストや接続は、nginxが終了するまで、そのプールを持ち続けます。valgrindはそのプールをpossibly lostとして報告するので、そのセルは失敗しません。実行40824899601では、終了時にまだ開いていたupstreamの接続のプールが、possibly lostでした。そのプールを確保したときのスタックには、`ngx_mrb_post_fiber`があります。このようなリークを調べるのは`soak`ジョブです。このジョブは、ワーカーの接続、タイマー、ファイルディスクリプタを、サンプルの間で比べます。説明は[メモリのソークテスト](#メモリのソークテスト)にあります。

`test/valgrind.supp`がsuppressするのは、nginx自身の確保だけです。各エントリーには、スタックと、コメントに書いた理由があります。今あるエントリーは、`ngx_set_environment()`の環境変数の配列だけです。この配列は8バイトで、どのセルでもdefinitely lostになります。nginxは、終了時にこの配列をわざと確保したまま残します。この処理は`nginx.c`の`ngx_cleanup_environment()`にあります。エントリーを加えるのは、レポートのスタックと、そのブロックがngx_mrubyのものでない理由があるときだけです。ngx_mruby、mruby、gemのフレームを持つリークは、suppressしません。

## 2つのsanitizerの下でテストを実行する

CIは、マトリクスのセルの1つを、AddressSanitizerとUndefinedBehaviorSanitizerを有効にする`-fsanitize=address,undefined`でビルドします。同じビルドを手元で実行するには、Linuxでgccかclangを使い、次のようにします。

```console
$ sudo sysctl -w vm.mmap_rnd_bits=28     # ASan and the kernel's high-entropy ASLR do not mix
$ export NGINX_EXTRA_CC_OPT="-fsanitize=address,undefined -fno-omit-frame-pointer"
$ export NGINX_EXTRA_LD_OPT="-fsanitize=address,undefined"
$ export NGX_MRUBY_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
$ export NGX_MRUBY_LDFLAGS="-fsanitize=address,undefined"
$ export ASAN_OPTIONS="detect_leaks=1"
$ export LSAN_OPTIONS="suppressions=$PWD/test/lsan.supp"
$ export UBSAN_OPTIONS="print_stacktrace=1:suppressions=$PWD/test/ubsan.supp"
$ NGINX_RUNNER=exec sh test.sh
$ grep -HnE 'ERROR: (AddressSanitizer|LeakSanitizer)|runtime error:|SUMMARY: (AddressSanitizer|UndefinedBehaviorSanitizer)' $(find build/nginx/logs $(ls -d build/nginx/second_instance 2>/dev/null) -type f -name '*.log')
```

最後の行は、CIのそのセルにあるステップ「Check for sanitizer reports」が読むファイルを、同じパターンで読みます。このステップは、パターンに一致する行があると失敗します。レポートは、それを書いたプロセスのstderrに出ます。そのstderrは、次のファイルのうちのどれかです。

| ファイル | 誰のstderrか |
|---|---|
| `build/nginx/logs/error.log` | テストのnginxが、ログを開いた後に出すstderr。終了時のリークのレポートも含む |
| `build/nginx/logs/stderr.log` | テストのクライアントのstderr。クライアントは`test/t/ngx_mruby.rb`とケースのファイルで、`test.sh`がそのstderrをこのファイルへリダイレクトする。そのため、テストがstderrをリダイレクトせずに起動するプロセスのstderrも、ここに入る。そのプロセスは、`nginx -t`、streamだけのテストの`nginx -s quit`、ログを開く前のnginxである |
| ほかの`build/nginx/logs/*.log` | テストが専用のログを持たせて起動するnginxのプロセスが、そのログを開いた後に出すstderr。streamだけのテストの`stream_only.error.log`がこれにあたる。このテストは、nginxを`daemon on`で実行するため |
| `build/nginx/second_instance/<mode>/*.log` | `test/t/cases/_second_instance.rb`が起動する2つ目のnginx。ファイルは`error.log`、`stderr.log`、`stdout.log` |

`test.sh`がケースのファイルより前で止まったときは、`build/nginx/second_instance/`がありません。そのときステップは、ほかのファイルを読み、このディレクトリが無いことを出力します。このステップは、`*.log.bak`のファイルを読みません。`test.sh`は、前の実行のログを、同じディレクトリのこれらのファイルに残します。テストのnginxが`error.log`を開く前に出したレポートは、次の段落にあるように、端末に出ます。CIでは、`script`のステップの出力に出ます。

`NGINX_EXTRA_CC_OPT`と`NGINX_EXTRA_LD_OPT`は、nginxの`--with-cc-opt`と`--with-ld-opt`の後ろに足されます。`NGX_MRUBY_CFLAGS`と`NGX_MRUBY_LDFLAGS`は、mrubyのビルドに渡ります。sanitizerとvalgrindを一緒に使わないでください。nginxは、設定を読み込んだ後に、stderrを`error.log`へ送ります。そのため、nginxが設定をパースする間に動くコードのレポートは、`error.log`でなく端末に出ます。そのようなコードは、ディレクティブのハンドラ、スクリプトのコンパイル、`mruby_init_code`です。両方を読んでください。`test/ubsan.supp`には、nginx自身から出るレポートが、それぞれの理由とともに挙げてあります。`test/lsan.supp`には、LeakSanitizerについて同じものが挙げてあります。nginxは、`cycle->connections`と、`ngx_event_process_init`で確保する2つのイベントの配列を解放しません。終了時にLeakSanitizerがこれらをレポートするかどうかは、これらの外にまだこれらを指すものがあるかどうかで決まります。そのため、抑制が無いと、nginx自身が確保したメモリのために実行が失敗することがあります。CIが使うgcc 11のランタイムでは、抑制したブロックはほかのものを隠しません。LLVMのランタイムとgcc 12以降は、抑制したブロックをルートとしても扱います。そのため、これらのランタイムでは、この2つの配列からしかたどれないブロックもレポートされなくなります。

## nginx自身のテストスイートnginx-tests

`sh test/nginx-tests/run.sh`は、nginx自身のテストスイートである[nginx-tests](https://github.com/nginx/nginx-tests)を`prove`で実行し、結果を比べます。実行の対象は、`nginx_version`が指定するバージョンのnginxを、次の2とおりの方法でビルドしたものです。

- ngx_mrubyを入れたnginx：`test.sh`が`TEST_SH_SKIP_TESTS=1`でビルドします。静的なモジュールで、`test.sh`のconfigureのオプションと`-DMRB_GC_STRESS`を使い、`build/nginx`にインストールします。`test.sh`のオプションは[テストを実行する](#テストを実行する)にあります。`TEST_SH_SKIP_TESTS=1`を付けると、`test.sh`はインストールの後で止まります。テストの設定を書かず、nginxをkillせず、nginxを起動もしません。`run.sh`は`BUILD_DYNAMIC_MODULE`をunsetします。この変数があると、`test.sh`は代わりに`build_dynamic/`へビルドするからです。
- ngx_mrubyを入れないnginx：同じnginxのソースを`build_nginxtests/plain/src`にコピーし、`test.sh`がnginxに渡したオプションでconfigureします。そのオプションは、生成した`Makefile`の`NGX_CONFIG_OPT`です。ただし、`Makefile`が足す2つの`--add-module`のオプションは除きます。2つは、ngx_mrubyのオプションとngx_devel_kitのオプションです。サマリーにある`nginx -V`の`configure arguments`の行が、両方のビルドのオプションを示します。

テストファイルは、それぞれ自分のnginxの設定を書きます。mrubyのディレクティブを持つ設定はありません。ngx_mrubyを入れたビルドでは、nginxを起動するたびとリロードするたびに、ngx_mrubyの`mrb_state`ができます。nginxは、設定を読む間に、`http {}`ブロックと`stream {}`ブロックのそれぞれにこの`mrb_state`を作ります。`mrb_state`を作るのは`mrb_open`で、`MRB_GC_STRESS`の下で動きます。`mrb_open`は、mrubyのコアと同梱のgemに含まれるRubyのコードを実行します。ngx_mrubyは、post-read、server rewrite、rewrite、access、logのフェーズにハンドラを加えます。各HTTPリクエストは、そのうちリクエストが到達したフェーズのハンドラを通ります。`return`や`rewrite`は、後のフェーズより前にリクエストを終えることがあります。リクエストは、contentのフェーズのngx_mrubyのハンドラも通ります。ただし、locationが自分のcontentハンドラを持つときは通りません。`proxy_pass`などがそのようなハンドラで、nginxは、そのフェーズのハンドラの代わりにそれを実行します。コードを設定していないとき、これらのハンドラはdeclineします。各streamのセッションは、ngx_mrubyのaccessのフェーズのハンドラを通ります。ngx_mrubyのヘッダフィルタとボディフィルタは、ディレクティブが求めたときにだけ加わります。また、設定に書くハンドラ、フィルタ、initのコードは、1つも動きません。そのため、ngx_mrubyを入れると失敗し、入れないと通るテストファイルは、何も設定していなくてもこのモジュールがnginxの挙動を変えることを示しています。

### 固定したnginx-testsのコミット

nginx-testsには、リリースもタグもありません。`run.sh`は、`NGINX_TESTS_COMMIT`のコミット`ec44bc80c4bf`をfetchします。これは2026年10月19日の`master`の先頭のコミットで、コミットした日は2026年10月16日です。こうすると、nginx-testsにテストが加わっても、結果が変わるのは、このリポジトリを変えたときだけになります。固定したコミットは、そのためだけのプルリクエストで動かします。そのプルリクエストは、動かす前と後のサマリーを引用します。`nginx_version`を変えたときは、固定したコミットを動かす理由になります。nginx-testsの新しいテストファイルは、新しいバージョンのnginxの機能をテストし、古いバージョンでは自分をスキップするからです。

### nginx-testsを実行する

`run.sh`には、Linuxと、root以外のユーザーと、`test.sh`が必要とするものが要ります。root以外のユーザーが要る理由は2つあります。テストファイルは、そのユーザーだけが読めるディレクトリに設定を書きます。また、rootが起動したnginxは、ワーカーを`nobody`で動かします。テストファイルが必要とするperlのモジュールやプログラムが無いとき、そのテストファイルは失敗でなくスキップになります。Ubuntu 22.04では、ジョブは次のものをインストールします。

```console
$ sudo apt-get install rake bison git gperf zlib1g-dev libpcre3-dev libssl-dev ruby \
    libio-socket-ssl-perl libnet-ssleay-perl libfcgi-perl libscgi-perl \
    libcache-memcached-perl libcache-memcached-fast-perl libprotocol-websocket-perl memcached
$ sh test/nginx-tests/self-test.sh
$ sh test/nginx-tests/run.sh
```

macOSでは、ツリーのコピーを同じパスにマウントしたLinuxのコンテナで実行します。

```sh
D=$HOME/ngx_mruby-nginx-tests   # any directory outside the checkout
rm -rf "$D" && mkdir -p "$D" && git archive HEAD | tar -x -C "$D"
docker run --rm -v "$D:$D" -w "$D" ubuntu:22.04 sh -c 'apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y build-essential perl rake ruby bison git gperf wget ca-certificates openssl zlib1g-dev libpcre3-dev libssl-dev libio-socket-ssl-perl libnet-ssleay-perl libfcgi-perl libscgi-perl libcache-memcached-perl libcache-memcached-fast-perl libprotocol-websocket-perl memcached >/dev/null && useradd -m nt && chown -R nt "$PWD" && su nt -c "NGX_MRUBY_COMMIT='"$(git rev-parse HEAD)"' sh test/nginx-tests/run.sh"'
```

テストファイルは、8000から8999のポートのうち自分がロックしたポートで、nginxを起動します。そのため、テストファイルは並列に動きます。並列の数は`NGINX_TESTS_JOBS`で決まり、デフォルトはCPUの数です。テストファイルは`test.sh`のポートを使いません。また、`test.sh`が止めるのは、自分が起動したnginxだけです。説明は上の「nginxを止める」にあります。

環境変数は次のとおりです。`NGINX_TESTS_OUT`は出力のディレクトリで、デフォルトは`build_nginxtests`です。`NGINX_TESTS_SRC`は、固定したコミットのnginx-testsのチェックアウトです。指定すると、`run.sh`はfetchの代わりにそれを使います。たとえば、github.comに接続できないときに使います。`NGINX_TESTS_JOBS`は並列の数です。`NGINX_TESTS_FILES`は、すべてのテストファイルの代わりに実行するテストファイルで、たとえば`NGINX_TESTS_FILES='access.t proxy.t'`と指定します。`NGX_MRUBY_COMMIT`は、サマリーに書くngx_mrubyのコミットです。デフォルトは、GitHub Actionsでは`GITHUB_SHA`で、それ以外ではチェックアウトの`HEAD`です。`run.sh`に足した引数は`test.sh`に渡り、そこから`./configure`に渡ります。nginx-tests自身の変数も使えます。失敗したファイルのエラーログを読むには、そのファイルだけを、`TEST_NGINX_LEAVE=1`か`TEST_NGINX_CATLOG=1`を付けて実行し直してください。`TEST_NGINX_LEAVE=1`は一時ディレクトリを残し、`TEST_NGINX_CATLOG=1`はログの内容を出力します。

`run.sh`は、次のファイルを`build_nginxtests/`に出力します。

| ファイル | 内容 |
|---|---|
| `summary.md` | 両方のビルドの件数、ビルドごとの失敗したファイル、スキップの理由、両方のビルドのconfigureの引数 |
| `only-mruby.txt`, `both.txt`, `only-plain.txt` | 失敗したテストファイルの一覧。順に、ngx_mrubyを入れたビルドでだけ失敗したもの、両方のビルドで失敗したもの、ngx_mrubyを入れないビルドでだけ失敗したもの |
| `mruby/`, `plain/` | ビルドごとの`prove.log`、`results.tsv`、`nginx-V.txt`。`prove.log`は`prove`の出力。`results.tsv`はテストファイルごとに1つのレコードを持ち、レコードはファイル、`passed`か`failed`か`skipped`、スキップの理由か失敗したサブテストの3つから成る |

`test/nginx-tests/results.pl`は`prove.log`を読みます。proveの「Test Summary Report」にあるファイルのエントリーに、失敗したサブテスト、0以外のwait status、パースのエラーのどれかがあると、そのファイルは失敗です。パースのエラーは、planが無いか、planが間違っている場合です。エントリーにあるのが、通ったTODOのサブテストだけなら、そのファイルは通ったことになります。ログがproveの完全な実行でないとき、`results.pl`は止まります。`test/nginx-tests/compare.pl`は、一覧とサマリーを書きます。`sh test/nginx-tests/self-test.sh`は、この2つのスクリプトを、`test/nginx-tests/self-test/`にある小さなテストファイルの`prove`の出力で確かめます。これらのテストファイルは、わざと通るか、失敗するか、スキップするか、planを壊します。その動きは2つのビルドで違い、組み合わせは、`self-test.sh`の先頭のテーブルにあります。

両方のビルドをテストし、その結果を読めたとき、`run.sh`は0で終わります。テストファイルが失敗したときも同じです。ビルド、fetch、`prove`自身のどれかが失敗したときと、ログが完全な実行でないときは、`run.sh`は0以外のステータスで終わります。

### CIで実行するnginx-tests

`.github/workflows/nginx-tests.yml`は、`ubuntu-22.04`でセルフテストと`run.sh`を実行します。このワークフローが動くのは、`next`へのPRがnginxのバイナリの入力、`test.sh`、`test/nginx-tests/`、ワークフローのどれかを変えるときと、「Run workflow」のときです。バイナリの入力は、性能の比較の[CIで実行する](#ciで実行する)に挙げてあります。Draftでは動かず、readyにすると始まります。`next`へのpushでは動きません。マージの記録には、PRのマージコミットでの実行を使うからです。ジョブのサマリーは`summary.md`で、ngx_mrubyを入れたビルドでだけ失敗するファイルには、warningのアノテーションが付きます。アーティファクト`nginx-tests`には、上の出力のうち、nginxのソースのコピーを除いたものが入ります。

このジョブは結果を記録します。ゲートにはなりません。ジョブが失敗するのは、セルフテスト、ビルド、fetch、`prove`自身のどれかが失敗したときと、`summary.md`が無いときだけです。テストファイルの結果では、ジョブは失敗しません。また、`ci-ok`はこのジョブを必要としません。詳しくは[必須のステータスチェック](#必須のステータスチェック)にあります。`docs/proposals/v3-plan.md`のPillar Eに従い、結果が安定したらこのジョブを必須にします。

### nginx-testsの結果

2026年10月19日に、2つのマシンで測りました。どちらのマシンでも、nginx-testsは`ec44bc80c4bf`で、nginx 1.31.6、gcc 11.4.0、OpenSSL 3.0.2、perl 5.34を使いました。

- CI：`ubuntu-22.04`で動いた[run 39241352263](https://github.com/matsumotory/ngx_mruby/actions/runs/39241352263)の`nginx-tests`ジョブです。x86_64で、テストファイルを4つずつ並列に実行しました。対象は、#602の`093e47d`を`7b5a0c4`の`next`へマージしたマージコミット`401cf56`です。
- macOSの上の`ubuntu:22.04`のDockerのコンテナ：aarch64で、テストファイルを11ずつ並列に実行しました。コマンドは[nginx-testsを実行する](#nginx-testsを実行する)のもので、対象は`093e47d`です。

| マシン | ビルド | テストファイル | 通った | 失敗した | スキップした | 実行したサブテスト |
|---|---|---|---|---|---|---|
| CI、x86_64 | ngx_mrubyを入れたnginx | 511 | 302 | 0 | 209 | 3994 |
| CI、x86_64 | ngx_mrubyを入れないnginx | 511 | 302 | 0 | 209 | 3994 |
| コンテナ、aarch64 | ngx_mrubyを入れたnginx | 511 | 301 | 0 | 210 | 3991 |
| コンテナ、aarch64 | ngx_mrubyを入れないnginx | 511 | 301 | 0 | 210 | 3991 |

- ngx_mrubyを入れると失敗し、入れないと通るテストファイルは、ngx_mrubyがnginxに入っているために失敗するファイルです。どちらのマシンでも、そのようなファイルはありませんでした。
- ngx_mrubyを入れないnginxでも失敗するテストファイルも、どちらのマシンでもありませんでした。

2つのマシンの結果は、`ssl_ktls.t`の1ファイルだけが違います。このファイルは、ランナーでは通り、コンテナではスキップになります。コンテナのカーネルにはkTLSが無く、スキップの理由は「no Linux KTLS」です。どちらのマシンでも、両方のビルドで同じファイルが、同じ理由でスキップになりました。ランナーでスキップになった209ファイルのうち189ファイルは、`test.sh`がビルドしないモジュールがnginxに無いために、スキップになりました。内訳は、`http_v2`が59ファイル、`stream_ssl`が25、`http_v3`が23、`mail`が16、`realip`が11、`sub`が9で、ほかの18のモジュールがそれぞれ1から6ファイルです。残りの20ファイルは、マシンかnginx-testsの条件で、スキップになりました。条件は次のとおりです。

- インストールしていないプログラムかperlのモジュール。`uwsgi`が4ファイルで、ほかに`GD`、`Win32API::File`、新しいバージョンの`IO::Socket::SSL`を要するファイルがあります
- OpenSSL 3.5
- root。3ファイルです
- ワイルドカードのアドレス。2ファイルです
- Windows。1ファイルです
- nginx-testsが`TEST_NGINX_UNSAFE`のときだけ実行するか、まったく実行しない6ファイル。孤立したプロセスグループ、長いテスト、OpenSSLのエンジンかプロバイダの鍵を使うものです

各実行のサマリーは、すべての理由をその件数とともに挙げます。ランナーでは、ジョブは約8分かかりました。2つのビルドに2分37秒、各ビルドの`prove`に2分37秒です。

この結果が確かめるのは、ngx_mrubyが入っていて、ngx_mrubyに何も設定していないnginxです。次の2種類の実行を加えると、もっと広い範囲を確かめられます。どちらもまだ用意していません。1つは、スキップしたファイルが必要とするモジュールを入れたビルドです。モジュールは、`--with-http_v2_module`、`--with-http_v3_module`、`--with-stream_ssl_module`、`--with-mail`と、上に挙げたほかのモジュールです。もう1つは、ngx_mrubyのハンドラかフィルタが、スイートのリクエストに対してRubyのコードを動かすテストの実行です。`docs/proposals/v3-plan.md`のPillar Eには、その手段として`TEST_NGINX_GLOBALS_HTTP`が書いてあります。`docs/HANDOFF.md`のキューには、両方が載っています。

## テストで使うLLMのモックのupstream

`test/soak/mock_llm.rb`は、HTTP/1.1のサーバです。`POST /v1/messages`にはAnthropic Messages APIと同じように答え、`POST /v1/responses`にはOpenAI Responses APIと同じように答えます。動かすにはCRuby 3.0以降が要ります。エージェントプロキシは、LLMのAPIの前に置いた、ngx_mrubyを入れたnginxです。このモックは、次の3つの場所で、エージェントプロキシのupstreamの代わりを務めます。

- メモリのソークテストの`agent_*`のシナリオと、性能の比較の`proxy_*`、`responses_stream_plain_*`、`auth`、`route_json_*`のシナリオ：ソークテストと性能の比較は、シナリオごとに、モックを別のプロセスとして、ポートのベース+2で起動します。ポートは12362と12372です。オプションはシナリオのもので、`test/soak/scenarios.rb`の`mock`にあります。
- ケースの`test/t/cases/agent_proxy.rb`：そのヘルパーの`test/t/cases/_agent_proxy_client.rb`は、リクエストを送る間、モックを自分のプロセスの中で12372と12373で動かします。ケースは、現在のビルドで動くエージェントプロキシのレシピを、`test/conf/conf.d/60-agent-proxy.conf`のサーバで確かめます。このサーバのポートは18132です。レシピは5つあります。1つ目はserver rewriteハンドラで、既知でないクライアントのキーを401で拒否し、serverのレベルの`error_page`がJSONのボディを付けます。そのリクエストはupstreamに届きません。2つ目はaccessハンドラで、JSONのボディの`model`で2つのupstreamブロックの1つを選び、クライアントの認証情報を差し替えます。3つ目は、クライアントのキーごとの`limit_conn`です。拒否は、`limit_conn_status 460`と`error_page`を通して、`retry-after`の付いたJSONの429になります。クライアントがストリームを閉じた後は、スロットがまた空きます。4つ目は、upstreamの529を変えずにクライアントへ渡すことです。5つ目は、`$upstream_status`を読むlogハンドラです。同じレシピは、`location = /v1/responses`でも、Responses APIのリクエストで動きます。そこでは、プロキシ自身が返す401と429のボディはResponses APIのエラーの形式を使い、upstreamのエラーは503と429です。ケースは、50個のデルタのストリームが1バイトも違わずに届くことも確かめます。確かめるストリームは、Messages APIのストリーム1つと、ストリームを終えるイベントの種類ごとのResponses APIのストリーム1つずつです。

```console
$ ruby test/soak/mock_llm.rb --port 12362 --events 50 --hold-after 10
```

| オプション | デフォルト | 意味 |
|---|---|---|
| `--port PORT` | 必須 | `127.0.0.1:PORT`で待ち受ける。ポートを増やすには、このオプションを繰り返す。どのポートも同じように答える |
| `--events N` | 50 | ストリームが持つ、テキストのデルタのイベントの数。Messages APIでは`content_block_delta`、Responses APIでは`response.output_text.delta` |
| `--delta-text TEXT` | `hello ` | テキストのデルタの各イベントが運ぶテキストの内容 |
| `--hold-after K` | 無効 | ストリームの最初のK個のイベントを書き、その後は相手が接続を閉じるまで何も書かずに待つ |
| `--reset-after K` | 無効 | ストリームの最初のK個のイベントを書き、その後に接続をRSTでリセットする |
| `--status CODE` | 無効 | すべてのリクエストに、イベントより前に、このステータスで答える。ボディには、そのAPIの形式のエラーを入れる。`/v1/messages`ではAnthropicのエラーで、529には`overloaded_error`、503には`api_error`。`/v1/responses`ではOpenAIのエラーで、429には`rate_limit_error`、503には`service_unavailable_error`、ほかの4xxには`invalid_request_error`、ほかの5xxには`server_error` |
| `--delay-ms MS` | 0 | 2つのイベントの間にMSミリ秒ずつ待つ |
| `--one-write` | 無効 | ステータス行とヘッダと、ストリームの全体を、1回のwriteで書く |
| `--terminal NAME` | `completed` | Responses APIのストリームを終えるイベント。`completed`、`incomplete`、`failed`のどれか |

リクエストは、ヘッダで、そのリクエストだけのオプションを上書きできます。ヘッダは、`x-mock-events`、`x-mock-hold-after`、`x-mock-reset-after`、`x-mock-status`、`x-mock-delay-ms`と、`x-mock-terminal`です。前の5つの値は0以上の数で、`x-mock-terminal`の値は`completed`、`incomplete`、`failed`のどれかです。`x-mock-hold-after`、`x-mock-reset-after`、`x-mock-status`は`off`も受け付けます。`off`は、それぞれ`--hold-after`、`--reset-after`、`--status`の動作を無効にします。`x-mock-events`と`x-mock-delay-ms`は`off`を受け付けません。それ以外の値には、そのヘッダの名前を書いた400で答えます。エラーは`invalid_request_error`です。nginxは、設定がヘッダを落とすとき以外は、これらのヘッダを転送します。`ruby test/soak/mock_llm_test.rb`は、これらの決まりと下に書く答えを、自分のプロセスの中のモックで確かめます。nginxは使わず、約1秒で終わります。`test/soak/run.sh`は、ソークテストの前に、これを実行します。

`POST /v1/messages`への答え方は次のとおりです。

- `"stream": true`を持つJSONのボディ：200で、`text/event-stream`とchunkedで答えます。イベントは、`usage`を持つ`message_start`、`content_block_start`、テキストを持つN個の`content_block_delta`、`content_block_stop`、`usage`を持つ`message_delta`、`message_stop`で、合わせてN + 5個です。
- それ以外のJSONのオブジェクト：メッセージをJSONにして、`Content-Length`を付けた200のレスポンスで答えます。

`POST /v1/responses`には、[openai/openai-openapi](https://github.com/openai/openai-openapi)の`openapi.yaml`にあるイベントの型とフィールドで答えます。読んだのはコミット`33248a6`のファイルで、日付は2026年10月19日です。

- `"stream": true`を持つJSONのボディ：200で、`text/event-stream`とchunkedで答えます。各イベントには、型を書いた`event:`の行と、`data:`の行があります。`data:`の行のJSONは、同じ`type`と、0から数える`sequence_number`を持ちます。イベントは、まず`response.created`と`response.in_progress`です。この2つは、ステータスが`in_progress`で`usage`がnullの`Response`オブジェクトを持ちます。続いて、`response.output_item.added`、`response.content_part.added`、テキストを持つN個の`response.output_text.delta`が来ます。ストリームを終えるイベントが`completed`か`incomplete`なら、その後に`response.output_text.done`、`response.content_part.done`、`response.output_item.done`と、`response.completed`か`response.incomplete`が続きます。この最後のイベントは、出力のテキストと`usage`を含む`Response`オブジェクトの全体を持ちます。`usage`のフィールドは、`input_tokens`、`input_tokens_details`、`output_tokens`、`output_tokens_details`、`total_tokens`です。イベントは合わせてN + 8個です。`failed`なら、デルタの後に`response.failed`が続きます。このイベントは、ステータスが`failed`で、`error`を持ち、`usage`がnullです。イベントは合わせてN + 5個です。
- それ以外のJSONのオブジェクト：`Response`オブジェクトをJSONにして200で答えます。ステータスは`completed`で、`Content-Length`を付けます。

どちらのパスでも、`--one-write`が無ければ、各イベントは1回のwriteで書く1つのチャンクです。ステータス行とヘッダは最初のイベントと一緒に書き、最後のチャンクは最後のイベントと一緒に書きます。JSONのオブジェクトでないボディには400で答え、レスポンスのボディには、そのAPIのエラーの形式で`invalid_request_error`を入れます。ほかのパスには、Anthropicの形式の404で答えます。`GET /_mock/stats`には、カウンタをJSONにして答えます。カウンタは下にあります。

答えは、リクエストとオプションだけで決まります。モデルは、リクエストの`model`です。`input_tokens`は、リクエストのボディのバイト数を4で割り、切り上げた数です。`output_tokens`はNで、ストリームを使わない答えでは6です。`Response`のidと時刻は固定です。`--delay-ms`のほかにsleepはありません。ドライバとケースは、同じコードで期待するレスポンスを計算し、1バイトずつ比べます。そのコードは`MockLLM.stream_body`と`MockLLM.answer_body`です。レスポンスには、答えたポートを示す`x-mock-port`も付きます。リクエストに認証情報のヘッダがあったときは、届いた値を`x-mock-authorization`と`x-mock-x-api-key`に入れて返します。そのため、テストは、プロキシがモックへどの認証情報を送ったのかを確かめられます。

モックは、アイドルのkeep-aliveの接続を自分から閉じません。モックが接続を閉じるのは、リクエストに`Connection: close`があるとき、相手が接続を閉じたとき、`--hold-after`と`--reset-after`のときだけです。`Connection: close`を持つリクエストには、答えにも`Connection: close`を付けます。`GET /_mock/stats`のカウンタは次のとおりです。

| カウンタ | 意味 |
|---|---|
| `connections_open` | いま開いている接続の数。尋ねている接続は数えない |
| `connections` | 受け付けた接続の数 |
| `requests` | 読んだ`POST /v1/messages`と`POST /v1/responses`のリクエストの数 |
| `completed` | 最後まで書いた答えの数。エラーのステータスで答えたものも含む |
| `held` | いま`--hold-after`で待たせているストリームの本数 |
| `held_closed` | `--hold-after`で待っている間に、相手が閉じたストリームの数 |
| `reset` | `--reset-after`でリセットした接続数 |
| `write_failed` | 相手が接続を閉じていたために、途中で切れた答えの数 |

## メモリのソークテスト

nginxのワーカーは、何日もリクエストを処理し続けます。終わったリクエストがワーカーに何かを残すと、それはワーカーが動いている間ずっと積み上がります。残るものには、GCのルート、生きているmrubyのオブジェクト、タイマー、ファイルディスクリプタ、接続、ヒープのメモリがあります。ソークテストは、シナリオごとに1つのlocationへ多数のリクエストを送り、これらのどれも増えないことを確かめます。CIは、このテストを、`soak`というジョブで実行します。

### 何を測るか

`test/soak/soak.rb`は、シナリオごとにnginxを起動します。設定は`master_process on`で、ワーカーは1つです。`soak.rb`は、まず1つのレスポンスを確かめ、`SOAK_WARMUP`個のリクエストを送ります。続いて、`SOAK_N`個のリクエストを、`SOAK_N / 3`個ずつ3つのウィンドウに分けて送ります。サンプルは、ウォームアップの後と各ウィンドウの後に1回ずつ、合わせて4回取ります。各サンプルの前に、`soak.rb`は自分の接続をすべて閉じます。そして、`stub_status`が示す開いた接続が、サンプルを求める接続だけになるまで待ちます。待つのは最大5秒です。サンプルは次のカラムからなります。

| カラム | 取得元 | 合格の条件 |
|---|---|---|
| `gc_live` | `Nginx::Debug.gc`の後に読んだ`Nginx::Debug.stats`。このメソッドの説明は下の「ソークのビルドと`Nginx::Debug`」の節に書いてある | どのサンプルでも同じ |
| `gc_root` | `gc_live`と同じ | どのサンプルでも同じ |
| `fibers` | `gc_root`と同じHashの`gc_root_fibers` | どのサンプルでも同じ |
| `arena` | `gc_root`と同じHashの`gc_arena_idx` | どのサンプルでも同じ |
| `timers` | 同じHashの`timers` | すべてのサンプルで0 |
| `fd` | `/proc/<worker>/fd`にあるエントリーの数 | `fd`から`up`を引いた値が、すべてのサンプルで同じ |
| `up` | モックのLLMの`connections_open`。モックを使わないシナリオでは、常に0 | `SOAK_CONCURRENCY`以下。`abort`と`cut`のシナリオでは、いつも0になる |
| `active` | `stub_status`の`Active connections` | すべてのサンプルで1 |
| `rss_kb` | `/proc/<worker>/status`にある`VmRSS` | 最後のサンプルからその前のサンプルを引いた値が`SOAK_RSS_STEP_KB`以下。最後のサンプルから最初のサンプルを引いた差の値が`SOAK_RSS_TOTAL_KB`以下に収まる |

どのサンプルの時点でも、ワーカーは同じ状態にあります。それより前に送ったリクエストはすべて終わっていて、動いているリクエストは`/debug/stats`自身だけです。そのため、カウンタの値は、それまでに動いたリクエストの数によって変わりません。

- `gc_live`は、生きているmrubyのオブジェクトの数です。`Nginx::Debug.gc`は最初にフルGCを実行するので、終わったリクエストのオブジェクトは既に解放されています。
- `gc_root`は、ngx_mrubyがGCから守っているオブジェクトの数で、`fibers`はそのうちのfiberの数です。数えるのは、各mrb_stateのholderと、holderに入れたオブジェクトです。holderはmrb_stateを開くときに1回だけ登録し、その実装は`src/http/ngx_http_mruby_gc_roots.h`にあります。ハンドラは、始まるときにholderへfiberを入れ、終わるときにそのスロットを空けます。そのため、サンプルに残るのは、holderと`/debug/stats`のfiberです。ngx_mrubyは自分の呼び出しを数えるので、このチェックは、mrubyがGCのルートをどう持つかに左右されません。数え方は、下の「ソークのビルドと`Nginx::Debug`」にあります。
- `arena`は、`/debug/stats`が動いている間のmrubyのGCアリーナの深さです。アリーナを保存するコードパスは、どれもアリーナを元に戻します。
- `timers`は、`Nginx::Async.sleep`のタイマーのうち、発火も削除もされていないものの数です。待っているリクエストが無いので、この数は0です。
- `fd`は、`/debug/stats`の接続が閉じた後に読みます。そのため、`fd`が数えるのは、listenしているソケット、ログのファイル、nginx自身のディスクリプタです。`active`は`/status`のリクエストから読みます。その時点で開いている接続は、このリクエストの接続だけです。リクエストがソケットやファイルを開いたままにすると、1つにつき、これらの値が1増えます。
- `up`は、モックのLLMで開いている接続の数です。nginxのupstreamは、これらの接続を次のリクエストのために保ちます。その数は、それまでで最も混んだ時点で同時に使われていたupstreamの接続の数です。そのため、後のウィンドウがたまたまそれより混むと、`up`は1増えることがあります。また、これらの接続は、それぞれ`fd`にも数えられます。そこでソークテストは、サンプルの間で`fd`から`up`を引いた値を比べ、`up`の上限をクライアントの接続の数で押さえます。`abort`と`cut`のシナリオでは、正常に終わるレスポンスが無いので、nginxはupstreamの接続を保ちません。ソークテストは`up`が0になるまで最大5秒待ち、0にならなければそのサンプルを失敗にします。

`VmRSS`は正確な値ではないので、ソークテストは比べずに上限で押さえます。ソークのビルドは、各サンプルの前のフルGCで`malloc_trim(0)`を呼びます。この関数は、Cのヒープの空きページを返します。説明は下の節にあります。この呼び出しが無いと、正しいビルドでも、サンプルの間でVmRSSが増える向きにも減る向きにも最大で約1 MB動きました。どれだけ動くかは、アロケータがたまたまどこに空きメモリを残したかによって決まりました。

`test/soak/nginx.conf`のシナリオは、`Nginx::Debug`自身も1回確かめます。確かめるのは、最初のレスポンスの後、ウォームアップの前です。シナリオは`/debug/check`にリクエストを送ります。そのコードは、まず`Nginx::Debug.gc`を実行し、`Nginx::Debug.stats`を読みます。次に、1000回のループの各回で、どこからも参照されないStringを2つ作ります。最後に、2回目の`Nginx::Debug.gc`の前と後に、`gc_live`をもう一度読みます。シナリオは、次のすべてが成り立たないと失敗します。

- `Nginx::Debug.stats`が、下の「ソークのビルドと`Nginx::Debug`」が挙げるキーを持ち、値がすべてIntegerであること。`gc_root_mruby`と`gc_root_fibers_mruby`は、両方あるか、両方無いかのどちらかであること
- `Nginx::Debug.gc`が`nil`を必ず返すこと
- Stringを作ると、`gc_live`が1000以上増えること
- 2回目のフルGCで`gc_live`が1000以上減り、最初に読んだ値に10を足した値以下になること

コードは、`GC.disable`と`GC.enable`の間でStringを作ります。フルGCの後でも、生きているオブジェクトは約1000個あります。そのため、こうしないと、mrubyのインクリメンタルGCがループの途中で始まります。そうすると、2回目に読む前に、Stringの大部分が解放されます。このチェックが無いと、キーが欠けた`Nginx::Debug.stats`や、何も解放しない`Nginx::Debug.gc`でも、すべてのサンプルが同じ値になり、ソークテストは通ってしまいます。

シナリオは、次のどれかが起きたときにも失敗します。

- レスポンスが期待どおりでないとき
- `SIGQUIT`を受けてから30秒以内にnginxが終了しないとき
- nginxの`error.log`かstderrに、`open socket`、`[error]`、`[alert]`、`[crit]`、`[emerg]`、`runtime error:`、`Sanitizer`のどれかが含まれるとき

ngx_mrubyは、ハンドラで発生した例外を`error`のレベルでログに書きます。また、`disconnect`のクライアントは最初のレスポンスしか読みません。そのため、そのクライアントの後のリクエストで起きた例外は、ログにだけ現れます。シナリオは、nginxが意図して`error`のレベルで書く行を挙げられます。挙げる場所は`test/soak/scenarios.rb`の`allowed_log`で、挙げた行はチェックの前に除かれます。どれかのシナリオが失敗すると、終了ステータスは1になります。

デフォルトのシナリオは次のとおりです。それぞれ`test/soak/nginx.conf`の1つのlocationです。

| シナリオ | ハンドラ | クライアント |
|---|---|---|
| `hello` | `Nginx.rputs` | keep-alive |
| `headers` | リクエストヘッダを3つ読み、レスポンスヘッダを2つ設定する | keep-alive |
| `var` | `Nginx::Var`で変数を2つ読み、1つを設定する | keep-alive |
| `filter` | `mruby_output_body_filter_code`が、`return 200`のボディを書き換える | keep-alive |
| `sleep` | `Nginx::Async.sleep 1`の後、レスポンスのボディを出力する | keep-alive |
| `sub_request` | `Nginx::Async::HTTP.sub_request`で、あるlocationにサブリクエストを送る。そのlocationは、2つ目のserverの静的なlocationへプロキシする。2つ目のserverのポートは、ベースのポートに1を足した番号を使う | keep-alive |
| `file` | スクリプトのファイルを指定し、`cache`を付けた`mruby_content_handler` | keep-alive |
| `disconnect` | `Nginx::Async.sleep 50`の後、レスポンスのボディを出力する | 接続ごとに1つのリクエストを送り、レスポンスを読まずに、その接続をすぐに閉じる |

加えて、エージェントプロキシのシナリオが4つあります。どれも、モックのLLMの前に置いた`test/soak/nginx.agent.conf`の`/v1/route`か`/v1/responses/route`を使います。説明は下の「エージェントプロキシのシナリオ」にあります。

| シナリオ | モック | クライアント |
|---|---|---|
| `agent_stream` | 50個の`content_block_delta`のイベントを持つストリーム。イベントは全部で55個 | keep-alive。すべてのストリームが1バイトも違わないことを比べる |
| `agent_client_abort` | 10個のイベントを書き、nginxがその接続を閉じるまでストリームの送信を止めておく | 接続ごとに1つのリクエスト。レスポンスのヘッダと最初の3つのイベントを読み、それを確かめてから、接続を閉じる |
| `agent_upstream_reset` | 10個のイベントを書き、その接続をリセットする | 接続ごとに1つのリクエスト。EOFまで読み、ボディがちょうど10個のイベントで、chunkedのボディの終わりが無いことを確かめる |
| `agent_responses_stream` | 50個の`response.output_text.delta`のイベントと`response.completed`を持つ、Responsesのストリーム。イベントは全部で58個。`/v1/responses/route`を通して中継する | keep-alive。すべてのストリームが1バイトも違わないことを比べる |

keep-aliveのクライアントは、`SOAK_CONCURRENCY`個の接続です。各接続は、レスポンスを読んでから次のリクエストを送ります。`soak.rb`は、すべてのレスポンスを確かめます。`disconnect`のクライアントは、スレッドごとに、100 msごとに16個のリクエストをまとめて送ります。こうすると、同時に開いているリクエストの数が、どのウィンドウでも同じになります。`agent_client_abort`のクライアントのモードは`:abort`で、`agent_upstream_reset`のクライアントのモードは`:cut`です。どちらのクライアントも`SOAK_CONCURRENCY`個のスレッドで、各スレッドは接続ごとに1つのリクエストを送り、届いたものを確かめます。

### エージェントプロキシのシナリオ

`test/soak/nginx.agent.conf`は、ソークテストと性能の比較のための、独立した設定です。この設定には、mrubyのフィルタのディレクティブがありません。`http {}`ブロックのどこかにボディフィルタのディレクティブが1つあるとします。すると、そのブロックのすべてのレスポンスに、ngx_mrubyのボディフィルタが入ります。`test/soak/nginx.conf`の`filter`のシナリオでは、そうなっています。その場合、ストリームのようなchunkedのレスポンスは、どれもそのフィルタを通り、そのたびにnoticeのログが出ます。この設定の`error_log`のレベルは`warn`です。プロキシの設定は、エージェントプロキシの設定と同じです。`proxy_buffering off`、`proxy_buffer_size 4k`、`proxy_http_version 1.1`を指定し、クライアントの`Authorization`を、ハンドラが選んだ認証情報に置き換えます。`upstream`ブロックには、`keepalive 32`、`keepalive_requests 1000000`、`keepalive_timeout 1h`を指定します。こうすると、シナリオの間、nginxもモックへのアイドルの接続を閉じません。ハンドラは`test/soak/handlers/`にあります。

- `agent_init.rb`：`mruby_init_worker`のハンドラです。クライアントのキー、認証情報、モデルのテーブルを用意します。
- `agent_auth.rb`：server `auth.agent.test`のserver rewriteハンドラです。`Authorization`か`x-api-key`からクライアントのキーを探し、3つの変数を設定します。キーを探すのに、Hashを合わせて2回引きます。
- `agent_route.rb`：`/v1/route`と`/v1/responses/route`のaccessハンドラで、そのlocationには`mruby_enable_read_request_body on`を指定しています。`JSON.parse(r.body)["model"]`を実行し、Hashを1回引いて、`proxy_pass http://$agent_backend`のための`$agent_backend`の値を設定します。

`/v1/plain`と`/v1/route`は、モックの`/v1/messages`へプロキシします。`/v1/responses/plain`と`/v1/responses/route`は、モックの`/v1/responses`へプロキシします。リクエストのボディは、ちょうど2 KBか64 KBのMessagesのリクエストです。`responses_*`と`agent_responses_*`のシナリオでは、ちょうど2 KBのResponsesのリクエストです。ボディは`MockLLM.request_body`が作り、Responsesのボディには`api: :responses`を渡します。どのボディでも`"model"`が最初のキーで、ストリームのボディには`"stream": true`があります。abortとresetのシナリオには、Responsesに対応するシナリオがありません。nginxは、どちらのAPIのバイトも、同じように中継するからです。

各`agent_*`のシナリオで、ソークテストはnginxより先にモックを起動します。モックのポートは、ベースのポートに2を足した番号です。最後のサンプルの後、ソークテストはモックのカウンタを確かめます。モックが読んだリクエストは、ソークテストが送ったリクエストとちょうど同じ数でなければなりません。その数は1 + `SOAK_WARMUP` + `SOAK_N`です。また、そのすべてのリクエストが、シナリオが決める終わり方で終わっていなければなりません。`agent_stream`では、レスポンスを最後まで書き終えることです。`agent_client_abort`では、nginxが接続を閉じるまでストリームを止めておくか、モックがまだ書いている間に接続が閉じていたことです。`agent_upstream_reset`では、接続をリセットすることです。モックが出力したものは`logs/mock.<scenario>.log`に書かれます。

`agent_upstream_reset`は、`error`のレベルの行を2つ許します。どちらも、モックの`/v1/messages`へのupstreamの接続についての行です。1つ目は`recv() failed (104: Connection reset by peer)`です。nginxは、upstreamの接続のエラーを`error`のレベルで、クライアントの接続のエラーを`info`のレベルでログに書きます。2つ目は`upstream prematurely closed connection`です。バッファリングしないモードで、upstreamがレスポンスの途中で接続を閉じると、nginxはこの行を書きます。これまでの実行で現れたのは1つ目だけです。その行の動作の部分は、「while reading upstream」か「while sending to client」でした。`agent_client_abort`は、`warn`以上のレベルでは何もログに書きません。

### ソークのビルドと`Nginx::Debug`

`test/soak/run.sh`は、`test/build_release.sh`で`build_soak/`にビルドします。説明は下の「リリースのビルド」にあります。nginxとngx_mrubyは`-O2 -g`でビルドし、`MRB_GC_STRESS`も`--with-debug`も付けません。`build_config.rb`のgemは、`build_config.rb.lock`のコミットでビルドします。このビルドには、定義が2つ加わります。ngx_mrubyは`-DNGX_MRUBY_DEBUG_STATS`を付けてコンパイルし、mrubyは`-DMRB_USE_MALLOC_TRIM`を付けてコンパイルします。後者を付けると、`mrb_full_gc()`は`malloc_trim(0)`も呼びます。mrubyがフルGCを実行するのは、求められたときと、まれな場合だけです。求めるのは`GC.start`や`Nginx::Debug.gc`です。まれな場合とは、インクリメンタルGCが多すぎるオブジェクトを見つけたときや、メモリの確保に失敗したときです。そのため、サンプルの間のワーカーは、この定義が無いときと同じように動きます。

`-DNGX_MRUBY_DEBUG_STATS`を付けると、クラスの`Nginx::Debug`が加わります。`build.sh`と`test.sh`のデフォルトのビルドには、このクラスがありません。

- `Nginx::Debug.gc`は、フルGCの`mrb_full_gc`を実行し、`nil`を返します。
- `Nginx::Debug.stats`は、次のSymbolをキーに持つHashを返します。
  - `gc_live`：`mrb->gc.live`の値です。
  - `gc_root`：nginxのプロセス全体で、ngx_mrubyがGCから守っているオブジェクトの数です。数えるのは2種類のオブジェクトで、呼び出し1回につき1つと数えます。1つは、`mrb_gc_register()`で登録して、まだ登録を外していないオブジェクトで、各mrb_stateのholderがこれにあたります。holderは`src/http/ngx_http_mruby_gc_roots.h`にあります。もう1つは、`ngx_mrb_gc_roots_add()`でholderに入れて、まだ`ngx_mrb_gc_roots_remove()`で外していないオブジェクトです。httpモジュールの分とstreamモジュールの分を足して数えます。即値はmrubyが登録しないので、数えません。ngx_mrubyが入れた数より多く外すと、この値は負になります。
  - `gc_root_fibers`：`gc_root`が数えるオブジェクトのうちの、fiberの数です。
  - `gc_arena_idx`：`mrb->gc.arena_idx`です。
  - `timers`：`Nginx::Async.sleep`のタイマーのうち、発火も削除もされていないタイマーの数です。
  - `gc_root_mruby`と`gc_root_fibers_mruby`：httpモジュールのmrb_stateにある、mruby自身の`_gc_root_`の配列の長さと、配列の中のfiberの数です。mruby 3.xと4.0は、そのmrb_stateで最初に`mrb_gc_register()`を呼んだときに、この配列を作ります。mruby 4.1は、代わりにGCのルートを`mrb->gc.root`に持つので、この2つのキーはありません。`gc_root`と違って、この2つの値には、mrubyとgemが登録したオブジェクトが入り、holderの中のオブジェクトは入りません。配列にあるのはhttpモジュールのholderで、holderの中のfiberではないからです。ソークテストはこの2つの値を確かめません。配列のあるバージョンのmrubyで、`gc_root`と比べるために出す値です。

`gc_root`と`gc_root_fibers`は、GCのルートをmrubyから読みません。mruby 4.1は、GCのルートを`_gc_root_`の配列に持たなくなったからです。配列から読むと、数はどのサンプルでも0になり、ソークテストは何も確かめずに通ってしまいます。ngx_mrubyはfiberをmrb_stateのholderに保持し、`src/http/ngx_http_mruby_core.c`の`ngx_mrb_gc_roots_add()`と`ngx_mrb_gc_roots_remove()`で数えます。`-DNGX_MRUBY_DEBUG_STATS`を付けると、`src/http/ngx_http_mruby_debug.h`は、`mrb_gc_register`と`mrb_gc_unregister`をマクロとして定義します。このマクロは、mrubyの関数を呼んでから、その呼び出しを数えます。そのため、このヘッダをインクルードするソースファイルの呼び出しは、後で加えた呼び出しも含めて、すべて数えられます。したがって、`src/http/`か`src/stream/`の`.c`ファイルのうち、どちらかの関数を呼ぶものは、`ngx_http_mruby_debug.h`をインクルードしなければなりません。`test/soak/run.sh`は、ビルドの前にこれを確かめ、インクルードしていないファイルがあれば止まります。定義が無いと、このヘッダはマクロを定義せず、呼び出しはmrubyの関数に直接届きます。

### 実行する

`soak.rb`は`/proc`を読むので、LinuxとCRuby 3.0以降が要ります。ほかのシステムでは、コンテナの中で実行してください。たとえば、次のようにします。

```console
$ docker run --rm -v "$PWD":/work -w /work ubuntu:22.04 sh -c 'apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y build-essential rake ruby bison git gperf wget ca-certificates zlib1g-dev libpcre3-dev libssl-dev >/dev/null && sh test/soak/run.sh'
```

Linuxでは、次のように実行します。

```console
$ sh test/soak/run.sh                                  # build, then run the default scenarios
$ ONLY_RUN=1 sh test/soak/run.sh                       # run without building
$ ONLY_RUN=1 SOAK_SCENARIOS=sleep,disconnect SOAK_N=100000 sh test/soak/run.sh
```

最初の実行には数分かかります。gemをクローンし、mrubyとnginxをビルドするからです。シナリオの実行には約1分かかり、aarch64のコンテナでは、そのうち`agent_*`のシナリオが約18秒です。結果のテーブルには、シナリオごとに1つのレコードがあります。ある値がサンプルの間で違うときは、4つの値をすべて`/`で区切って示し、その理由をテーブルの下に挙げます。ログは`build_soak/nginx/soak/logs/`にあり、`error.<scenario>.log`、`stderr.<scenario>.log`、`mock.<scenario>.log`、`soak.log`の4種類です。`mock.<scenario>.log`は、`agent_*`のシナリオでモックのLLMが出力したもので、`soak.log`は`soak.rb`の出力の記録です。

`test.sh`が止めるのは、自分が起動したnginxだけです。説明は上の「nginxを止める」にあります。また、`test.sh`のポートは、ソークテストのポートとは重なりません。

| 変数 | デフォルト | 意味 |
|---|---|---|
| `ONLY_RUN` | 未設定 | 設定すると、ビルドを飛ばす |
| `NUM_THREADS_ENV` | CPUの数の半分 | ビルドの並列数。`build.sh`に渡す |
| `SOAK_SCENARIOS` | デフォルトのシナリオ全部 | カンマで区切ったシナリオの名前 |
| `SOAK_N` | 20000 | ウォームアップの後に、シナリオごとに送るリクエストの数 |
| `SOAK_WARMUP` | 2000 | 最初のサンプルを取る前に送るリクエストの個数 |
| `SOAK_CONCURRENCY` | 8 | 接続の数。`disconnect`ではスレッドの数を表す |
| `SOAK_PORT_BASE` | 12360 | シナリオのポート。`sub_request`のバックエンドは次の番号を使い、モックのLLMはさらにその次の番号を使う |
| `SOAK_RSS_STEP_KB` | 512 | 最後のウィンドウでのVmRSSの上限。単位はkB |
| `SOAK_RSS_TOTAL_KB` | 1024 | 最初のサンプルから最後のサンプルまでのVmRSSの上限。単位はkB |

### しきい値とキャリブレーション

VmRSSの2つの上限は、2026年10月3日にデフォルトのシナリオを実行した結果から決めました。環境は、nginx 1.31.6、Ubuntu 22.04、gcc 11、glibc 2.35です。実行した場所は、aarch64のコンテナと、x86_64のCIの`soak`ジョブです。テーブルの値は、そのレコードのすべてのシナリオと実行のうちで、最も大きい値です。

| 実行 | 最後のウィンドウの増分 | 最初のサンプルからの増分 |
|---|---|---|
| aarch64のコンテナ、3回実行、`SOAK_N=20000`、`MRB_USE_MALLOC_TRIM`を付けないとき | +144 kB | +212 kB。減る向きには最大で-1076 kB |
| aarch64のコンテナ、1回実行、`SOAK_N=100000`、`MRB_USE_MALLOC_TRIM`を付けないとき | +288 kB | +3396 kB (`disconnect`) |
| aarch64のコンテナ、10回実行、`SOAK_N=20000` | +112 kB (`sub_request`) | +204 kB (`sleep`) |
| aarch64のコンテナ、1回実行、`SOAK_N=100000` | +68 kB (`file`) | +160 kB (`file`) |
| x86_64のCIのランナー、4回実行、`SOAK_N=20000` | +144 kB (`filter`) | +236 kB (`sleep`) |
| aarch64、3回、`SOAK_N=20000`、`agent_*`、2026年10月4日の実行 | +28 kB (`agent_stream`) | +32 kB、シナリオは`agent_upstream_reset` |
| x86_64のCI、実行37152930938と37156005549、`SOAK_N=20000`、`agent_*`、2026年10月4日の2回の実行 | +16 kB、シナリオは`agent_stream`と`agent_client_abort` | +84 kB (`agent_stream`と`agent_client_abort`) |

`malloc_trim(0)`が無いと、`SOAK_N=300000`の`disconnect`のシナリオでは、VmRSSがウィンドウごとに+2832 kB、-788 kB、+1088 kB動きました。最後のウィンドウの上限を512 kBにすると、この動きは上限を超えます。それでも、このシナリオのカウンタは同じままで、全体の増分は`SOAK_N=100000`のときより小さくなりました。`malloc_trim(0)`があると、最も大きい増分は、最後のウィンドウで144 kB、全体で236 kBです。デフォルトの上限は、最後のウィンドウで512 kB、全体で1024 kBで、それぞれこれらの約3.5倍と約4.3倍です。最後のウィンドウの上限を緩いほうにしたのは、共有のCIのランナーで、1つのウィンドウが144 kB増えたためです。小さなリークを見つけるのは、全体の上限のほうです。リクエストあたり約50バイト未満のリークは、`SOAK_N`がデフォルトの20000なら、1024 kBに届きません。それより小さなリークを探すには、`SOAK_N`を上げてください。比較のために挙げると、リクエストあたり4 kBリークするビルドは、ウィンドウごとに約26 MB増えます。

### シナリオを追加する

1. `test/soak/nginx.conf`にlocationを加えます。ハンドラを使うなら、ハンドラのファイルを`test/soak/handlers/`に加えます。そのディレクトリのパスには`__SOAK_HANDLERS__`を使い、2つ目のserverには`__SOAK_BACKEND_PORT__`を使います。モックのLLMを後ろに置くシナリオは、代わりに`test/soak/nginx.agent.conf`に加え、モックには`__SOAK_MOCK_PORT__`を使います。
2. `test/soak/scenarios.rb`の`SCENARIOS`に`Scenario`を加えます。パス、リクエストヘッダ、期待するボディとレスポンスヘッダ、モードを指定します。モードは`:keepalive`、`:disconnect`、`:abort`、`:cut`のどれかです。エージェントのテンプレートのシナリオでは、`conf: 'nginx.agent.conf'`、リクエストのメソッドとボディ、`mock:`も設定します。`mock:`にはモックのオプションを指定し、デフォルトのままなら`[]`にします。フィールドの一覧は、そのファイルの先頭のコメントにあります。
3. `test/soak/soak.rb`の`DEFAULT_SCENARIOS`にシナリオの名前を加えます。ソークテストを3回実行し、すべてのカウンタが同じままで、VmRSSが上限に収まることを確かめます。あるカウンタが増え続けるなら、そのシナリオは問題を見つけました。シナリオを通すために、上限を上げたり、比較を外したりしないでください。脆弱性の可能性があるときは、`SECURITY.md`に書いてある方法で、非公開で報告してください。
4. `:keepalive`のシナリオは、下の性能の比較でも測れます。`test/perf/perf.rb`の`DEFAULT_SCENARIOS`に名前を加え、性能の比較の「しきい値とキャリブレーション」にある、変更の無い比較をそこで流して確かめてください。

## リリースのビルド

`sh test/build_release.sh SOURCE_DIR BUILD_DIR`は、リリースに近いオプションで、ngx_mrubyを静的モジュールとして組み込んだnginxをビルドします。nginxとngx_mrubyは`-O2 -g`でビルドし、mrubyは、mrubyのgccのツールチェインが決めるフラグでビルドします。そのフラグは`-O3 -g`です。`test.sh`が加える`MRB_GC_STRESS`と、`--with-debug`は付けません。`build_config.rb`のgemは、gemのロックのコミットでビルドします。ロックの説明はこの下にあります。ソークテストと性能の比較は、このスクリプトでビルドします。オプションが混ざらないように、それぞれ専用のディレクトリにビルドします。

| ビルド | ディレクトリ | 加えるオプション |
|---|---|---|
| `test/soak/run.sh`のソークテスト | `build_soak/` | ngx_mrubyに`-DNGX_MRUBY_DEBUG_STATS`を`RELEASE_CC_OPT`で加え、mrubyに`-DMRB_USE_MALLOC_TRIM`を`NGX_MRUBY_CFLAGS`で足す |
| 性能の比較の`test/perf/run.sh`と`test/perf/compare.sh` | `build_perf/head/`、`build_perf/base/` | 無し。どちらの定義を付けても、測るプロセスに余分なコードが加わるため |

`SOURCE_DIR`はビルドするチェックアウトで、スクリプトは、そのチェックアウト自身が持つビルドのファイルを使います。`build.sh`、`configure`、`build_config.rb`などです。そのため、プルリクエストのベースは、ベース自身のビルドの仕方でビルドされます。スクリプトはソースを`BUILD_DIR/tree`にコピーし、そこで`build.sh`を実行して、nginxを`BUILD_DIR/nginx`にインストールします。その結果、スクリプトは、`build/`ディレクトリ、`mruby/build`、`test.sh`が生成した`Makefile`、`config`、`mrbgems_config`には触れません。このビルドは、いつも、自分でダウンロードしたnginxのソースとシステムのOpenSSLでビルドする静的モジュールです。そのため、スクリプトは`BUILD_DYNAMIC_MODULE`、`NGINX_SRC_ENV`、`OPENSSL_SRC_VERSION`を無視します。nginxのソースは`BUILD_DIR/tree/build/`にダウンロードします。nginx.orgに届かないときは、`AGENTS.md`に書いてある方法で、ソースをそこに置いてください。

サードパーティのgemは、`SOURCE_DIR`にコミットした`build_config.rb.lock`のコミットでビルドします。説明は`docs/install/README.md`の「Gem commits」にあります。`RELEASE_GEM_LOCK`が設定されていて空でないときは、その値が指すロックのコミットでビルドします。`test/soak/run.sh`と`test/perf/run.sh`は、環境の`RELEASE_GEM_LOCK`をそのまま渡します。そのため、`RELEASE_GEM_LOCK=/path/to/other.lock sh test/soak/run.sh`を実行すると、チェックアウトを変えずに別のコミットでビルドできます。ロックの無いチェックアウトでは、最初のビルドが各gemのブランチの先頭を取ります。ロックをコミットする前のチェックアウトが、これにあたります。rakeは、ビルドしたコミットを`BUILD_DIR/tree/build_config.rb.lock`に書き込みます。

後の実行では、スクリプトはコピーを更新し、変わったファイルだけをビルドし直します。

- スクリプトは、内容が違うときだけ、ファイルをコピーに書き込みます。書き込んだファイルの時刻は、`SOURCE_DIR`の時刻でなく、コピーした時刻になります。`git archive`で作ったチェックアウトのファイルは、コミットの時刻を持ちます。この時刻は前のビルドのオブジェクトより古いことがあり、そうするとmakeはそのファイルをビルドし直しません。
- `SOURCE_DIR`に無くなったファイルは、コピーから消します。
- makeは、`src/`と`dependence/`のヘッダを追いません。そのため、そのどれかが変わったときは、スクリプトがそこにある`.c`ファイルをtouchします。
- スクリプトは、ファイルを消して作り直さず、その場で上書きします。ソースが大文字と小文字を区別しないファイルシステムにあり、それをコンテナと共有することがあります。macOSのDocker Desktopがその例です。この場合、rakeはmrubyの`Rakefile`を`rakefile`として読み込みます。ファイルを消して作り直した後、同じコンテナでの2回目の実行は、`LoadError: cannot load such file -- .../rakefile`で失敗していました。

ただし、makeとrakeが気づかない変更もあります。消したソースや外したgemのオブジェクトは`libmruby.a`に残り、nginxのconfigureも再び実行されません。そこでスクリプトは、次の入力を、`BUILD_DIR/build_stamp`に記録します。

- mrubyのツリー。`SOURCE_DIR`がgitのworktreeの最上位なら、gitがそのツリーに付けたidを記録します。そうでなければ、`mruby/build`と`mruby/bin`を除いたファイルのチェックサムを記録します。この2つのディレクトリは、`test.sh`がビルドした出力です。
- `mrbgems/`の下のファイルの名前
- `build_config.rb`、`config.in`、`configure`、`Makefile.in`、`build.sh`、`nginx_version`のチェックサム
- `NGX_MRUBY_CFLAGS`。スクリプトは、`test.sh`と同じように、この値をmrubyに渡します。
- nginxのconfigureのオプション
- そのビルドのgemのロック

スタンプが前のビルドのスタンプと違うと、スクリプトはmrubyとnginxを最初からビルドし、gemも新しくクローンします。ダウンロードしたnginxのソースは残します。新しいクローンが要るのは、ロックだけが変わったときです。rakeは、既にあるクローンを、fetchせずにロックのコミットでチェックアウトします。古いクローンには、そのコミットが無いことがあります。スタンプが扱わない変更の後は、`rm -rf build_soak`でビルドを手でリセットしてください。性能の比較では`build_perf`を消します。スタンプが扱わない変更には、たとえば`mruby/`の下のコミットしていない変更があります。gitがツリーに付けるidは、コミットしたときのままだからです。

## callgrindで性能を比べる

リクエストを処理する経路を変えると、どのテストも失敗しないまま、すべてのリクエストの仕事が増えることがあります。性能の比較では、プルリクエストのベースとヘッドのそれぞれで、nginxがリクエストあたりに実行する命令の数を数えます。そして、シナリオごとの変化をレポートに出します。命令の数はcallgrindの`Ir`で、ベースとヘッドはどちらもリリースのビルドです。命令の数はマシンの速さにも負荷にも左右されないので、この比較は共有のCIのランナーでも使えます。共有のランナーのスループットは30%を超えて変わり、そのことは`docs/proposals/v3-plan.md`の3.7節に書いてあります。命令の数には、キャッシュミス、分岐予測のミス、カーネルで使った時間は出ません。命令の数は、nginx、ngx_mruby、mruby、Cライブラリのユーザー空間のコードが、1つのリクエストのためにする仕事の量を表します。

### 何を測るか

測るシナリオは2種類です。1つは、ソークテストのシナリオのうち、keep-aliveのクライアントを使うものです。`hello`、`headers`、`var`、`filter`、`sleep`、`sub_request`、`file`で、そのテーブルは「メモリのソークテスト」にあります。もう1つは、下の「性能の比較に入れたエージェントプロキシのシナリオ」にあるエージェントプロキシのシナリオです。`disconnect`は測りません。`test/perf/perf.rb`は、各シナリオについて、ベースとヘッドの順番に次のことをします。

1. シナリオにLLMのモックがあれば、モックを起動します。nginxは、`test/soak/nginx.conf`かシナリオのテンプレートを`master_process off`に変えた設定で、`valgrind --tool=callgrind --instr-atstart=no`の下で起動します。こうすると、起動の間は計測しません。
2. レスポンスを1つ確かめてから、`PERF_WARMUP`の数のリクエストを送ります。
3. ウォームアップの接続が1つも開いていないと`stub_status`に出るまで待ち、`callgrind_control --instr=on`で計測を有効にします。
4. keep-aliveで`PERF_N`の数のリクエストを送り、すべてのレスポンスを確かめます。nginxは1000のリクエストの後に接続を閉じ、クライアントは次の接続を開きます。この1000は`keepalive_requests`の値です。
5. `callgrind_control --dump`でプロファイルを書き出し、nginxを止めます。

ステップ5のプロファイルには、ステップ4のリクエストのコストが入ります。起動、設定、ウォームアップ、終了のコストは入りません。**リクエストあたりのIr**は、このプロファイルのIrの合計を`PERF_N`で割った値です。別の方法として、Nと2Nのリクエストで2回実行し、その差をNで割ることもできます。この方法では3倍の数のリクエストが要り、2回の実行のばらつきも加わります。1回の実行で計測する区間であるウィンドウには、リクエストのほかに何も入りません。

callgrind_controlは、valgrindのgdbserverである`vgdb`を通してプロセスに届きます。vgdbは、nginxのワーカーのような、valgrindがforkしたプロセスを扱いません。`master_process off`では、nginxの1つのプロセスが、ワーカーと同じようにイベントループとハンドラを実行します。`epoll_wait`で待っているプロセスに割り込むためのptraceをvgdbが使えないときは、コマンドは、そのプロセスが次にコードを実行したときに動きます。そのため`perf.rb`は、コマンドが動くまで、0.2秒ごとに`/status`へリクエストを送ります。`/status`は`stub_status`です。これらのリクエストの一部はウィンドウに入ります。これまでの実行では、ウィンドウごとに2つでした。

**GCを除いたリクエストあたりのIr**は、mrubyのガベージコレクタのコストを除いた値です。除くのは、コレクタの外から`mrb_incremental_gc`と`mrb_full_gc`を呼んだ呼び出しのinclusiveのコストです。そうした呼び出しは、`mrb_obj_alloc`、mallocのラッパー、`GC.start`から来ます。このコストは、再帰のサフィックス`'2`の無い`mrb_incremental_gc`と`mrb_full_gc`について`callgrind_annotate --inclusive=yes`が出すinclusiveのコストです。ただし、`mrb_incremental_gc`が実行するフルGCは2回数えません。`perf.rb`は、この値をプロファイルの呼び出しの記録から読みます。詳しくは`parse_profile`のコメントにあります。GCは、まとまって動きます。生きているオブジェクトの数がしきい値を超えると、`mrb_obj_alloc`がコレクタを呼びます。1つのサイクルは、ルートのスキャンとマーク、その後のスイープで、数回の呼び出しになります。`hello`では、20000のリクエストで21回の呼び出しがあり、およそ2000のリクエストに1つのサイクルです。GCは合計の約6%です。リクエストあたりに確保するオブジェクトが数個増えたり減ったりする変更では、サイクルがウィンドウに対してずれます。そして合計は、1つのサイクルの一部の分だけ動きます。GCを除いた値はこのようには飛ばないので、しきい値はこの値に当てます。合計もレポートに出します。

GCが動くと、残りの部分のコストも変わります。スイープが多くのブロックを解放した後は、リクエストのコードの次の`malloc`の呼び出しに時間がかかります。そのため、ウィンドウは多くのGCのサイクルにまたがる必要があります。`PERF_N=20000`では、`hello`のGCを除いたリクエストあたりのIrは11039でした。`PERF_WARMUP=7000`にしてウィンドウを5000のリクエストだけずらすと11049で、差は+0.1%でした。`PERF_N=1000`と`PERF_WARMUP=200`のウィンドウは1つのサイクルより短く、2回の実行で10726と10732になり、-2.8%でした。これが、`PERF_N`を20000に設定した理由です。

<a id="agent-proxy-scenarios-in-the-comparison"></a>

### 性能の比較に入れたエージェントプロキシのシナリオ

これらのシナリオでは、エージェントプロキシにリクエストあたりどれだけのコストがかかるかを測ります。測るのは、`test/soak/nginx.agent.conf`の設定でLLMのモックの前に置いたnginxです。LLMのモックは「LLMのモックのupstream」に、この設定はソークテストの節の「エージェントプロキシのシナリオ」にあります。Rubyを使わないシナリオは、同じ形のシナリオのベースラインです。そのため、2つの差がRubyの加えるコストになります。テーブルの最後には、`test/soak/nginx.conf`の7つのシナリオを、各シナリオのリクエストの関数を示すために載せています。

| シナリオ | リクエストと応答 | リクエストあたりのRuby | リクエストの関数。括弧の中はリクエストあたりの呼び出しの数 |
|---|---|---|---|
| `proxy_plain_2k`, `proxy_plain_64k` | ちょうど2 KBか64 KBのMessagesのボディを`/v1/plain`へPOSTし、`proxy_pass`でモックへ送る。応答はJSONのメッセージ1つ | 無し | `ngx_http_log_request` (1) |
| `proxy_stream_plain_50`, `proxy_stream_plain_1000` | `"stream": true`を付けた2 KBのボディを`/v1/plain`へ送る。応答は50か1000のデルタのストリームで、イベントは55か1005 | 無し | `ngx_http_log_request` (1) |
| `responses_stream_plain_50`, `responses_stream_plain_1000` | `"stream": true`を付けた2 KBのResponsesのボディを`/v1/responses/plain`へ送り、`proxy_pass`でモックの`/v1/responses`へ送る。応答は、50か1000のデルタと`response.completed`のResponsesのストリームで、イベントは58か1008 | 無し | `ngx_http_log_request` (1) |
| `auth` | `proxy_plain_2k`のリクエストをサーバの`auth.agent.test`へ送る。このサーバのserver rewriteハンドラの`agent_auth.rb`が、クライアントのキーを探し、upstreamの認証情報を差し替える | ハンドラ1つ | `ngx_http_log_request` (1) |
| `route_json_2k`, `route_json_64k` | `proxy_plain_*`のリクエストを`/v1/route`へ送る。そのaccessハンドラの`agent_route.rb`が、`JSON.parse`でボディをパースし、`proxy_pass http://$agent_backend`のupstreamブロックを選んで設定する | ハンドラ1つ | `ngx_http_log_request` (1) |
| `ruby_call_1`, `ruby_call_10` | `mruby_set_code`の変数を1つか10個持ち、`return 200`で応答するlocationへのGET。upstreamは無し | 1回か10回のハンドラの呼び出し | `ngx_http_mruby_set_inline_handler` (1か10) |
| `hello`, `headers`, `var`, `filter`, `sleep`, `sub_request`, `file` | `test/soak/nginx.conf`のlocationへのGET。locationは「メモリのソークテスト」にある。モックは無し | ハンドラかフィルタ1つ | `ngx_mrb_start_fiber` (1) |

`test/soak/nginx.conf`の7つのシナリオは、`ngx_mrb_start_fiber`の呼び出しを数えます。ハンドラやフィルタのRubyのコードを実行する`ngx_mrb_run`は、実行のたびにfiberを1つ始めます。ほかに`ngx_mrb_start_fiber`を呼ぶものはありません。これらのシナリオが`ngx_mrb_run`を数えないのは、callgrindがその呼び出しをどのビルドでも同じようには記録しないからです。2026年10月4日に`next`の`45c9e52`をaarch64でビルドしたものでは、callgrindは、リクエストごとに`ngx_mrb_run`の2つ目の呼び出しを記録しました。`filter`では、`ngx_mrb_run`から`ngx_mrb_run'2`への呼び出しとして記録し、この呼び出しは1回と数えます。ほかの6つのシナリオでは、`ngx_mrb_http_get_module_ctx.part.0`から`ngx_mrb_run'2`への呼び出しとして記録しました。`ngx_mrb_http_get_module_ctx`は`ngx_mrb_run`を呼ばないにもかかわらず、そう記録しました。そのため、6つのシナリオのウィンドウにはリクエストごとに2回の呼び出しが入り、チェックに失敗しました。`ngx_mrb_start_fiber`の呼び出しは、7つのすべてで、リクエストごとに1回と記録しました。CIのランナーで動かしたx86_64のビルドと同じです。

upstreamのあるシナリオは、`ngx_http_log_request`の呼び出しを数えます。nginxは、Rubyの有無にかかわらず、終えるリクエストごとにこの関数を1回呼びます。サブリクエストについては、`log_subrequest on`のときだけ呼びます。Rubyを使わないシナリオには、数える`ngx_mrb_start_fiber`の呼び出しがありません。そこで、upstreamのあるシナリオは、どれも同じこの関数を数えます。`callgrind_control`のためにnginxを起こす`/status`のリクエストも、計測を有効にした後に来たものはウィンドウの中で終わります。そのため、ウィンドウには、その数だけ多くの呼び出しが入ることがあります。これまでの実行では、ウィンドウごとに2つでした。`mruby_set_code`は、そのハンドラの末尾呼び出しを通して`ngx_mrb_run`に至ります。callgrindは、この末尾呼び出しを、いつも`ngx_mrb_run`の呼び出しとして記録するとは限りません。aarch64のビルドでは、`ruby_call_10`のリクエストあたり10回の呼び出しのうち1回が、ハンドラから`ngx_mrb_start_fiber`への呼び出しとして出て、`ruby_call_1`では1回も出ませんでした。そのため、`ruby_call_*`のシナリオは、nginxがポインタを通して呼ぶハンドラの呼び出しの回数を数えます。

リクエストあたりの数のうち2つは、テーブルの後に出力し、`report.json`に残しますが、チェックはしません。1つ目は`ruby_calls`で、`ngx_mrb_start_fiber`の呼び出しの数です。`ngx_mrb_run`はRubyのコードを実行するたびにfiberを1つ始め、ほかにこの関数を呼ぶものはありません。`test/soak/nginx.conf`の7つのシナリオでは、ウィンドウのチェックも同じ呼び出しを数えます。2つ目は`non_buffered_calls`で、バッファしないレスポンスを中継する`ngx_http_upstream_process_non_buffered_request`の呼び出しの数です。nginxは、upstreamの接続が読めるようになったときと、クライアントの接続に書けるようになったときに、この関数を呼びます。1回の呼び出しで、nginxは`recv()`がブロックするところまでupstreamから読み、読んだものをクライアントへ書きます。一度に読むのは、最大で`proxy_buffer_size`の4kです。そのため、この数は4kずつ読んだ回数ではありません。1つのレスポンスに何回の呼び出しがかかるかは、各呼び出しのときにレスポンスのどれだけが届いていたかで決まります。この数は、ビルドとマシンでも違います。`proxy_plain_*`、`auth`、`route_json_*`では、aarch64のコンテナでリクエストあたり2.00回、x86_64のCIのランナーで1.00回でした。

呼び出しのたびにIrがかかります。aarch64で`PERF_N=2000`の`proxy_stream_plain_50`を、モックの書き方を3通りに変えて測りました。ストリームを1回で書く場合、イベントごとに1回書く場合、イベントごとに1 msずつ空けて1回書く場合です。リクエストあたりの呼び出しは3.00、4.96、109.99回で、リクエストあたりのコストは52270、54255、142740 Irでした。1つ目と2つ目の差からは呼び出しあたり約1010 Ir、1つ目と3つ目の差からは約850 Irになります。2つのビルドを比べるとき、呼び出しの数が違うシナリオのレポートの行には、その差だけで生じるIrを出します。このIrは呼び出しあたり1000 Irとして計算し、ベースのGCを除いた値に対する割合で示します。1000は`NON_BUFFERED_CALL_IR`の値です。その割合が`PERF_WARN_PERCENT`の半分以上なら、その行には、シナリオの変化はレスポンスが届いたタイミングから来たのかもしれないと書きます。`proxy_stream_plain_50`では、呼び出しがリクエストあたり約2回増えると`WARN`に、約3回増えると`FAIL`に届きます。「しきい値とキャリブレーション」では、ビルドの入力を変えない変更を測りました。そこでは、1回の実行のベースとヘッドの間で、このシナリオの呼び出しはリクエストあたり0.01から0.25回違いました。

最初の測定は2026年10月4日です。このチェックアウトのヘッドのビルドで、`test/perf/perf.rb`を1回実行しました。ヘッドは、`next`の`f62880c`にハーネスを加えたものです。環境は、aarch64のコンテナの中のUbuntu 22.04で、gcc 11、valgrind 3.18.1、nginx 1.31.6、`PERF_N=20000`です。Hは同じ実行の`hello`の値で、リクエストあたり11856 Ir、GCを除くと11158 Irになります。

| シナリオ | リクエストあたりのIr。括弧の中はGCを除いた値 | H | リクエストあたりの`non_buffered_calls` |
|---|---|---|---|
| `proxy_plain_2k` | 21952 (21952) | 1.85 | 2.00 |
| `proxy_plain_64k` | 22264 (22264) | 1.88 | 2.00 |
| `proxy_stream_plain_50` | 54294 (54294) | 4.58 | 4.97 |
| `proxy_stream_plain_1000` | 432228 (432228) | 36.5 | 38.43 |
| `auth` | 49132 (46977) | 4.14 | 2.00 |
| `route_json_2k` | 109396 (106246) | 9.23 | 2.00 |
| `route_json_64k` | 1603842 (1600216) | 135.3 | 2.00 |
| `ruby_call_1` | 11404 (10737) | 0.96 | 0 |
| `ruby_call_10` | 41541 (35237) | 3.50 | 0 |

同じ実行での、同じ形のシナリオの間の差は次のとおりです。

- `auth`から`proxy_plain_2k`を引くと、リクエストあたり27180 Irで、GCを除くと25025 Ir、2.3 Hです。これは、2回のHashの検索と3回の変数への代入をするserver rewriteハンドラ1つの分です。
- `route_json_2k`から`proxy_plain_2k`を引くと、87444 Irで、GCを除くと84294 Ir、7.4 Hです。これは、2 KBのボディをパースするaccessハンドラ1つと、変数を使う`proxy_pass`の分です。この`proxy_pass`は、upstreamブロックを名前で探します。
- `route_json_64k`から`proxy_plain_64k`を引くと、1581578 Irで、GCを除くと1577952 Ir、133 Hです。増えた62 KBのボディには、GCを除いて1 KBあたり約24100 Irかかりました。
- Rubyの呼び出しを1回増やすと、`(ruby_call_10 - ruby_call_1) / 9`で3349 Ir、GCを除くと2722 Ir、0.28 Hです。
- Rubyを使わずにストリームのイベントを1つ増やすと、`(proxy_stream_plain_1000 - proxy_stream_plain_50) / 950`で398 Irです。その実行の`non_buffered_calls`は、リクエストあたり4.97と38.43でした。

Responsesのストリームは、2026年10月19日に測りました。`next`の`a466688`をベースにし、シナリオを加えたヘッドと比べて、`test/perf/compare.sh`を1回実行しました。ベースとヘッドはどちらもリリースのビルドで、同じバイナリです。環境は、aarch64のコンテナの中のUbuntu 22.04で、gcc 11、valgrind 3.18.1、nginx 1.31.6、`PERF_N=20000`です。ベースのビルドでは、`hello`はリクエストあたり11618 Irで、GCを除くと11260 Irでした。ほかの結果は次のとおりです。

| シナリオ | リクエストあたりのIr。括弧の中はGCを除いた値 | H | リクエストあたりの`non_buffered_calls` |
|---|---|---|---|
| `proxy_stream_plain_50` | 53674 (53674) | 4.62 | 4.27 |
| `responses_stream_plain_50` | 55710 (55710) | 4.80 | 5.65 |
| `proxy_stream_plain_1000` | 433190 (433190) | 37.3 | 37.20 |
| `responses_stream_plain_1000` | 478098 (478098) | 41.2 | 59.46 |

中継するResponsesのイベントを1つ増やすと、`(responses_stream_plain_1000 - responses_stream_plain_50) / 950`で445 Irかかりました。同じ実行で、Messagesのイベントは399 Irでした。Responsesのストリームのデルタのイベントは186から189バイトで、長さが変わるのは`sequence_number`が大きくなるためです。Messagesのストリームのデルタのイベントは121バイトです。1000のデルタのストリームのボディは、Responsesでは215046バイト、Messagesでは121619バイトです。中継の呼び出しは、リクエストあたりResponsesで59.46回、Messagesで37.20回でした。

その実行では、`proxy_stream_plain_1000`と`route_json_64k`に、ビルドごとに83秒と129秒かかりました。デフォルトのセットのシナリオは、すべて合わせて約140秒です。そのため、この2つは`DEFAULT_SCENARIOS`に入れていません。`responses_stream_plain_1000`も入れていません。これらは`PERF_SCENARIOS`で挙げてください。エージェントプロキシのほかのシナリオはデフォルトのセットに入り、測定の時間はビルドごとに約1分増えます。

### しきい値とキャリブレーション

GCを除いたリクエストあたりのIrがベースより3%以上多いと、シナリオは`WARN`になり、5%以上多いと`FAIL`になります。3%は`PERF_WARN_PERCENT`の値で、5%は`PERF_FAIL_PERCENT`の値です。終了ステータスは、シナリオが`FAIL`のとき、測定が失敗して`ERROR`になったとき、比べたシナリオが1つも無いときに1になります。測定が失敗するのは、次のどれかがあったときです。期待しないレスポンス、`error.log`の`error`以上のレベルの行、タイムアウト、ダンプが無いこと、リクエストを含まないウィンドウです。詳しくは「CIで実行する」にあります。例外は1つだけです。ヘッドが通るのにベースが期待しないレスポンスを返す場合で、ヘッドの機能を必要とするシナリオはこうなります。このとき、レポートはシナリオを`n/a`と示し、実行は失敗になりません。ただし、これはベースの測定でほかに何も問題が起きなかったときだけです。ベースの`error.log`には、リクエストのRubyのコードが例外を起こしたときにngx_mrubyが出す行があってもかまいません。その行は`mrb_run failed: return 500 HTTP status code to client: error: ...`で、ヘッドのRubyのメソッドやクラスを持たないベースは、`NoMethodError`や`NameError`でこの行を出します。`error`以上のレベルのほかの行があると、シナリオは`ERROR`になります。たとえば、LLMのモックが失敗してnginxが502を返したときに、nginxがログに出す`connect()`や`recv()`のエラーです。モックの問題と、1つのログにそのレベルの行が5つより多くあることも、`ERROR`になります。レポートはログごとに5行を示し、残りは読まないからです。ヘッドにしか無いディレクティブがあると、ベースは起動のときに止まります。これも`ERROR`です。

しきい値は、2026年10月3日に、ビルドの入力を変えない変更で確かめました。ビルドの入力が同じ2つのチェックアウトで、`compare.sh`を3回実行しました。チェックアウトは、`next`の`f713d4e`と、`test/`とドキュメントだけを変えるブランチです。環境は、aarch64のコンテナの中のUbuntu 22.04で、gcc 11、valgrind 3.18.1、nginx 1.31.6です。1回目の実行は両方のツリーをビルドし、残りの2回は`ONLY_RUN=1`で同じビルドをもう一度測りました。次のテーブルは、ベースに対するヘッドの変化を、合計とGCを除いた値の順に示します。

| シナリオ | ベースのリクエストあたりのIr。括弧の中はGCを除いた値 | 1回目 | 2回目 | 3回目 |
|---|---|---|---|---|
| `hello` | 11736 (11039) | +0.002% / +0.003% | -0.000% / -0.000% | +0.008% / +0.008% |
| `headers` | 36002 (34025) | +0.002% / +0.002% | -0.002% / -0.002% | +0.000% / +0.000% |
| `var` | 21199 (19700) | -0.000% / -0.000% | +0.000% / +0.000% | +0.000% / +0.000% |
| `filter` | 14010 (13089) | -0.002% / -0.002% | -0.002% / -0.002% | +0.002% / +0.002% |
| `sleep` | 15427 (14654) | -0.006% / -0.007% | -0.002% / -0.002% | +0.000% / +0.000% |
| `sub_request` | 48710 (47538) | -0.003% / -0.004% | -0.001% / -0.001% | -0.001% / -0.001% |
| `file` | 14009 (13075) | +0.002% / +0.002% | +0.000% / +0.000% | -0.002% / -0.002% |

最大の変化は0.008%で、リクエストあたり約1命令です。これは`WARN`の3%の300分の1より小さいので、`N`を上げる必要はありません。後の2026年10月4日の実行では、同じ2つのチェックアウトを新しくビルドし、`sub_request`が+0.076%でした。GCを除いたリクエストあたりのIrは47501と47537です。ほかのシナリオは、どれも0.011%以内でした。2つ目のサーバへプロキシする`sub_request`は、いちばん大きくばらつきます。下に書くとおり、CIのランナーでも同じです。`callgrind_control`を起こす`/status`へのリクエストは、接続を含めて約12500命令かかります。各ウィンドウには、そのうち2つのリクエストの一部が入ります。これは、いちばん小さいウィンドウである`hello`の2億3500万命令の、多くて約0.01%にあたります。

エージェントプロキシのシナリオは、2026年10月4日に、ビルドの入力を変えない変更で確かめました。1つは、同じ種類のaarch64のコンテナで2回測ったもので、9つのシナリオをすべて測りました。9つには、デフォルトのセットから外した2つも入ります。もう1つは、これらのシナリオを加えたプルリクエストの`perf`ジョブで、x86_64のCIのランナーで、デフォルトのセットの7つを測りました。このジョブの実行は37152930938で、ベースは`next`の`f62880c`、ヘッドはマージコミットで、ビルドの入力は変わっていません。次のテーブルは、ベースに対するヘッドの変化を、合計とGCを除いた値の順に示します。

| シナリオ | aarch64で同じビルドを2回。`next`の`4f29b06` | aarch64の`compare.sh`。`next`の`f62880c`とプルリクエスト | x86_64のCIの実行37152930938 |
|---|---|---|---|
| `proxy_plain_2k` | +0.000% / +0.000% | +0.005% / +0.005% | +0.000% / +0.000% |
| `proxy_plain_64k` | +0.005% / +0.005% | +0.009% / +0.009% | -0.110% / -0.110% |
| `proxy_stream_plain_50` | +0.042% / +0.042% | +0.023% / +0.023% | -0.063% / -0.063% |
| `proxy_stream_plain_1000` | +0.004% / +0.004% | +0.007% / +0.007% | 実行していない |
| `auth` | +0.000% / +0.000% | +0.000% / +0.000% | +0.000% / +0.000% |
| `route_json_2k` | +0.000% / +0.000% | +0.000% / +0.000% | -0.000% / -0.000% |
| `route_json_64k` | +0.000% / +0.000% | +0.000% / +0.000% | 実行していない |
| `ruby_call_1` | +0.000% / +0.000% | +0.000% / +0.000% | +0.000% / +0.000% |
| `ruby_call_10` | +0.003% / +0.004% | +0.000% / +0.000% | +0.000% / +0.000% |

upstreamのあるシナリオがいちばん大きくばらつき、`non_buffered_calls`では、そのばらつきの一部しか説明できません。aarch64では、`proxy_stream_plain_50`が最大で0.042%動きました。このときの呼び出しは、ベースとヘッドでリクエストあたり5.01と5.02でした。CIのランナーでは、`proxy_plain_64k`が-0.110%動きました。リクエストあたりのIrは22530と22506で、呼び出しは両方のビルドで1.00でした。`proxy_stream_plain_50`は-0.063%動き、その間に呼び出しは4.86から4.94に増えました。この増加だけで約0.14%増えるはずです。同じジョブの2回目の実行は37156005549で、そのプルリクエストのレビューを反映したコミットで動きました。このときもビルドの入力は変わっていません。この実行では、`proxy_plain_64k`が+0.30%でした。リクエストあたりのIrは22564と22630で、呼び出しは両方のビルドで1.00でした。`proxy_stream_plain_50`は+0.39%で、その間に呼び出しは4.92から5.17に増え、比較はその分を+0.43%と見積もりました。ほかのシナリオは、どれも0.02%以内でした。タイミングで量が変わるほかの仕事は数えていません。たとえば、64 KBのリクエストのボディを何回で読むかです。aarch64で同じビルドを繰り返し実行したときは、GCを除いたリクエストあたりのIrが、`auth`で46797と46977で、差は0.38%でした。`route_json_2k`では106066と106246で、差は0.17%でした。しきい値が比べるのは1回の実行のベースとヘッドの間の変化で、これらの実行での最大は0.39%でした。これは`WARN`の3%の約8分の1です。ランナーでの後の実行でも、upstreamのあるシナリオは0.数%動くことがあります。これらのシナリオの変化が`WARN`に近いときは、リグレッションとみなす前に、2回目の実行と、`non_buffered_calls`の注記が要ります。

この`compare.sh`の実行では、aarch64の両方のビルドで、`test/soak/nginx.conf`の7つのシナリオがウィンドウのチェックに失敗しました。当時、これらのシナリオは`ngx_mrb_run`を数えていて、callgrindはその呼び出しをリクエストごとに2回記録しました。詳しくは「性能の比較に入れたエージェントプロキシのシナリオ」にあります。今は`ngx_mrb_start_fiber`を数えます。2026年10月4日に、同じ種類のコンテナで、ビルドの入力を変えない変更をもう1つ測りました。`compare.sh`のベースは`next`の`45c9e52`で、ヘッドは`test/perf/`とドキュメントだけを変えるブランチです。この測定では、両方のビルドで、7つのシナリオの各ウィンドウに`ngx_mrb_start_fiber`の呼び出しがちょうど20000回ありました。デフォルトのセットのシナリオは、どれも0.017%以内で、最大は`proxy_stream_plain_50`でした。7つのシナリオは0.009%以内でした。

しきい値が働くことを確かめるために、ベースのコピーの`ngx_mrb_run`の先頭に、100回まわる空のループを入れてヘッドにしました。ループのカウンタは`volatile`です。当時の7つのシナリオは、どれもリクエストごとに`ngx_mrb_run`を1回実行します。エージェントプロキシのシナリオは後から加わりました。そのうち`proxy_*`のシナリオはRubyを実行せず、`ruby_call_10`は10回実行します。`ngx_mrb_run`のselfのコストは、どのシナリオでもリクエストあたり604命令増えました。レポートでは、`hello`が+5.47%で`FAIL`になりました。`filter`と`file`が+4.62%、`sleep`が+4.10%、`var`が+3.07%で、これらは`WARN`でした。`headers`は+1.79%、`sub_request`は+1.26%で、これらは`ok`でした。これらの割合は、604命令を各シナリオのGCを除いたリクエストあたりのIrで割った値です。`compare.sh`は1で終了しました。命令の数で言うと、3%は、`hello`ではリクエストあたり約330、`sub_request`では約1430命令です。

CIのランナーでは、`perf`ジョブを加えたプルリクエストのそのジョブが、同じく、ビルドの入力を変えない変更になります。ランナーはx86_64のubuntu-22.04で、バージョンは上と同じです。ベースは`next`の`f713d4e`で、ヘッドはマージコミットでした。このジョブを4回実行し、どの回も両方のツリーをビルドしました。1回目から3回目は、そのプルリクエストの最初のコミットでの、ジョブの実行と2回の再実行です。4回目は、ドキュメントだけを変えた2つ目のコミットで、ジョブを実行しました。

| シナリオ | ベースのリクエストあたりのIr。括弧の中はGCを除いた値 | 1回目 | 2回目 | 3回目 | 4回目 |
|---|---|---|---|---|---|
| `hello` | 11669 (11006) | -0.003% / -0.004% | -0.003% / -0.003% | +0.000% / +0.000% | +0.000% / +0.000% |
| `headers` | 39424 (37267) | -0.002% / -0.002% | +0.000% / +0.000% | +0.000% / +0.000% | +0.000% / +0.000% |
| `var` | 22383 (20706) | +0.000% / +0.000% | +0.000% / +0.000% | +0.000% / +0.000% | +0.000% / +0.000% |
| `filter` | 14569 (13636) | +0.000% / +0.001% | +0.003% / +0.004% | +0.000% / +0.000% | +0.003% / +0.002% |
| `sleep` | 15833 (15068) | +0.006% / +0.006% | +0.000% / +0.000% | +0.001% / +0.001% | +0.002% / +0.002% |
| `sub_request` | 49996 (48854) | +0.001% / +0.001% | +0.016% / +0.016% | -0.001% / -0.001% | +0.020% / +0.021% |
| `file` | 14309 (13360) | +0.002% / +0.002% | +0.000% / +0.000% | -0.002% / -0.003% | +0.000% / +0.001% |

そのプルリクエストのレビューを反映したコミットで、このジョブをさらに2回実行しました。このときも、ビルドの入力は変わっていません。`sub_request`を除くすべてのシナリオは0.007%以内で、`sub_request`は+0.005%と-0.047%でした。`sub_request`のGCを除いたリクエストあたりのIrは、48706と48683です。2026年10月4日までの6回の実行をまとめると、次のとおりです。

- 1回の実行のベースとヘッドの間では、最大の変化は約0.05%で、`sub_request`の約23命令でした。ほかのシナリオは、どれも0.007%以内でした。
- 実行の間では、`sub_request`のGCを除いたリクエストあたりのIrは48683から48857までで、差は0.36%でした。ほかのシナリオは、どれも0.015%以内でした。

ばらつくのは、2つ目のサーバへプロキシする`sub_request`です。その1回の実行の中での最大の変化でも、`WARN`の3%の約60分の1です。ベースとヘッドは同じジョブで続けて測るので、しきい値が見るのは1回の実行の中の変化です。命令セットが違うので、数はaarch64のものと違います。x86_64では、callgrindはGCの入口の関数に再帰のサフィックスを付けません。GCを除いた値から除くコストは、ここでも、`callgrind_annotate`が出す`mrb_incremental_gc`のinclusiveのコストに等しくなります。このジョブは、コードを変えるプルリクエストでも実行されるまで、参考のためのジョブで、`ci-ok`はこのジョブを必要としません。下の「CIで実行する」を参照してください。

### 受け入れ済みの差

同梱のmrubyの次の差は、受け入れ済みです。そのため、後の比較は、この差を含んだ状態を基準に測ります。#678からは、PRのbaseの`next`はmruby 4.1.0-rc2を同梱します。

- mruby 4.1.0-rc2と4.0.0の差です。どちらにも#682のGCのルートのholderを入れて比べ、比較は[#678](https://github.com/matsumotory/ngx_mruby/pull/678)にあります。`auth`のGCを除いたリクエストあたりのIrは、42599から45621へ7.10%増えました。Rubyを使うシナリオでは、GCの割合も増えました。たとえば、`auth`は3.7%から13.5%に、`headers`は6.6%から20.9%になりました。ほかのシナリオは、GCを除いた値で`WARN`より下でした。
  - GCを除いた値が増えたのは、mruby 4.1のVMとコアが、同じバイトコードをより多くの命令で実行するからです。`auth`では、mruby自身の関数で、リクエストあたり約2260 Ir増えました。原因は3つあります。1つ目は2-wayのメソッドキャッシュで、リクエストごとに探索で見つけるメソッドが、4.0.0の17個から22個に増えました。2つ目は、Stringのキーで`Hash`を引くときに`obj_eql`を通ることです。3つ目は、Cのメソッドの引数のパースが、さらに分かれたことです。どれもmruby 4.1の作りで、不具合として知られているものはありません。
  - GCの割合が増えたのは、ヒープに空きのスロットが無いときの動作が変わったからです。mruby 4.1は、前回のマークで空きができていれば、ヒープのページを足す代わりにフルGCを実行します。これはmrubyのコミット`c009f1633`の変更で、小さな固定のアリーナで動くターゲットのヒープを抑えるためのものです。コミットの題は「gc: try to reclaim before growing the object heap」です。ngx_mrubyのワーカーは、1024スロットのページ2つに、生きているオブジェクトを約1100個持ちます。そのため、インクリメンタルGCが始まる前にヒープの空きが尽き、そのたびにフルGCが動きます。
  - `GC.interval_ratio`を変えても、この動作は変わりません。ヒープを大きくすると、GCの割合は0〜3%になります。大きくするには、`MRB_HEAP_PAGE_SIZE`を4096にするか、起動時に`mrb_gc_add_region()`でページを足します。しかし、多くのシナリオでGCを除いた値が増え、増え方は最大で17%でした。測定は#678にあります。ngx_mrubyは、mrubyのデフォルトのままにします。
- オーナーは、2026年10月31日にこれらの差を受け入れました。記録は#678と`docs/HANDOFF.md`にあります。

baseが同梱するmrubyがheadより古い比較では、このような差がまた測られます。#678より前の`next`のコミットをbaseにすると、上のmruby 4.0.0との差が出ます。タグの前に前のタグと比べるときも、baseは古くなります。その比較は、AGENTS.mdの「Design principles」にあります。v3の最初のプレリリースの前は、baseはmruby 3.3.0を同梱する`v2.7.2`です。mruby 3.3と4.1の差を扱う行はファイルに無いので、その比較の`WARN`と`FAIL`の行は、規則のとおりオーナーに確かめます。

`test/perf/accepted.txt`には、受け入れ済みの差を1つずつ1行に書きます。行には、条件、シナリオ、GCを除いたリクエストあたりのIrの変化の許容幅を、パーセントで書きます。条件は`mruby-version`だけです。この条件は、各ビルドのツリーの`mruby/include/mruby/version.h`にある`MRUBY_RELEASE_MAJOR`と`MRUBY_RELEASE_MINOR`から作る`MAJOR.MINOR`を比べます。書式は、ファイルの先頭のコメントにあります。`mruby-version 4.0 4.1 auth 8`は、baseがmruby 4.0.xを、headが4.1.xを同梱するときに当てはまります。

行が当てはまるのは、両方のビルドが条件に合うときだけです。そのとき、許容幅に収まる`WARN`か`FAIL`のシナリオの行は、`ok (accepted: mruby 4.0.0→4.1.0, +8%)`と表示されます。この行は実行を失敗させず、ジョブのアノテーションのnoticeになります。許容幅を超える変化は、`WARN`か`FAIL`のままです。`report.txt`のヘッダの1行と、ジョブのサマリーのテーブルの下の1行には、両方のビルドのmrubyのバージョンと、当てはまった差を出力します。たとえば`perf: mruby: base 4.0.0, head 4.1.0; accepted differences (accepted.txt): auth up to +8% (mruby 4.0.0→4.1.0)`で、当てはまる差が無ければ`none apply`です。`perf.rb`は、測る前にこのファイルを読み、書式に合わない行があると、ファイルと行の番号を示して止まります。`--self-test`もこのファイルを確かめます。GCの割合は出力するだけで判定しないので、ファイルにはGCの割合の許容幅の行がありません。

### 実行する

ドライバには、CRuby 3.0以降と、`callgrind_control`とその補助の`vgdb`を持つvalgrindが要ります。`callgrind_control`と`vgdb`はLinuxで動きます。これらが無いと、`perf.rb`はすぐに止まります。macOSでは、Linuxのコンテナの中で実行してください。このチェックアウトを`origin/next`とコンテナの中で比べるには、次の1つのコマンドを実行します。

```console
$ rm -rf build_perf/base-src && git archive --prefix=build_perf/base-src/ origin/next | tar -x && docker run --rm -v "$PWD":/work -w /work ubuntu:22.04 sh -c 'apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y build-essential rake ruby bison git gperf wget ca-certificates zlib1g-dev libpcre3-dev libssl-dev valgrind >/dev/null && sh test/perf/compare.sh build_perf/base-src'
```

Linuxでは、次のように実行します。

```console
$ sh test/perf/compare.sh build_perf/base-src          # build both, then compare
$ ONLY_RUN=1 sh test/perf/compare.sh build_perf/base-src
$ ONLY_RUN=1 PERF_SCENARIOS=hello,var sh test/perf/compare.sh build_perf/base-src
$ sh test/perf/run.sh                                  # measure this checkout only
```

`compare.sh BASE_DIR [HEAD_DIR]`は、`BASE_DIR`を`build_perf/base`に、`HEAD_DIR`を`build_perf/head`にビルドします。`HEAD_DIR`のデフォルトはこのチェックアウトです。どちらのビルドでも、サードパーティのgemは、そのツリーにコミットした`build_config.rb.lock`のコミットです。そのため、gemが違うのはヘッドがロックを変えたところだけです。gemを別のコミットへ動かすプルリクエストは、マージしたときと同じく、そのコミットで測ります。ロックの無いチェックアウトは、反対側のロックを使います。ロックをコミットする前のチェックアウトがこれに当たります。ベースはヘッドのロックを、ヘッドはベースのビルドが書いたロックを使います。レポートは、コミットの違うgemの数を示し、その一覧を出します。測定に使う`test/perf/`と`test/soak/`のシナリオは、両方のビルドとも、このチェックアウトのものです。最初の実行は2つのツリーをビルドし、それぞれ数分かかります。デフォルトのシナリオの測定は、ビルドごとに約140秒かかります。CIのランナーでは139秒で、そのうち28秒が`sleep`です。`PERF_SCENARIOS`で`proxy_stream_plain_1000`と`route_json_64k`を挙げると、それぞれ約80秒と130秒が加わります。レポートは`build_perf/report.txt`と`build_perf/report.json`に書きます。`test.sh`も12372でLLMのモックのupstreamを起動するので、同時に実行しないでください。

| 変数 | デフォルト | 意味 |
|---|---|---|
| `ONLY_RUN` | 未設定 | 設定するとビルドを飛ばす |
| `NUM_THREADS_ENV` | CPUの数の半分 | ビルドの並列数。`build.sh`へそのまま渡す |
| `PERF_SCENARIOS` | `test/perf/perf.rb`にある`DEFAULT_SCENARIOS` | カンマで区切ったシナリオの名前 |
| `PERF_N` | 20000 | 測るウィンドウのリクエストの数 |
| `PERF_WARMUP` | 2000 | ウィンドウの前のリクエストの数 |
| `PERF_WARN_PERCENT` | 3 | GCを除いたリクエストあたりのIrがこの割合以上変わるとWARN |
| `PERF_FAIL_PERCENT` | 5 | この割合以上変わるとFAIL |
| `PERF_PORT_BASE` | 12370 | シナリオのポート。`sub_request`のバックエンドは次のポートを、LLMのモックはさらにその次のポートを使う |
| `PERF_REPORT_DIR` | `build_perf` | `report.txt`と`report.json`を書くディレクトリ |
| `PERF_ACCEPTED_FILE` | `test/perf/accepted.txt` | 受け入れ済みの差を記録するファイル。空のファイルなら適用前の判定を表示 |
| `PERF_REQUEST_FUNCTIONS` | `ngx_mrb_start_fiber` | `test/soak/nginx.conf`の7つのシナリオで、リクエストごとに1回と数える関数の名前。「CIで実行する」を参照 |

### CIで実行する

`.github/workflows/test.yml`の`perf`ジョブは、ビルドするreadyのPRで始まります。ビルドするのは、[実行するジョブの選択](#実行するジョブの選択)で`build`が`standard`か`full`になるPRです。比べるのは、`test/ci/changes.sh`が`perf`を`true`にするときです。つまり、PRが測るバイナリの入力か測定を変えるときか、PRにラベル`perf`があるときです。ラベルはジョブが動くときに読むので、ラベルを付けてジョブを再実行すれば足ります。これらのファイルのうち`test.yml`だけを変えるPRは、ラベルがあるときだけ比べます。コードとテストのどれも変えないPRは、ラベルがあってもジョブをスキップします。バイナリの入力は、`test/build_release.sh`がコピーするものです。`src/`、`mrbgems/`、`mruby/`、`dependence/`、トップレベルのビルドのファイルの`build_config.rb`、`configure`、`config.in`、`Makefile.in`、`build.sh`、`nginx_version`と、gemのロックの`build_config.rb.lock`です。`dependence/`は、`Makefile.in`がnginxに加えるngx_devel_kitです。測定は、`test/perf/`、`test/build_release.sh`、`test/soak/`のシナリオのファイルです。シナリオのファイルは、`nginx.conf`、`nginx.agent.conf`、`scenarios.rb`、`http_client.rb`、`mock_llm.rb`、`handlers/`です。`master`のジョブも同じで、違いは2つです。`master`はgemのロックをコミットしないので、`master`ではロックは入力ではありません。また、`master`にはソークのジョブが無いので、`master`の`perf`ジョブは、`next`では`test/soak/run.sh`が実行するLLMのモックのチェックを最初に実行します。そのチェックは`ruby test/soak/mock_llm_test.rb`です。`next`で`test/soak/mock_llm_test.rb`を変えると`soak`が真になり、`soak`ジョブがその検査を実行します。`master`には`soak`ジョブがないため、このファイルだけの変更ではラベル`perf`がある場合だけ実行します。

`nginx_version`を変えると、ヘッドは別のnginxでビルドされます。そのため、その`WARN`や`FAIL`には、ngx_mrubyのコストだけでなく、nginx自身のコストも入ります。ngx_mrubyのリグレッションとみなす前に、下に書くとおり、プロファイルの関数を読んでください。

プルリクエストのチェックアウトは、マージコミットの`refs/pull/N/merge`です。ジョブは、その1つ目の親であるベースブランチとマージコミットを比べます。そのため、差は、マージしたときのプルリクエストの変更になります。テーブルはジョブのサマリーにあり、その下に失敗した測定の理由があります。`WARN`、`FAIL`、`ERROR`、`n/a`のシナリオと、シナリオを1つも比べなかった実行は、アノテーションになります。ジョブは`FAIL`と`ERROR`で失敗します。測定は、次のときに失敗して`ERROR`になります。nginxが起動しないか応答しないとき、`callgrind_control`が失敗するかタイムアウトしたとき、ダンプが無いとき、`error.log`に`error`以上のレベルの行があるとき、ウィンドウがリクエストを含まないときです。ウィンドウがリクエストを含まないとは、Irが0のときか、シナリオのリクエストの関数の呼び出しが期待した数でないときです。期待する数は、`test/soak/nginx.conf`の7つのシナリオでは、リクエストごとにちょうど1回の`ngx_mrb_start_fiber`の呼び出しです。エージェントプロキシのシナリオでは、「性能の比較に入れたエージェントプロキシのシナリオ」のテーブルにある関数と回数です。vgdbがプロセスに届かなかったときも`callgrind_control`は「OK.」と出力するので、空のウィンドウはここで見つかります。`n/a`になるのは、ベースがシナリオに期待しないレスポンスを返し、ngx_mrubyの`mrb_run failed`の行のほかに問題が無いときだけです。これは、ヘッドの機能を必要とするシナリオで起きます。性能の比較の[しきい値とキャリブレーション](#しきい値とキャリブレーション-1)を参照してください。比べるシナリオが1つも無かった実行は失敗になります。

リクエストの関数の呼び出しは、名前で数えます。GCCが`-O2`で作る関数のコピーは、元の関数として数えます。コピーとは、`ngx_mrb_start_fiber.part.0`、`.isra.0`、`.constprop.0`、`.cold`のようなものです。あるコピーから別のコピーへの呼び出しは1回と数えます。そのため、GCCが関数を分割したりクローンしたりするようになる変更でも、ウィンドウのチェックは失敗しません。次の2種類のプルリクエストは、`test/perf/perf.rb`の`REQUEST_FUNCTIONS`に新しい名前を加え、古い名前を残す必要があります。`ngx_mrb_start_fiber`の名前を変えるプルリクエストと、Rubyの実行のfiberを始める処理を別の関数へ移すプルリクエストです。ヘッドの`perf.rb`はベースも測り、一覧にある2つの名前の間の呼び出しは1回と数えるからです。今は、GCCは`ngx_mrb_start_fiber`をインライン化できません。この関数は`ngx_http_mruby_async.c`で定義し、`ngx_http_mruby_module.c`から呼んでいるからです。コンパイラがこの関数をインライン化できるようにする変更では、プロファイルにこの関数の呼び出しが残りません。たとえば、ただ1つの呼び出し元のファイルの中でこの関数を`static`にする変更や、LTOでのビルドです。そうなると、7つのシナリオのウィンドウは、どれも呼び出しが0回になります。そのため、そうした変更では、実際の呼び出しが残る関数を一覧に挙げる必要があります。ローカルの実行では、カンマで区切った`PERF_REQUEST_FUNCTIONS`で一覧を上書きできます。`REQUEST_FUNCTION_CALLS`ではシナリオのリクエストあたりの呼び出しの数を、`SCENARIO_REQUEST_FUNCTIONS`ではシナリオの関数を、別のものに設定します。`ruby test/perf/perf.rb --self-test`は、名前の規則とプロファイルの読み方を、用意した架空のプロファイルで確かめます。ビルドもvalgrindも要りません。`compare.sh`と`run.sh`は、最初にこれを実行します。

このジョブは、今は参考のためのジョブです。`ci-ok`はこのジョブを必要としないので、`FAIL`でもマージは止まりません。上のキャリブレーションのとおり、命令の数はランナーの速さで変わりません。そこで、`docs/proposals/v3-plan.md`のPillar Eの計画では、命令の数でマージを止めることにしています。`src/`か`mrbgems/`を変えるプルリクエストでもこのジョブが誤検知なしに動いたら、このジョブを`ci-ok`の`needs`に加える計画です。

アーティファクトの`perf-callgrind`には、レポートがあります。また、`base`と`head`のそれぞれについて、ウィンドウのプロファイル、`callgrind_control`とvalgrindの出力、nginxのログがあります。プロファイルは`callgrind/callgrind.out.<scenario>`です。変化がどこから来たかを見るには、同じシナリオの関数を両方のビルドで出力して比べます。

```console
$ callgrind_annotate --inclusive=yes build_perf/head/callgrind/callgrind.out.var | head -40
$ callgrind_annotate build_perf/base/callgrind/callgrind.out.var > base.txt
$ callgrind_annotate build_perf/head/callgrind/callgrind.out.var > head.txt
$ diff base.txt head.txt
```

数はウィンドウ全体の値です。1つのリクエストの値は、`PERF_N`で割って求めます。プロファイルは、KCachegrindやQCachegrindでも開いて読めます。


## サイトCIの検査範囲

この節では、`.github/workflows/site.yml`のブラウザの検査を説明します。`test.yml`は上で説明しました。

### 所要時間

ブラウザの系統に分ける前は、サイトのビルドのジョブ1つが、すべての検査を実行していました。[実行41135116891](https://github.com/matsumotory/ngx_mruby/actions/runs/41135116891/job/124345060406)は26分04秒かかりました。内訳は、computed styleの検査が10分56秒、トップページとコードの操作の検査が4分45秒、日本語の行の検査が2分13秒、スクリーンショットが2分06秒、ブラウザのインストールが2分02秒です。

下の系統に分けた後、`29cf75611`の[実行41173244320](https://github.com/matsumotory/ngx_mruby/actions/runs/41173244320)は、buildのジョブの開始から`site-ok`の終了まで17分58秒かかりました。この時間には、ランナーを待つ時間も入ります。いちばん長いブラウザのジョブは459秒でした。2つの実行はソースもランナーも違うので、この差は条件をそろえた測定ではありません。また、並列のジョブの時間を足しても、全体の経過時間にはなりません。同じ実行のChromiumでは、`check-styles.mjs`が25ページに209.651秒かかり、ページの読み込みは250回でした。対象を絞った実行が選ぶインストールの2ページでは20.101秒で、読み込みは20回だけでした。

### ブラウザ検査の範囲と並列化

サイトは、ビルドとすべての静的な検査を1回だけ実行します。ブラウザの検査は、同じ実行の`site-validation`アーティファクトを使います。このアーティファクトには、ビルドしたHTMLと生成したmanifestが入ります。別のコミットの結果をキャッシュとして使うことはありません。アーティファクトには、サイトとv2のソースのリビジョン、ソースがcleanかどうか、lockfileのハッシュ、ワークフローの実行が結び付いています。リビジョン、dirtyなビルド、lockfile、実行、アーティファクトのdigestのどれかが合わないと、検査は失敗します。

`ci-plan.mjs`は、PRの範囲と、新しく生成したmanifestを使います。PRの範囲は、マージコミットとその1つ目の親の差です。`next`でデプロイするpushと`workflow_dispatch`は、いつも全範囲を検査します。前のpushからの範囲だけを見ると、実行が失敗したかキャンセルされたpushのページが、一度も検査されないまま残るからです。

PRでは、`docs/`の下の既存の通常のMarkdownの変更なら、検査するページを絞れます。絞れるのは、ジェネレーター自身のsatteriのパーサーで、次の契約が変わっていないと確かめられたときです。契約は、タイトル、タイトルの削除、見出しの階層と文言、コード、インラインのコード、HTML、frontmatterです。絞ったときも、英語と日本語の両方のルートを検査します。`/ja/`の下で英語の本文を表示するページ、つまり`site/scripts/lib/site.mjs`の`GENERATED_REFERENCE`と`NOT_TRANSLATED_YET`のページでは、全範囲の実行と同じく、日本語の行の検査は注記だけを測ります。こうすると、Markdownを正規表現で近似せずに、実際の文書の本文とリンクの変更を絞って検査できます。

次の変更では、全範囲を検査します。これらの契約の変更、ファイルの追加、削除、rename、MDX、共有のCSS、レイアウト、ジェネレーター、依存関係、ワークフローの変更、未知の入力、証拠が得られない場合です。リポジトリの最上位のAGENTS.md、CLAUDE.md、README.mdだけを変えるPRでは、3.xのページのブラウザの検査は要りません。静的な検査は、それでもすべて実行します。

PRでは、buildのジョブは、`test/ci/changes.sh`でもマージコミットとbaseの差を分類します。分類は[実行するジョブの選択](#実行するジョブの選択)にあります。6つのブラウザの系統とmaintenanceの系統が動くのは、`site`が`true`のときか、`docs`が`true`で上の計画が`full`か`targeted`のときです。`site`が`true`になるのは、`site/`か`site.yml`を変えたときです。`src/`、`test/`、`build_config.rb`、`examples/`を変え、`site/`と`docs/`のファイルを変えないPRは、ビルドとすべての静的な検査を実行し、ブラウザの検査は実行しません。reference、sample、トップページの静的な検査は、これらのファイルを読むからです。pushとdispatchは、すべての系統を実行します。DraftのPRでは、このワークフローのジョブは動きません。readyにすると実行が始まります。

ブラウザの系統は、互いに独立して動く次のジョブです。

- Chromiumのスタイルの検査とWebKitのスタイルの検査。前と同じviewport、テーマ、motionの範囲を、別々のジョブで、それぞれ検査します。
- 3.xのトップページの操作とコードのレイアウトの検査。文書の変更で対象を絞ったときは、影響を受けるページのコードだけを検査します。その場合、トップページは変わっていないので、トップページの操作は検査しません。
- 日本語のページの行の検査。
- focus、言語のリンク、Lighthouseのアクセシビリティの検査。
- スクリーンショット。全範囲では代表のページを撮り、対象を絞ったときは選んだすべてのページを撮ります。どちらも、両方のエンジン、両方のテーマ、320、390、1440 pxの幅で、viewportとページ全体を撮ります。全範囲では、この系統は最初に`check-project-badges.mjs --browser`で、フッターのOpenSSF Best Practicesのバッジを375 pxで確かめます。対象は、Chromiumでは`/`と`/v2/ja/`のライトとダーク、WebKitでは`/ja/`です。

フッターのバッジは、サイトで唯一の、別のoriginの画像です。読み取り専用のbrowser contextは`scripts/lib/read-only-browser.mjs`にあり、同じoriginへのGETだけを許します。呼び出す側は画像のURLを正確に指定でき、そのURLへのGETには、ネットワークの代わりにローカルのfixtureで答えます。デプロイの前の検査の`check-project-badges.mjs`、`check-home-interaction.mjs`、`screenshots-live.mjs`は、バッジのURLに`scripts/lib/project-badges.mjs`の代わりの画像で答えます。そのため、bestpractices.devが遅いか止まっていても、公開は止まりません。本物の画像を取得するのは、デプロイの後の`check-live.mjs`だけです。`check-live.mjs`は、問題を報告する前に3回再試行します。

v2の入力は`master`から別に取得するので、**`next`の差分から、v2が変わっていないとは判断しません**。maintenanceの系統は、2.xの日本語の行、v2のすべてのコードの表示、両方のバージョンの検索のindexを検査します。この系統は、すべてのpushとdispatchで動き、PRではブラウザの系統が動くときに動きます。この系統には、公開のワークフローにあった、読み取り専用のbrowserのfixtureの検査と、デプロイの前のローカルのsmokeのスクリーンショットも残っています。トップページのcopy-idleの検査は、全範囲の操作の検査に残っています。デプロイの後の確認も残っています。3.xとv2のコードの検査を全範囲で合わせると、以前の1つのスイートと同じになることを、テストで確かめます。アサーション、viewport、エンジンは、どれも減らしていません。CIの範囲の指定なしにスクリプトを直接起動すると、元の全範囲で動きます。

`site-ok`は、Draftを除いて、`!cancelled()`で動きます。`site-ok`が成功するのは、buildが成功し、さらに、すべてのブラウザの系統とmaintenanceの検査が成功したときか、それらがスキップされたときです。スキップしてよいのは、buildのジョブが、PRにブラウザは要らないと判定し、`browser`を`false`にしたときです。そのほかの理由のスキップと、キャンセル、欠落、失敗したジョブがあると、`site-ok`は失敗し、公開できません。実行そのものがキャンセルされると、`site-ok`は動かず、GitHubはcancelledにします。[必須のステータスチェック](#必須のステータスチェック)を参照してください。`deploy`は、buildとこのゲートの両方を必要とします。範囲がnoneのブラウザのジョブも、アーティファクトを確かめた後に、仕事が無いことを示す成功を明示して返します。失敗した依存のジョブを、黙って迂回することはありません。独立したレビューでは、関係する回帰のスイートを実行し直し、関係の無い成果物まですべてをビルドし直すことはしません。

```sh
cd site
node scripts/test-ci-scope.mjs
node scripts/test-ci-browser.mjs
node scripts/test-ci-integration.mjs
```

契約のテストは、次の場合を含みます。実際のGitの範囲、renameとmodeの変更、Markdownのパースの反例、正確なバージョンの範囲、ワークフローの接続、古い、dirtyな、別の実行の、lockfileの違う、v2の違うアーティファクトの拒否です。`measure_scope=true`を付けた手動の`site`のdispatchと、CIの方針かスクリプトを変えるPRでは、全範囲のスタイルの系統が通った**後**に、同じビルドで2ページのChromiumのスタイルの比較を加えます。この比較は、必須の全範囲の検査の代わりにはなりません。各系統は、スクリプトを測った秒数と、選んだページを、ジョブのサマリーに書きます。比べるのは、並列のジョブの時間の合計ではなく、ワークフロー全体の実際のcritical pathです。

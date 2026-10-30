# エージェントプロキシ

**開発版です。** このページは、まだリリースしていないブランチ`next`のngx_mruby 3.xを説明します。現在のリリースは2.7です。下のレシピは現在の`next`で動き、CIが確かめています。図は、v3の計画に沿ってv3.0.0に向けて作るエージェントプロキシを示します。図の各ステップには、現在動くか、[計画](../../proposals/v3-plan.md#agent-proxy-the-v30-use-case)のどのステップで加わるかを書いています。

エージェントプロキシは、LLMのプロバイダが提供するAPIの前に置くnginxです。このnginxは、コーディングエージェントとプロバイダの間に入ります。Rubyは、リクエストごとに次の3つを決めます。クライアントのキーが既知か、リクエストがどのupstreamとどのプロバイダの認証情報を使うか、`limit_conn`が数えるキーは何かです。バイトを運ぶのはnginxです。nginxはリクエストを読み、プロバイダのレスポンスを届くたびに中継し、nginx自身のモジュールの制限をかけます。このプロキシは、Anthropic Messages APIの`/v1/messages`と、OpenAI Responses APIの`/v1/responses`を、server-sent eventsのストリームのレスポンスも含めてそのまま通します。2つのAPIの間で形式の変換はしません。

<a id="implementation-status-and-the-v3-target"></a>

## 実装状況と<wbr>v3の完成像

以下の図はv3の完成予定の構成です。状態の意味を次に示します。

- `implemented`：`next`に存在します。2.7でリリース済みとは限りません。
- `planned`：合意済みの計画です。APIや実行可能な例は、まだ提供していません。
- `under-design`：詳細が未決定です。文書に構想を載せても、実装済みの契約にはなりません。

<a id="nextに実装済みリクエストの規則"></a>

### 実装済み：認証と振り分け

利用者キーの検査、キーごとの同時リクエスト制限、モデル振り分け、認証情報の差し替えは実装済みです。[ローカルの試用](../start/README.md#modelで転送先を選ぶ)で振り分けとキーの差し替えを確認できます。以下の完全なレシピは[`agent_proxy.rb`](../../../test/t/cases/agent_proxy.rb)が検証します。

<a id="nextに実装済みストリーム中継"></a>

### 実装済み：ストリーム中継

結合テストはmock upstreamを使い、Messages/Responsesのバイト列とupstreamエラーを保つ中継を確認します。実プロバイダとの相互運用や、API形式の変換を保証するものではありません。

<a id="計画中使用量の計上とストリーム制御"></a>

### 計画：計上とストリーム制御

共有使用量の計上、イベント分割・フィルタ、初回バイトの期限は計画7a・7b・7cの対象です。図は予定する配置を示します。アプリにコピーして使えるAPIは未実装です。

<a id="計画中プロバイダとの通信方針"></a>

### 計画：プロバイダ通信

プロバイダ別のHost/SNI、フォールバック方針、参照プロキシの通信境界は計画7eの対象です。以下のリクエスト・エンドポイント図と[v3の計画](../../proposals/v3-plan.md#agent-proxy-the-v30-use-case)を参照してください。

安定版2.7の文書は現在の挙動を説明します。予定しているv3のAPIを2.7の設定へコピーしないでください。将来のAPIの例は、実装と対応するテストが入るまで、実行可能であることの証拠にはしません。

## 現在<wbr>動く<wbr>レシピ

次に示す設定は、同じレシピで、両方のAPIを処理します。プロキシの後ろには、2つのAPIのモックがあります。モックは`test/soak/mock_llm.rb`で、テストのクライアントがポート12372と12373で起動します。

- server rewriteハンドラの`agent_proxy_auth.rb`は、`Authorization`の`Bearer`か`x-api-key`から、クライアントのキーを探します。既知でないキーには401を返します。nginxは、`error_page 401 @agent_proxy_401`に従って、そのレスポンスにAPIのエラーの形式のJSONのボディを付けます。このリクエストはupstreamに届かずに終わります。
- クライアントのキーごとに数える`limit_conn`は、同時に1つのリクエストだけを許します。1つ目のレスポンスがストリームで届いている間に同じキーで送った2つ目のリクエストには、JSONのボディと`retry-after`の付いた429が返ります。この429は、どのupstreamも送らないステータス460を経由して返すので、upstream自身の429はそのまま通ります。
- accessハンドラの`agent_proxy_route.rb`は、JSONのボディの`model`を読んでupstreamブロックを選び、クライアントの認証情報の代わりにupstreamが受け取る認証情報を設定します。upstreamの無いモデルには403を返します。
- `proxy_buffering off`にした`proxy_pass`は、レスポンスを届くたびに中継します。529のようなupstreamのエラーは、ボディとともにクライアントに届きます。
- logハンドラの`agent_proxy_log.rb`は、リクエストごとに、キーのidと`$upstream_status`を1行に書きます。

```sample
label: development
case: test/t/cases/agent_proxy.rb
conf: test/conf/conf.d/60-agent-proxy.conf
script: test/html/agent_proxy_auth.rb
script: test/html/agent_proxy_route.rb
script: test/html/agent_proxy_log.rb
compared: test/html/agent_proxy_auth.expected
compared: test/html/agent_proxy_route.expected
compared: test/html/agent_proxy_limit.expected
compared: test/html/agent_proxy_log.expected
```

テストのクライアントの`test/t/cases/_agent_proxy_client.rb`は、各レシピのリクエストを`/v1/messages`へ送り、値を1行に1つずつ出力します。上のファイルは、Messages APIについてケースが比べる値です。ケースは`/v1/responses`でも同じレシピを比べ、各APIの50個のデルタのストリームが1バイトも違わずに届くことも確かめます。

## v3.0の<wbr>リクエスト

```diagram
agent-proxy-request
label: development
caption: v3.0のエージェントプロキシを通るリクエストのステップを、それぞれが現在動くか、v3の計画のどのステップで加わるかとともに示します。
source: docs/proposals/v3-plan.md 407-447 558-576
source: test/conf/conf.d/60-agent-proxy.conf 14-111
at: 8d1500bf0 2026-10-29
leg-now: 現在：<wbr>`next`で<wbr>動き、<wbr>`agent_proxy.rb`が<wbr>確かめる
leg-next: ステップ4：<wbr>v3の<wbr>計画の<wbr>次の<wbr>ステップ
leg-later: ステップ7aから7e：<wbr>v3の<wbr>計画の<wbr>後の<wbr>ステップ

key: 現在：<wbr>server rewriteハンドラが<wbr>クライアントの<wbr>キーを<wbr>確かめる。<wbr>既知でない<wbr>キーには<wbr>JSONの<wbr>ボディの<wbr>401
limit: 現在：<wbr>クライアントの<wbr>キーごとの<wbr>`limit_conn`。<wbr>同じ<wbr>キーの<wbr>2つ目の<wbr>ストリームには<wbr>429
route: 現在：<wbr>accessハンドラが<wbr>ボディの<wbr>`model`で<wbr>振り分け、<wbr>認証情報を<wbr>差し替える。<wbr>既知でない<wbr>モデルには<wbr>403
budget: ステップ7aと7b：<wbr>キーの<wbr>トークンと<wbr>金額の<wbr>予算を<wbr>共有ディクショナリに<wbr>置く。<wbr>`body_json`が<wbr>Cで<wbr>`model`を<wbr>読む
upstream: 現在：<wbr>`proxy_pass`が、<wbr>選んだ<wbr>upstreamへ、<wbr>プロバイダの<wbr>認証情報で<wbr>リクエストを<wbr>中継する
overloaded: 現在：<wbr>upstreamの<wbr>529は、<wbr>ボディとともに<wbr>クライアントに<wbr>届く
fallback: ステップ7e：<wbr>参照実装の<wbr>プロキシが<wbr>プロバイダごとに<wbr>Hostと<wbr>SNIを<wbr>設定し、<wbr>`error_page 529 = @name`で<wbr>529に<wbr>なった<wbr>リクエストを<wbr>別の<wbr>プロバイダへ<wbr>送る
```

## v3.0の<wbr>ストリームの<wbr>レスポンス

```diagram
agent-proxy-stream
label: development
caption: v3.0のエージェントプロキシがストリームのレスポンスをどう中継し、使用量をどう計上するかを、各ステップが現在動くか、v3の計画のどのステップで加わるかとともに示します。
source: docs/proposals/v3-plan.md 407-447 558-576
source: test/conf/conf.d/60-agent-proxy.conf 44-55
at: 8d1500bf0 2026-10-29
leg-now: 現在：<wbr>`next`で<wbr>動き、<wbr>`agent_proxy.rb`が<wbr>確かめる
leg-next: ステップ4：<wbr>v3の<wbr>計画の<wbr>次の<wbr>ステップ
leg-later: ステップ7aから7e：<wbr>v3の<wbr>計画の<wbr>後の<wbr>ステップ

deadline: ステップ7c：<wbr>最初の<wbr>バイトの<wbr>期限で、<wbr>ヘッダを<wbr>送らない<wbr>プロバイダを<wbr>打ち切る。<wbr>`proxy_read_timeout`は<wbr>アイドルの<wbr>タイムアウトのまま
relay: 現在：<wbr>nginxが<wbr>プロバイダの<wbr>イベントを、<wbr>届くたびに、<wbr>1バイトも<wbr>変えずに<wbr>中継する
frame: ステップ7b：<wbr>イベントフィルタが<wbr>Cで<wbr>イベントを<wbr>区切り、<wbr>一覧に<wbr>ある<wbr>イベントごとに<wbr>Rubyを<wbr>1回<wbr>呼ぶ
usage: ステップ7b：<wbr>Rubyが<wbr>`message_start`と<wbr>`message_delta`、<wbr>または<wbr>最後の<wbr>`response.*`イベントから<wbr>使用量を<wbr>読む
charge: ステップ7a：<wbr>レスポンスが<wbr>終わるか<wbr>切れたときに、<wbr>共有ディクショナリの<wbr>カウンタに<wbr>計上する
log: ステップ4：<wbr>logハンドラが<wbr>`access_log`の<wbr>前に<wbr>動き、<wbr>その後で<wbr>`access_log`が<wbr>費用と<wbr>トークンを<wbr>ログに<wbr>書く
```

## v3.0の<wbr>エンドポイント

```diagram
agent-proxy-endpoints
label: development
caption: v3.0のエージェントプロキシが自分で答えるもの、そのまま通すもの、拒否するものを、リクエストの種類ごとに示します。それぞれ現在動くか、v3の計画のどのステップで加わるかも示します。
source: docs/proposals/v3-plan.md 424-447
source: test/conf/conf.d/60-agent-proxy.conf 93-110
at: 8d1500bf0 2026-10-29
leg-now: 現在：<wbr>`next`で<wbr>動き、<wbr>`agent_proxy.rb`が<wbr>確かめる
leg-next: ステップ4：<wbr>v3の<wbr>計画の<wbr>次の<wbr>ステップ
leg-later: ステップ7aから7e：<wbr>v3の<wbr>計画の<wbr>後の<wbr>ステップ

own-errors: 現在：<wbr>プロキシが<wbr>401と<wbr>429を<wbr>JSONの<wbr>ボディで<wbr>自分で<wbr>返し、<wbr>403を<wbr>nginxの<wbr>エラーページで<wbr>返す
models: ステップ7cと7e：<wbr>クライアントの<wbr>モデルの<wbr>許可リストから<wbr>答える<wbr>`GET /v1/models`と、<wbr>最初の<wbr>バイトの<wbr>期限の<wbr>後の<wbr>504
pass: 現在：<wbr>`POST /v1/messages`と<wbr>`POST /v1/responses`は、<wbr>ストリームも<wbr>含めて<wbr>そのまま<wbr>通る
upstream-errors: 現在：<wbr>upstreamの<wbr>エラーは、<wbr>ボディとともに<wbr>クライアントに<wbr>届く
upgrade: ステップ7e：<wbr>参照実装の<wbr>プロキシは、<wbr>Responses APIの<wbr>WebSocketの<wbr>トランスポートである<wbr>`Upgrade`を<wbr>拒否する
```

エージェントプロキシの計画、プロトコルの範囲、ステップの順は、v3の計画の[Agent proxy: the v3.0 use case](../../proposals/v3-plan.md#agent-proxy-the-v30-use-case)にあります。計画した機能のサンプルは、その機能とテストがマージされたときにこのページに載ります。

## リクエスト<wbr>あたりの<wbr>コスト

perfのレーンの`test/perf/compare.sh`は、nginxがリクエストごとに実行する命令の数を、callgrindで数えます。`test/soak/handlers/`にあるレーンのハンドラの`agent_auth.rb`と`agent_route.rb`は、レーン自身の設定で、上のレシピと同じようにクライアントのキーを探し、ボディの`model`で振り分けます。測った日は2026年10月14日です。条件は、`PERF_N=20000`、nginx 1.31.6、aarch64のUbuntu 22.04のコンテナです。測ったのは、`next`のコミット`bc2488a`のツリーに、#561のmruby 4.0.0を入れたものです。結果を次に示します。

| 測った処理 | リクエストあたりの命令の数。括弧の中はGCを除いた数 |
|---|---|
| server rewriteハンドラでの認証の確認。Rubyなしで2 KBのPOSTをプロキシしたときと比べた増分 | 25,276 (23,305) |
| 2 KBのボディの`JSON.parse`と`model`での振り分け。Rubyを使わない同じプロキシと比べた増分 | 85,228 (82,097) |

各シナリオは、[性能の比較に入れたエージェントプロキシのシナリオ](../../test/README.md#agent-proxy-scenarios-in-the-comparison)にあります。

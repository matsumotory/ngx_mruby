# はじめに

手元のプロキシから2つのmock APIへリクエストを送ります。Rubyを編集して、同じリクエストの転送先を変えます。プロバイダのアカウントやAPIキーは不要です。mockは転送先と認証情報の確認用で、文章生成やLLMへの接続は行いません。

これは<strong>v3の開発ブランチ<code>next</code></strong>を試す構成です。リリース済みv3のイメージや本番用の設定ではありません。基本的なRubyのレスポンスハンドラを試す`/hello`も残しています。

## 始める前に<wbr>用意するもの

Composeプラグイン付きのDocker（`docker compose`）、git、curl、ネットワーク接続が必要です。初回はソースからnginxとmrubyをビルドします。nginxはnginx.orgから、`build_config.rb.lock`で固定したgemはGitHubから取得します。以降は作成済みイメージを再利用します。検証済みのv3イメージは未提供です。

[`compose.yaml`](../../../examples/start/compose.yaml)のポート8080は`127.0.0.1`だけで公開します。2つのmock APIはコンテナ内のループバックで待ち受け、ホストには公開しません。キーはすべて公開のデモ用文字列です。公開サービスでは使用しないでください。

## ローカルプロキシを<wbr>起動する

```console
$ git clone --branch next https://github.com/matsumotory/ngx_mruby.git
$ cd ngx_mruby/examples/start
$ docker compose up --build --wait
```

`--wait`はヘルスチェック用の`/hello`が応答すると終了します。振り分けは次のリクエストで確認します。以降も例のディレクトリで実行します。

<a id="model-routing"></a>

## modelで<wbr>転送先を選ぶ

ローカルの利用者キーを付けてモデルAを送ります。nginxはキーを確認し、`route.rb`の対応表からモデルを探し、利用者の認証情報を置き換えてボディを転送します。mockの応答は転送先を示し、利用者キーではなく、その転送先専用の認証情報を受け取ったことを確認します。

`client.conf`にローカルURLとデモ用ヘッダをまとめています。以下のコマンドではmodelを変えます。設定の全文は後半に掲載しています。

```console
$ curl -K client.conf -d '{"model": "mock-model-a"}'
{
  "upstream":"a",
  "model":"mock-model-a",
  "credential_replaced":true
}
```

`model`だけを変更してAPI Bを選びます。URLと利用者キーは同じです。

```console
$ curl -K client.conf -d '{"model": "mock-model-b"}'
{
  "upstream":"b",
  "model":"mock-model-b",
  "credential_replaced":true
}
```

この例で確認するのはモデル振り分けと認証情報の差し替えです。API形式の変換、実プロバイダとの接続試験、LLMによる生成は行いません。ストリーム中継や同時実行制限と、それらを確かめる別の結合テストは、[エージェントプロキシのガイド](../guides/agent-proxy.md)を参照してください。

## リクエストを変えずに<wbr>転送先を変える

対応表でモデルAの転送先と上流用の認証情報を**両方**変更します。コマンドは元のファイルを`route.rb.orig`に保存します。マウントされたRubyハンドラには`cache`を指定していないため、次のリクエストで変更を読み取り、リロードは不要です。

```console
$ sed -i.orig 's/local_api_a/local_api_b/;s/upstream-a/upstream-b/' route.rb
$ curl -K client.conf -d '{"model": "mock-model-a"}'
{
  "upstream":"b",
  "model":"mock-model-a",
  "credential_replaced":true
}
```

リクエストは`mock-model-a`のままですが、応答は`upstream: b`になります。元の対応表を戻し、同じリクエストが再びAへ届くことを確認します。

```console
$ mv route.rb.orig route.rb
$ curl -K client.conf -d '{"model": "mock-model-a"}'
{
  "upstream":"a",
  "model":"mock-model-a",
  "credential_replaced":true
}
```

## 拒否するリクエストを<wbr>確認する

利用者キーがない、または未知のキーなら401、対応表にないモデルなら403、不正なJSONなら400です。これらのリクエストはプロキシで終了し、mock APIへ届きません。

```console
$ curl -sS localhost:8080/v1/responses -d '{}' -o /dev/null -w '%{http_code}\n'
401
$ curl -K client.conf -o /dev/null -w '%{http_code}\n' -d '{"model": "unknown"}'
403
$ curl -K client.conf -o /dev/null -w '%{http_code}\n' -d '{'
400
```

## 実行する<wbr>ファイル

`nginx.conf`はaccessハンドラ、名前付きupstream、mockのエンドポイントを接続します。基本の`/hello`ハンドラも残しています。このフォルダはコンテナ内へ読み取り専用でマウントされるため、ファイルはホスト側で編集します。

```text title="client.conf"
# Local demonstration credentials, not for a public service.
url = "http://localhost:8080/v1/responses"
header = "Content-Type: application/json"
header = "Authorization: Bearer local-client"
silent
show-error
```

```nginx title="nginx.conf"
# Local examples: one proxy and two mock APIs inside the container.
user nobody nogroup;
worker_processes 1;
error_log /dev/stderr;

events {
    worker_connections 64;
}

http {
    access_log /dev/stdout;

    upstream local_api_a { server 127.0.0.1:8081; }
    upstream local_api_b { server 127.0.0.1:8082; }

    server {
        listen 8080;

        location /hello {
            mruby_content_handler /example/hello.rb;
        }

        location = /v1/responses {
            set $selected_backend "";
            set $upstream_credential "";
            mruby_enable_read_request_body on;
            mruby_access_handler /example/route.rb;
            proxy_http_version 1.1;
            proxy_set_header Connection close;
            proxy_set_header Authorization $upstream_credential;
            proxy_set_header x-api-key "";
            proxy_buffering off;
            proxy_pass http://$selected_backend;
        }
    }

    server {
        listen 127.0.0.1:8081;
        location = /v1/responses {
            mruby_enable_read_request_body on;
            mruby_content_handler /example/mock.rb;
        }
    }

    server {
        listen 127.0.0.1:8082;
        location = /v1/responses {
            mruby_enable_read_request_body on;
            mruby_content_handler /example/mock.rb;
        }
    }
}
```

`route.rb`はローカルのキーを確認し、転送先と認証情報を選びます。nginxの変数を通して、その値を`proxy_pass`と`proxy_set_header`に渡します。

```ruby title="route.rb"
# Local demonstration credentials. Never use these values for a public service.
r = Nginx::Request.new
v = Nginx::Var.new

if r.headers_in["Authorization"] != "Bearer local-client"
  Nginx.return Nginx::HTTP_UNAUTHORIZED
else
  routes = {
    "mock-model-a" => ["local_api_a", "Bearer local-upstream-a"],
    "mock-model-b" => ["local_api_b", "Bearer local-upstream-b"]
  }
  begin
    body = JSON.parse(r.body)
    route = body.kind_of?(Hash) ? routes[body["model"]] : nil
    if route
      v.selected_backend = route[0]
      v.upstream_credential = route[1]
      Nginx.return Nginx::DECLINED
    else
      Nginx.return Nginx::HTTP_FORBIDDEN
    end
  rescue JSON::ParserError, ArgumentError
    Nginx.return Nginx::HTTP_BAD_REQUEST
  end
end
```

`mock.rb`はAPI AまたはBが受け取ったリクエストを報告します。認証情報そのものは返さず、一致したかどうかを真偽値で返します。

```ruby title="mock.rb"
# These local mocks report the selected route; they do not call an LLM.
r = Nginx::Request.new
v = Nginx::Var.new
name = v.server_port == "8081" ? "a" : "b"
body = JSON.parse(r.body)
r.headers_out["Content-Type"] = "application/json"
Nginx.rputs JSON.pretty_generate({
  "upstream" => name,
  "model" => body["model"],
  "credential_replaced" => r.headers_in["Authorization"] == "Bearer local-upstream-#{name}"
})
```

## 基本のレスポンス<wbr>ハンドラを試す

`hello.rb`はnginxのworker内でRubyを動かし、upstreamを使わずにレスポンスを書きます。挨拶を変更してもう一度リクエストを送り、その後で元へ戻します。

```ruby title="hello.rb"
# The content handler of the start page (examples/start/nginx.conf).
r = Nginx::Request.new
name = r.var.arg_name.to_s
name = "world" if name.empty?
r.content_type = "text/plain"
Nginx.rputs "Hello, #{name}! hello.rb answered #{r.method} #{r.uri}.\n"
```

```console
$ curl -sS 'http://localhost:8080/hello?name=Ruby'
Hello, Ruby! hello.rb answered GET /hello.
$ sed -i.orig 's/Hello/Good morning/' hello.rb
$ curl -sS 'http://localhost:8080/hello?name=Ruby'
Good morning, Ruby! hello.rb answered GET /hello.
$ mv hello.rb.orig hello.rb
```

## 設定の変更を<wbr>反映する

キャッシュしないRubyハンドラは、次のリクエストでファイルを読みます。`nginx.conf`や`cache`付きのRubyハンドラを変更した場合は、設定を検証してリロードします。以下はこのイメージ内のパスです。

```console
$ docker compose exec -T nginx /usr/local/nginx/sbin/nginx -t -c /example/nginx.conf
$ docker compose exec -T nginx /usr/local/nginx/sbin/nginx -s reload -c /example/nginx.conf
$ curl -sS 'http://localhost:8080/hello?name=Ruby'
Hello, Ruby! hello.rb answered GET /hello.
$ curl -K client.conf -d '{"model": "mock-model-a"}'
{
  "upstream":"a",
  "model":"mock-model-a",
  "credential_replaced":true
}
```

本番の設定では[コンパイル済みコードのキャッシュ](../../directives/README.md#caching-compile-code)を使い、リクエストごとのファイル読み取りを避けてください。mrbgemやビルドオプションの変更には、リロードだけでなくイメージの再ビルドが必要です。

## 試用を<wbr>終了する

```console
$ docker compose down
```

起動やヘルスチェックに失敗した場合は`docker compose logs nginx`を確認します。ベースイメージのメタデータ取得やダウンロードの失敗は、nginx起動前のレジストリやネットワークの問題で、この例が返した応答ではありません。

## 自分のアプリに<wbr>組み込む

- [エージェントプロキシ](../guides/agent-proxy.md)：認証、モデル振り分け、同時実行制限、ストリーム中継のテストと計画。
- [インストール](../install/README.md)：既存環境のnginxバージョンとビルドオプションに合わせて、静的または動的モジュールを作成。
- [ディレクティブ](../../directives/README.md)：nginxがRubyを実行するフェーズを選択。
- [リクエストのフェーズ](../concepts/request-phases.md)：1つのリクエストが通るハンドラの順序。

公式nginxのパッケージやイメージにngx_mrubyは含まれません。`--with-compat`も任意のnginxバージョンとの互換性は保証しません。Mac上でのLinuxコンテナの動作と、ネイティブmacOSビルドの検証は別です。

`examples`ワークフローは対象コミットごとに、このページのコマンドを実行して出力を比較します。利用するリビジョンのrunを確認してください。以前のrunだけでは変更後の手順が動く証拠になりません。従来のHelloだけの例は、2026-10-29のGitHub `ubuntu-24.04` runner（Docker Engine 28.0.4、Compose 2.38.2）で170秒でした。これは過去のビルド記録で、現在の所要時間、振り分けの実行、arm64の動作を保証するものではありません。

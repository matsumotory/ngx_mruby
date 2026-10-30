# バックエンドを選ぶ

nginxは、`proxy_pass`でリクエストをバックエンドへ渡します。[`mruby_set`](../../directives/README.md#mruby_set-and-mruby_set_code)を使うと、Rubyのスクリプトがリクエストごとにバックエンドを決め、`proxy_pass`はスクリプトが設定した変数を使います。その後、nginxがバックエンドに接続し、受け取ったレスポンスを中継します。スクリプトはリクエストごとに1回動き、文字列を返します。

## サンプル

スクリプトは、リクエストヘッダ`X-Tenant`と、テナントとバックエンドのアドレスのテーブルから、バックエンドを選びます。ヘッダの無いリクエストと、テーブルに無いテナントのリクエストには、どちらもバックエンド`a`を選びます。スクリプトの最後の行の値が、`$backend`の値になります。

```sample
case: test/t/cases/guides.rb
conf: test/conf/conf.d/73-guide-routing.conf
script: test/html/guide_routing.rb
request: test/html/guide_routing.request
response: test/html/guide_routing.response
```

ケースは`X-Tenant`の無いリクエストも送り、ポート18164のバックエンド`a`のレスポンスを期待します。

## 単独で試す

同じ振り分け表を使い、別のポートとキャッシュ付きのRubyで試します。既存のnginx設定やバックエンドは不要です。見つからないキーはバックエンド`a`へ送ります。これは認証の判断ではありません。`X-Tenant`だけでテナントへのアクセスを許可しないでください。

### 前提と対象版

実行した版は開発コミット[`6d65a12ec`](https://github.com/matsumotory/ngx_mruby/commit/6d65a12ecf166e11a6ece40d56f0f2efb05ea112)です。その標準gem lockとnginx 1.31.8を使い、Ubuntu 22.04 aarch64・GCC 11.4.0で確認しました。next向けの例であり、v3の正式提供を示すものではありません。この手順をリリース済みのv2.7.2タグでは実行していません。

ngx_mrubyのHTTPモジュールを組み込んだnginxが必要です。[インストール](../../install/README.md)を参照し、実行ファイルの絶対パスを`NGX_BIN`へ設定します。現在のチェックアウトの`build/nginx`へインストールした場合は、次の設定を使います。

```sh
export NGX_BIN="$PWD/build/nginx/sbin/nginx"
"$NGX_BIN" -V
```

シェルには`curl`、`mktemp`、`cmp`と標準的なPOSIXコマンドが必要です。nginxとcurlが使う同じネットワーク名前空間で、19480・19481・19482番ポートを空けてください。一般ユーザーか、隔離したテスト用コンテナで実行します。ホストへのポート公開は不要です。モジュールの無い配布版nginxでは動きません。動的ロードとLinux以外は未検証です。

### 作成から停止まで

次のブロック全体をシェルへ貼り付けます。新しい一時ディレクトリに2つのファイルを作り、設定を検査して専用のnginxを起動します。5つの入力についてステータス、メディア型、本文全体を照合し、そのインスタンスだけを停止します。表示したディレクトリには、調査用のログとファイルを残します。heredoc内のnginx変数のバックスラッシュは残してください。シェルが展開するのは`RUN_DIR`です。

```sh
(
set -eu
: "${NGX_BIN:?Set NGX_BIN to the absolute path of nginx with ngx_mruby}"
case "$NGX_BIN" in /*) ;; *) echo 'NGX_BIN must be absolute' >&2; exit 1 ;; esac
RUN_DIR="$(mktemp -d)"
mkdir -p "$RUN_DIR/logs"
printf 'Runtime and logs: %s\n' "$RUN_DIR"
started=0
cleanup() {
    result=$?
    trap - 0
    if [ "$started" = 1 ]; then
        "$NGX_BIN" -p "$RUN_DIR/" -c nginx.conf -s quit || result=1
        tries=0
        while [ -f "$RUN_DIR/logs/nginx.pid" ] && [ "$tries" -lt 50 ]; do
            sleep 0.1
            tries=$((tries + 1))
        done
        if [ -f "$RUN_DIR/logs/nginx.pid" ]; then
            echo 'Shutdown not confirmed; inspect the runtime logs' >&2
            result=1
        fi
    fi
    if [ "$result" != 0 ]; then
        tail -n 30 "$RUN_DIR/logs/error.log" >&2 || :
    fi
    exit "$result"
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' TERM
cat > "$RUN_DIR/route.rb" <<'RUBY'
backends = {
  "a" => "127.0.0.1:19481",
  "b" => "127.0.0.1:19482",
}
tenant = Nginx::Request.new.headers_in["X-Tenant"].to_s
backends.fetch(tenant, backends["a"])
RUBY
cat > "$RUN_DIR/nginx.conf" <<CONF
worker_processes 1;
pid logs/nginx.pid;
error_log logs/error.log notice;
events { worker_connections 64; }
http {
    access_log off;
    default_type text/plain;
    server {
        listen 127.0.0.1:19480;
        location / {
            mruby_set \$backend "$RUN_DIR/route.rb" cache;
            proxy_pass http://\$backend;
        }
    }
    server {
        listen 127.0.0.1:19481;
        return 200 "backend a: \$request_uri\n";
    }
    server {
        listen 127.0.0.1:19482;
        return 200 "backend b: \$request_uri\n";
    }
}
CONF
"$NGX_BIN" -p "$RUN_DIR/" -c nginx.conf -t
"$NGX_BIN" -p "$RUN_DIR/" -c nginx.conf
started=1
check() {
    label=$1
    backend=$2
    shift 2
    meta=$(curl --noproxy '*' --fail --silent --show-error --max-time 5 \
        -D "$RUN_DIR/headers" -o "$RUN_DIR/body" \
        -w '%{http_code} %{content_type}' "$@" \
        'http://127.0.0.1:19480/orders?limit=2')
    test "$meta" = '200 text/plain'
    printf 'backend %s: /orders?limit=2\n' "$backend" > "$RUN_DIR/expected"
    cmp "$RUN_DIR/expected" "$RUN_DIR/body"
    printf '%s -> %s; ' "$label" "$meta"
    cat "$RUN_DIR/body"
}
check tenant-a a -H 'X-Tenant: a'
check tenant-b b -H 'X-Tenant: b'
check absent a
check unknown a -H 'X-Tenant: other'
check address-input a -H 'X-Tenant: 127.0.0.1:1'
)
```

実行ディレクトリとnginxの設定検査メッセージに続き、成功した照合は次の5行を出力します。本文の末尾には改行が1つあり、`cmp`はそれも照合します。パスとクエリ文字列も選んだバックエンドへ届きます。

```text
tenant-a -> 200 text/plain; backend a: /orders?limit=2
tenant-b -> 200 text/plain; backend b: /orders?limit=2
absent -> 200 text/plain; backend a: /orders?limit=2
unknown -> 200 text/plain; backend a: /orders?limit=2
address-input -> 200 text/plain; backend a: /orders?limit=2
```

アドレス形式のヘッダ値も接続先ではなく表のキーなので、バックエンド`a`へ送られます。リクエストは順番に送り、`a`から`b`へ、その後`a`へ切り替わることを確認します。負荷試験や性能測定ではありません。Rubyは文字列を選び、接続とレスポンスの中継はnginxが行います。

### 失敗を調べる

- `unknown directive "mruby_set"`なら、`NGX_BIN`と`-V`の出力を確認します。Ruby処理系だけでなく、ngx_mrubyを組み込んだ実行ファイルが必要です。
- `bind() ... address already in use`なら、既存プロセスは停止しないでください。3つのポートを空けるか、設定、Rubyの表、curlのURLの対応するアドレスを全て変更してから再実行します。
- `502`やcurlの接続エラーなら、表示したディレクトリの`logs/error.log`と3つの待受を確認します。この数値アドレスにDNS resolverは不要です。
- 条件式や`cmp`が失敗したら、同じディレクトリの`headers`、`body`、`expected`を見比べます。`200`だけでは正しい振り分けと判断できません。
- Rubyの読込みに失敗したら、生成された絶対パスとディレクトリの権限を確認します。`cache`を使うため、編集した内容は例を再起動して読み直します。

正常終了時は、一時インスタンスのPIDファイルが消えたことまで確認します。途中で失敗しても、起動済みならtrapがそのインスタンスへ正常終了を要求します。停止が未確認なら、記録したインスタンスを調べてからポートを再利用します。

ログが不要になったら、この例が表示したディレクトリだけを削除できます。既存の結合テストは`test/t/cases/guides.rb`にあります。この例は既存テストを変えず、未知のキーとアドレス形式の入力も検査します。

## 気を<wbr>つけること

- `mruby_set`は、locationのrewriteフェーズで、nginxがバックエンドに接続する前に動きます。フェーズの順は[リクエストのフェーズ](../concepts/request-phases.md)にあります。スクリプトは`Nginx::Request`でリクエストを読みます。レスポンスは見えません。
- 変数を使った`proxy_pass`は、アドレスをそのまま使います。値が`upstream`ブロックの名前なら、そのブロックを使います。それ以外のホスト名には、nginxの`resolver`ディレクティブが要ります。
- リクエストヘッダはクライアントの入力です。スクリプトはヘッダをテーブルのキーと比べるので、クライアントはテーブルにあるバックエンドにしか届きません。詳しくは[信頼境界](../../security/trust-boundary.md)にあります。
- `cache`が無いと、nginxはリクエストのたびにスクリプトのファイルを読みます。本番では、ディレクティブに`cache`を付けるか、`mruby_set_code`を使ってください。詳しくは[コンパイルしたコードのキャッシュ](../../directives/README.md#caching-compile-code)にあります。

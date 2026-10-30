# はじめに

このページでは、ngx_mrubyを組み込んだnginxをDockerで動かし、Rubyのスクリプトが答えるリクエストを送ってから、そのスクリプトを書き換えます。例は、リポジトリのフォルダ`examples/start`にあります。Composeは、[`compose.yaml`](../../../examples/start/compose.yaml)に従い、[`Dockerfile`](../../../examples/start/Dockerfile)を使って、チェックアウトしたソースからngx_mrubyを組み込んだnginxをビルドします。次に、フォルダの`nginx.conf`と`hello.rb`でそのnginxを起動します。

## 始める<wbr>前に

- Dockerと、`docker compose`のコマンドを使うためのComposeのプラグイン、git、curl、ネットワークへの接続が要ります。ビルドは、nginxをnginx.orgから、`build_config.rb`のmrbgemsをGitHubからダウンロードします。
- このv3開発版の検証済みビルド済みイメージは提供していないため、最初の実行では、mrubyとnginxをコンパイルします。2026年10月29日に、GitHubの`ubuntu-24.04`のランナーで、Docker Engine 28.0.4とDocker Compose 2.38.2を使ったとき、手順3は170秒かかりました。2回目からは、ビルド済みのイメージを使い回します。
- これらの手順は、`examples/`を変えるすべてのプルリクエストでCIが実行します。そのワークフローの`.github/workflows/examples.yml`は、このページの出力をすべて、コマンドが表示したものと比べます。

## Rubyの<wbr>ハンドラを<wbr>持つ<wbr>nginxを<wbr>動かす

このサイトで扱うのは、ブランチ`next`で開発中のngx_mruby 3.xです。

1. リポジトリから、ブランチ`next`をクローンします。

   ```console
   $ git clone --branch next https://github.com/matsumotory/ngx_mruby.git
   ```

2. 例のフォルダへ移動します。

   ```console
   $ cd ngx_mruby/examples/start
   ```

3. イメージをビルドし、nginxを起動します。`--wait`を付けると、nginxが`compose.yaml`のヘルスチェックに答えたときにコマンドが戻り、Composeはコンテナ`start-nginx-1`をhealthyとして表示します。

   ```console
   $ docker compose up --build --wait
   ```

4. 引数`name`を付けて、`/hello`へリクエストを送ります。レスポンスはRubyのスクリプトが書きます。

   ```console
   $ curl -s 'http://localhost:8080/hello?name=Ruby'
   Hello, Ruby! hello.rb answered GET /hello.
   ```

## リクエストに<wbr>答えたもの

nginxは、`nginx.conf`の[`mruby_content_handler`](../../directives/README.md#mruby_content_handler-and-mruby_content_handler_code)に従って、`/hello`へのリクエストをRubyのスクリプトに渡します。

```nginx title="nginx.conf"
# The nginx configuration of the start page. compose.yaml mounts this
# folder at /example, and the image starts nginx with this file.
user nobody nogroup;
worker_processes 1;
error_log /dev/stderr;

events {
    worker_connections 64;
}

http {
    access_log /dev/stdout;

    server {
        listen 8080;

        location /hello {
            mruby_content_handler /example/hello.rb;
        }
    }
}
```

`hello.rb`は、`Nginx::Request`で引数を読み、`Nginx.rputs`でボディを書き出します。

```ruby title="hello.rb"
# The content handler of the start page (examples/start/nginx.conf).
r = Nginx::Request.new
name = r.var.arg_name.to_s
name = "world" if name.empty?
r.content_type = "text/plain"
Nginx.rputs "Hello, #{name}! hello.rb answered #{r.method} #{r.uri}.\n"
```

nginxは、ワーカープロセスの中でngx_mrubyがnginxに組み込んだmrubyのVMを使ってスクリプトを実行します。ほかのプロセスは関わりません。スクリプトが使えるクラスとメソッドは、[Rubyのリファレンス](../../class_and_method/README.md)にあります。

## スクリプトを<wbr>書き換える

Composeは、`compose.yaml`に従ってこのフォルダをコンテナにマウントします。ディレクティブは、パラメータ`cache`を付けずにスクリプトを指定しています。そのため、nginxはリクエストのたびにファイルを読み直します。`hello.rb`を変えると、リロードしなくても次のリクエストから変更が効きます。

1. `hello.rb`の`Hello`を`Good morning`に置き換えます。このコマンドは、元のファイルを`hello.rb.orig`として残します。

   ```console
   $ sed -i.orig 's/Hello/Good morning/' hello.rb
   ```

2. もう一度リクエストを送ります。レスポンスには新しいあいさつが入っています。

   ```console
   $ curl -s 'http://localhost:8080/hello?name=Ruby'
   Good morning, Ruby! hello.rb answered GET /hello.
   ```

3. 元のスクリプトを戻します。

   ```console
   $ mv hello.rb.orig hello.rb
   ```

4. マウントした設定を検証してリロードします。`PATH`に依存せず、このイメージのバイナリと設定のパスを指定します。

```console
$ docker compose exec -T nginx /usr/local/nginx/sbin/nginx -t -c /example/nginx.conf
$ docker compose exec -T nginx /usr/local/nginx/sbin/nginx -s reload -c /example/nginx.conf
$ curl -s 'http://localhost:8080/hello?name=Ruby'
Hello, Ruby! hello.rb answered GET /hello.
```

5. コンテナを止めて削除します。Composeは、コンテナ`start-nginx-1`をremovedと表示します。

   ```console
   $ docker compose down
   ```

リクエストのたびにファイルを読むと、スクリプトを書いている間は便利です。その代わり、nginxはリクエストの処理の途中でディスクを読みます。本番では、[コンパイルしたコードのキャッシュ](../../directives/README.md#caching-compile-code)にあるように、ディレクティブに`cache`を付けてください。`cache`を付けると、nginxは設定を読むときにスクリプトを1回だけコンパイルします。

## 変更を反映する方法

| 変更 | 反映方法 | 理由 |
|---|---|---|
| `cache`なしのRuby | 再送 | マウントしたスクリプトを毎回読みます |
| `nginx.conf`、または`cache`付きRuby | `nginx -t`で検証してから上記コマンドでreload | 設定読込時にコードをコンパイルします |
| mrbgemやビルドオプション | 再ビルド | ビルド条件が変わる |

コンテナ内のマウントは読み取り専用です。ホスト側のファイルを編集します。この例はホストのインターフェースに8080番を公開するため、ローカルだけで試す場合は起動前にComposeの対応を`127.0.0.1:8080:8080`へ変更してください。healthcheckや設定エラーは`docker compose logs nginx`で調べます。コンパイル前のイメージmetadata取得エラーはレジストリやネットワークの問題で、nginxの応答ではありません。

コンテナは試用の入口の一つです。既存のLinux環境へ組み込む場合は[インストール](../install/README.md)に従い、nginxの版とビルド条件を合わせます。公式nginxパッケージやイメージにはngx_mrubyは含まれず、`--with-compat`も任意のnginx版との互換性を意味しません。Mac上でLinuxコンテナを動かした結果は、macOSネイティブビルドの証明ではありません。

上記170秒は過去のCI環境での記録であり、現在の所要時間やarm64での結果を保証しません。2026-10-30のfresh linux/arm64試行はUbuntu基盤イメージのmetadata取得で止まり、コンパイル前に終了しました。その試行では起動・編集反映・reloadは未検証です。examplesワークフローがLinuxランナーでコマンドを検査するため、使用するcommitの実行結果を確認してください。

一次資料: [NGINXコンテナ](https://docs.nginx.com/nginx/admin-guide/installing-nginx/installing-nginx-docker/)、[Linuxパッケージ](https://nginx.org/en/linux_packages.html)、[動的モジュール](https://blog.nginx.org/blog/nginx-dynamic-modules-how-they-work)、[reload](https://nginx.org/en/docs/control.html)、[bind mount](https://docs.docker.com/engine/storage/bind-mounts/)。

## 次に<wbr>読む<wbr>ページ

- [インストール](../install/README.md)：ngx_mrubyを、静的なモジュールか動的なモジュールとして、自分のnginxに組み込んでビルドします。
- [ディレクティブ](../../directives/README.md)：nginxがRubyを実行するフェーズと、各フェーズのディレクティブを載せています。
- [リクエストのフェーズ](../concepts/request-phases.md)：nginxが1つのリクエストのハンドラを実行する順序を説明しています。

- [エージェントプロキシ](../guides/agent-proxy.md): 検証済みのモデル振り分けとストリーム中継へ進みます。

# 信頼境界

ngx_mrubyは、nginxのサーバーの運用者が書いたRubyのコードを実行し、クライアントが送るものを、そのコードへの入力として扱います。ngx_mrubyはサンドボックスではありません。設定で読み込むコードの動作を制限しません。このページでは、境界の両側に何があるか、ngx_mrubyが何に責任を持つか、運用者のコードが何に責任を持つかを説明します。また、それが[SECURITY.md](../../../SECURITY.md)の対象の範囲にどう対応するかも説明します。

## 信頼する設定とコード

- nginxの設定と、設定で読み込むすべてのRubyのコードを信頼します。このコードは、ディレクティブで指定するスクリプトのファイル、`*_code`のディレクティブのインラインのコード、`build_config.rb`でモジュールに組み込むgemです。スクリプトのファイルを指定するディレクティブには、`mruby_content_handler /path/to/handler.rb`などがあります。ngx_mrubyはこのコードをそのままコンパイルして実行し、コードが何をするかを確かめません。
- [`mruby_add_handler on`](../../directives/README.md#mruby_add_handler)では、リクエストのURIで、どのファイルを実行するかが決まります。ngx_mrubyはURIをlocationのrootの下のパスに対応させ、そのファイルをcontentハンドラとして実行します。そのrootの下でlocationにマッチするすべてのファイルが、この種類のコードです。
- 初期化のコードと、serverの設定のコードは、nginxが設定を読む間にmasterプロセスで動きます。初期化のコードは、`mruby_init`、`mruby_init_code`、`mruby_stream_init`、`mruby_stream_init_code`のコードです。serverの設定のコードは、`mruby_server_context_handler_code`と`mruby_stream_server_context_code`のコードです。これらのコードは、nginxを起動したときの権限で動きます。nginxをrootで起動したなら、rootの権限です。ほかのすべてのコードは、ワーカープロセスで、ワーカーの権限で動きます。ほかのコードとは、init_workerとexit_workerのコード、すべてのハンドラとフィルタ、SSLのハンドシェイクのハンドラ、streamのハンドラです。masterがrootで動くとき、ワーカーの権限は、`user`ディレクティブのユーザーの権限です。
- `http {}`のブロックのすべてのコードは、ワーカーごとに1つの`mrb_state`で動きます。`stream {}`のブロックにも、ワーカーごとに別の`mrb_state`が1つあります。その`mrb_state`を、ブロックのすべてのserver、location、クライアントが共有します。詳しくは[ワーカーがリクエストをまたいで保つもの](../concepts/lifetimes.md#ワーカーがリクエストをまたいで保つもの)にあります。あるlocationのコードは、別のserverやlocationのコードが定義したグローバル変数、定数、クラス、メソッドを読み、変えられます。ngx_mrubyは、1つのブロックのスクリプトを、互いに隔離しません。
- デフォルトのビルドでは、このコードは、`build_config.rb`の`NGX_MRUBY_CORE_GEMS`に挙げたmrubyのコアのgemと、`build_config.rb`のほかのgemを使えます。詳しくは[コアのgem](../install/README.md#コアのgem)にあります。使える機能には、次のものがあります。mruby-evalの`eval`と`instance_eval`、mruby-ioのファイルと、シェルのコマンドを実行する`IO.popen`とバッククォート、mruby-socketのソケット、mruby-sleepの`sleep`、iij/mruby-processの`Process`、`ENV`、`Dir`です。スクリプトは、そのプロセスのユーザーにできることなら何でもできます。

そのため、nginxの設定、設定で読み込むスクリプト、そのスクリプトを置くディレクトリ、`build_config.rb`のどれかを変えられる人は、ワーカーとして任意のコードを実行できます。その人は、初期化のコードを通して、masterとしても任意のコードを実行できます。運用者が信頼しない相手からnginxの設定やRubyのコードを受け取る構成では、コードを渡す相手のそれぞれが、この権限を持ちます。その権限は、nginx全体と、ほかの相手のトラフィックに及びます。顧客ごとにスニペットを動かすマルチテナントのサービスは、この構成の例です。ngx_mrubyには、そのようなコードの動作を制限する手段がありません。この使い方はサポート外です。

## 信頼しない入力

クライアントから受け取るデータは、すべて信頼しない入力として扱います。対象には、リクエストライン、URIとその引数、ヘッダとクッキー、リクエストのボディ、nginxがそれらから導く値があります。スクリプトは、これらの値を[`Nginx::Request`](../../class_and_method/README.md#nginxrequest-class)、[`Nginx::Headers_in`](../../class_and_method/README.md#nginxheaders_in-class)、[`Nginx::Var`](../../class_and_method/README.md#nginxvar-class)で読みます。`Nginx::Request`のメソッドには、`uri`、`unparsed_uri`、`args`、`uri_args`、`post_args`、`method`、`headers_in`、`get_body`、`user`などがあります。`Nginx::Var`で読む変数には、たとえば`$http_*`、`$arg_*`、`$cookie_*`、`$request_uri`があります。クライアントがTLSのハンドシェイクで送るサーバー名も、同じように信頼しない入力です。スクリプトはこの名前を[`Nginx::SSL#servername`](../../class_and_method/README.md#nginxsslservername---string)で読みます。upstreamのサーバーからのレスポンスは、そのサーバー自身と同じ程度にだけ信頼できます。サブリクエストや出力フィルタが読むレスポンスも同じです。

## ngx_mrubyの責任範囲

- ngx_mrubyがリクエストを受け取る前に、nginxがリクエストをパースします。ngx_mrubyの`src/`のCのコードと、`mrbgems/`の同梱のgemは、リクエストの値をRubyの文字列などのオブジェクトとしてスクリプトに渡します。スクリプトが返す値は、データとして受け取ります。ディレクティブとメソッドをドキュメントのとおりに使う設定では、次のことが起きないようにngx_mrubyを作っています。ngx_mrubyがバッファの外のメモリを読み書きすること、ワーカーが終了するかハングすること、あるリクエストに別のリクエストのデータが渡ることです。クライアントが何を送っても、スクリプトがクライアントの入力をngx_mrubyのメソッドに渡しても、同じです。これが起きたなら、ngx_mrubyの不具合です。クライアントの値が関わらず、スクリプト自身の呼び出しだけで起きた場合も、ngx_mrubyの不具合です。
- 2.7.1と2.7.2では、設定のコード自身の呼び出しで起きる、この種類の不具合を直しました。そのうちのいくつかには、クライアントの値が関わっていませんでした。2.7.0では、`Nginx.rputs`か`Nginx.echo`で書いたボディをボディフィルタが短くすると、新しいボディの終わりより後ろのバイトが送られました。また、リクエストのスコープのメソッドをリクエストの外で呼ぶと、そのメソッドが別のリクエストのデータを使うことがありました。詳しくは、[2.7.1のリリースノート](../../releases/v2.7.1.ja.md)のエントリー2と8と、アドバイザリの[GHSA-h7fw-wf49-8rv5](https://github.com/matsumotory/ngx_mruby/security/advisories/GHSA-h7fw-wf49-8rv5)にあります。2.7.1では、`Nginx::Var`が、名前か引数の外のメモリを読むことがありました。読んだのは、名前が空のとき、名前が`=`だけでできているとき、値の無いセッターを呼んだときです。また、`Nginx::Var#set`は、名前として渡したStringかSymbolを変えていました。詳しくは[2.7.2のリリースノート](../../releases/v2.7.2.ja.md)のエントリー1と2にあります。今のアクセサは、名前と引数を読む前に確かめます。`#set`は、名前を小文字にしたコピーで変数を探します。スクリプトがどんな値を渡しても同じで、クライアントから受け取った値を渡しても同じです。

## 運用者のコードの責任

ngx_mrubyは、スクリプトが求めることを実行します。クライアントの入力を先へ渡した結果には、スクリプトが責任を持ちます。

- クライアントの入力は、その入力を使う処理へ渡す前に検証してください。対象には、`eval`と`instance_eval`、シェルのコマンド、ファイルのパス、nginxの変数の名前、upstreamのアドレス、リダイレクトの先、レスポンスヘッダがあります。シェルのコマンドを実行するのは、バッククォート、`IO.popen`、`Process`です。ファイルのパスを使うのは、`File`、`Dir`、[`Nginx::SSL#certificate=`](../../class_and_method/README.md#nginxsslcertificatestring)、`#certificate_key=`です。nginxの変数の名前を使うのは、実行時に組み立てた名前を渡す`Nginx::Var`と、`Nginx::Var#set`です。upstreamのアドレスを使うのは、`mruby_set $backend`と`Nginx::Upstream#server=`です。入力を許可する値のリストと比べるか、コードが期待する型にパースし、合わないものは拒否してください。たとえば、サーバー名から証明書のパスを組み立てるハンドシェイクのハンドラでは、クライアントがパスを選べます。代わりに名前をテーブルで引き、証明書のある名前だけがパスに届くようにしてください。

  ```nginx
  http {
      mruby_init_code '
          CERT_DIRS = {
            "example.com"     => "/etc/nginx/certs/example.com",
            "www.example.com" => "/etc/nginx/certs/www.example.com",
          }
      ';

      server {
          listen 443 ssl;
          ssl_certificate     /etc/nginx/certs/default.crt;
          ssl_certificate_key /etc/nginx/certs/default.key;

          mruby_ssl_handshake_handler_code '
              ssl = Nginx::SSL.new
              dir = CERT_DIRS[ssl.servername]
              if dir
                ssl.certificate = "#{dir}/cert.pem"
                ssl.certificate_key = "#{dir}/key.pem"
              end
          ';
      }
  }
  ```

  コードが証明書を設定しないハンドシェイクでは、serverの`ssl_certificate`と`ssl_certificate_key`を使います。詳しくは[Nginx::SSL](../../class_and_method/README.md#nginxssl-class)にあります。`certificate=`と`certificate_key=`を使うと、ワーカーはハンドシェイクの間にファイルを読み、その間ブロックします。次の項目を見てください。この読み込みを避けるには、初期化のコードでPEMのデータを読み込み、[`certificate_data=`](../../class_and_method/README.md#nginxsslcertificate_datastring)と[`certificate_key_data=`](../../class_and_method/README.md#nginxsslcertificate_key_datastring)で設定してください。
- 1つのリクエストのデータを、グローバル変数、定数、`main`のインスタンス変数、`Userdata`に置かないでください。ワーカーが次に受けるリクエストからは、どのクライアントのリクエストでも、そのデータが見えます。詳しくは[ワーカーがリクエストをまたいで保つもの](../concepts/lifetimes.md#ワーカーがリクエストをまたいで保つもの)にあります。
- リクエストの経路で、ブロックする呼び出しを避けてください。ワーカーは多くのクライアントを同時に扱います。スクリプトが`sleep`、ソケット、ファイル、シェルのコマンド、`Process`、Redisの呼び出しで待つ間、ワーカーはほかのクライアントを扱えません。そのため、スクリプトを待たせられるクライアントは、そのワーカーのすべてのクライアントを遅くできます。[`Nginx::Async.sleep`](../../class_and_method/README.md#nginxasyncsleepmsec)と[`Nginx::Async::HTTP.sub_request`](../../class_and_method/README.md#nginxasynchttpsub_requestlocation-string_or_hashnil)は、それぞれのドキュメントに動くと書いてある場面で使ってください。また、スクリプトのファイルをリクエストのたびにディスクから読まないように、スクリプトのディレクティブに`cache`を加えるか、`mruby_cache on`を設定するか、インラインのコードを使ってください。
- nginxの設定、スクリプト、スクリプトを置くディレクトリ、`build_config.rb`は、運用者だけが書き込めるようにしてください。`mruby_add_handler on`を使うときは、そのrootの下にハンドラのスクリプトだけを置き、クライアントがアップロードしたファイルを置かないでください。

## SECURITY.mdとの対応

ngx_mrubyの`src/`か`mrbgems/`に次の不具合を見つけたら、[SECURITY.md](../../../SECURITY.md)に書いてある方法で、非公開で報告してください。ディレクティブとメソッドをドキュメントのとおりに使う設定で、ngx_mrubyがバッファの外のメモリを読み書きする不具合、ワーカーが終了するかハングする不具合、別のリクエストのデータが漏れるか変わる不具合です。クライアントが制御する入力で起きる不具合は、特に報告してください。スクリプトがクライアントの入力をngx_mrubyのメソッドに渡して起きる不具合も、報告の対象です。スクリプトがドキュメントのとおりにメソッドを呼び、クライアントの値が無くても起きる不具合も、報告の対象です。同梱のコンポーネントやサードパーティのコンポーネントの不具合は、SECURITY.mdにあるとおり、それぞれのupstreamのプロジェクトにも報告してください。不具合が対象に入るか分からないときは、非公開で報告してください。

信頼するコードと設定が、書いたとおりに動いた結果は、SECURITY.mdの対象の範囲の外です。範囲の外になるのは、次の場合です。スクリプトがクライアントの入力を、`eval`、シェルのコマンド、ファイルのパスのような、上に挙げた使い道へ渡す場合です。スクリプトが1つのリクエストのデータをグローバル変数に置き、後のリクエストがそのデータを見る場合です。スクリプトのブロックする呼び出しで、ワーカーが止まる場合です。設定、スクリプト、`build_config.rb`を変えられる人が、コードを実行する場合です。運用者が信頼しない相手から、nginxの設定やRubyのコードを受け取る構成も、範囲の外です。

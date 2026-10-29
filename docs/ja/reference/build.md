# ビルド

このページでは、ngx_mrubyのビルドの組み立て、`./configure`と`build.sh`のオプション、デフォルトのビルドに入るmrbgems、CIがビルドしてテストするバージョンを説明します。手順は[インストール](../install/README.md)にあります。

## ビルドの<wbr>組み立て

```diagram
build-layout
caption: ビルドのステップを、`./configure`と`make`が実行する順に示します。
source: configure.in 53-62 190-194
source: Makefile.in 27-28 87 98-119
source: config.in 48-81
source: build_config.rb 81-153
source: build.sh 103 107
at: c35606b0e 2026-10-19
configure: `./configure`が<wbr>`config.in`と<wbr>`Makefile.in`から<wbr>`config`と<wbr>`Makefile`を<wbr>書く
rake: `make`が<wbr>`build_config.rb`と<wbr>そのロックで<wbr>mrubyの<wbr>`rake`を<wbr>実行し、<wbr>mrbgemsを<wbr>含む<wbr>`libmruby.a`を<wbr>作る
mrbgems-config: `make`が、<wbr>そのmrubyの<wbr>ビルドの<wbr>フラグから<wbr>`mrbgems_config`を<wbr>書く。<wbr>動的な<wbr>ビルドでは<wbr>`mrbgems_config_dynamic`
nginx-configure: nginxの<wbr>`configure`を、<wbr>`--add-module`の<wbr>ngx_mrubyと<wbr>`ngx_devel_kit`で<wbr>実行する。<wbr>動的な<wbr>ビルドでは<wbr>`--enable-dynamic-module`に<wbr>従って<wbr>`--add-dynamic-module`を<wbr>使う。<wbr>`config`は<wbr>`mrbgems_config`を<wbr>読む
nginx-make: nginxの<wbr>`make`が、<wbr>ngx_mrubyを<wbr>組み込んだ<wbr>nginxか、<wbr>nginxが<wbr>読み込む<wbr>モジュールの<wbr>ファイルを<wbr>作る
modules: その中に<wbr>あるもの：<wbr>`ngx_http_mruby_module`、<wbr>nginxの<wbr>streamモジュールが<wbr>あるときの<wbr>`ngx_stream_mruby_module`、<wbr>ngx_mrubyの<wbr>upstreamの<wbr>keepaliveを<wbr>扱うモジュール
```

- `./configure`は、`config.in`と`Makefile.in`から`config`と`Makefile`を書きます。`--enable-dynamic-module`を付けると、`Makefile`はngx_mrubyを、`--add-module`ではなく`--add-dynamic-module`でnginxの`configure`に渡します。`dependence/ngx_devel_kit`は、いつも`--add-module`で渡します。`mruby_set`は、その`set_var`の部分を使います。
- `make`は、最初にmrubyをビルドします。`mruby/`の中で、`rake`は`build_config.rb`と`build_config.rb.lock`を読みます。`build_config.rb`にはコアのgemとサードパーティのmrbgemsが書いてあり、`build_config.rb.lock`はサードパーティの各mrbgemのコミットを固定します。結果は、gemを含むライブラリの`libmruby.a`と、gemが要るコンパイラとリンカのフラグを書いた`libmruby.flags.mak`です。`make`は、このファイルを元に`mrbgems_config`を書きます。動的なビルドでは`mrbgems_config_dynamic`を書きます。
- 次に`make`は、nginxのソースツリーでnginxの`configure`と`make`を実行します。`config`は`mrbgems_config`を読み、`libmruby.a`をnginxにリンクします。動的なビルドでは、モジュールのファイルにリンクします。モジュールには、`ngx_http_mruby_module`と、ngx_mrubyがupstreamとの接続を保つためのモジュールが入ります。そのモジュールのディレクティブが`mruby_upstream_keepalive`です。nginxのstreamモジュールを含むビルドでは、`ngx_stream_mruby_module`も入ります。
- `build.sh`は、自分でダウンロードしたnginxのソースで`./configure`を実行し、続いて、`make`を実行します。

## configureの<wbr>オプション

| オプション | 設定するもの | デフォルト |
|---|---|---|
| `--with-ngx-src-root=DIR` | nginxのソースツリー | 無し。`configure`は、指定が無いと止まる |
| `--with-ngx-config-opt=OPT` | `make`がnginxの`configure`に渡すオプション | 無し |
| `--enable-dynamic-module` | 動的モジュールとしてビルドする | 静的なモジュール |
| `--with-build-dir=DIR` | `make clobber`が消すビルドのディレクトリ。`build.sh`は`build`か`build_dynamic`を渡し、そこにnginxのソースを置いておく | `build` |
| `--with-openssl-src=DIR` | nginxが一緒にビルドするOpenSSLのソースの場所。nginxの`--with-openssl`の指定にあたる | システムのOpenSSL |
| `--with-openssl-opt=OPTIONS` | OpenSSLのビルドに足すオプション。nginxの`--with-openssl-opt`にあたる | 無し |
| `--with-mruby-root=DIR` | ビルドするmrubyのソースツリー | このリポジトリの`mruby/` |
| `--with-mruby-incdir=DIR` | mrubyのインクルードのディレクトリ | `src`、`include`、`build/host/include`。どれもmrubyのツリーの中にある |
| `--with-mruby-libdir=DIR` | `libmruby.a`を置いたディレクトリ | `build/host/lib`。mrubyのツリーの中にある |
| `--with-ndk-root=DIR` | 使う`ngx_devel_kit`のソースツリー | `dependence/ngx_devel_kit` |

## ビルドの<wbr>環境変数

| 変数 | 読むもの | 働き |
|---|---|---|
| `NGINX_CONFIG_OPT_ENV` | `build.sh` | nginxの`configure`のオプションの全部。デフォルトのオプションの代わりに使う。デフォルトは、プレフィックスの`build/nginx`と、`--with-http_stub_status_module`、`--with-stream`、`--without-stream_access_module`、`--with-cc-opt=-fno-common`。動的なビルドのプレフィックスは`build_dynamic/nginx` |
| `NGINX_SRC_ENV` | `build.sh` | `nginx_version`のバージョンをダウンロードする代わりに使う、nginxのソースツリー |
| `BUILD_DYNAMIC_MODULE` | `build.sh` | 値があれば、`build_dynamic/`に動的なモジュールをビルドする |
| `NUM_THREADS_ENV` | `build.sh` | `make`のジョブの数。デフォルトはプロセッサの数の半分 |
| `OPENSSL_SRC_VERSION` | `build.sh` | そのバージョンのOpenSSLをダウンロードし、nginxと一緒にビルドする |
| `NGX_MRUBY_AUTO_SSL=1` | `build_config.rb` | auto-sslのmrbgemと、それが依存するgemを加える。詳しくは[auto-sslのmrbgemを入れる](../install/README.md#auto-sslのmrbgemを入れる)にある |
| `NGX_MRUBY_ALLOW_MISSING_CORE_GEMS=1` | `build_config.rb` | `NGX_MRUBY_CORE_GEMS`の名前のうち、ビルドするmrubyに無いものを、通知を出して読み飛ばす |
| `NGX_MRUBY_CFLAGS`、`NGX_MRUBY_LDFLAGS`、`NGX_MRUBY_LIBS` | `build_config.rb` | mrubyのビルドに足すコンパイラのフラグ、リンカのフラグ、ライブラリ |

## デフォルトの<wbr>mrbgems

デフォルトの`build_config.rb`は、`NGX_MRUBY_CORE_GEMS`が挙げるmrubyのコアのgemに加えて、次のmrbgemsを`libmruby.a`に入れてビルドします。コアのgemの説明は[コアのgem](../install/README.md#コアのgem)にあります。`build_config.rb.lock`は、サードパーティの各gemのコミットを固定します。詳しくは[gemのコミット](../install/README.md#gemのコミットとbuild_configrblock)にあります。

- [`iij/mruby-env`](https://github.com/iij/mruby-env)：`ENV`
- [`iij/mruby-digest`](https://github.com/iij/mruby-digest)：MD5、RMD160、SHA1、SHA256、SHA384、SHA512、HMACを扱う`Digest`
- [`iij/mruby-process`](https://github.com/iij/mruby-process)：`Process`
- [`mattn/mruby-json`](https://github.com/mattn/mruby-json)：`JSON`
- [`mattn/mruby-onig-regexp`](https://github.com/mattn/mruby-onig-regexp)：正規表現の`OnigRegexp`
- [`matsumotory/mruby-redis`](https://github.com/matsumotory/mruby-redis)：`Redis`。Redisのサーバの応答を、ワーカーの中で1つずつ待つクライアントです。このgemのビルドは、hiredisのライブラリをタグv1.5.0でクローンし、そのコミットを確かめて静的にリンクします。また、このgemが依存するmatsumotory/mruby-pointerもクローンします。`Redis`を呼ぶスクリプトには、動いているRedisのサーバが要ります
- [`matsumotory/mruby-vedis`](https://github.com/matsumotory/mruby-vedis)：`Vedis`
- [`matsumotory/mruby-userdata`](https://github.com/matsumotory/mruby-userdata)：クラスの`Userdata`
- [`matsumotory/mruby-uname`](https://github.com/matsumotory/mruby-uname)：`Uname`
- [`matsumotory/mruby-mutex`](https://github.com/matsumotory/mruby-mutex)：`Mutex`
- [`matsumotory/mruby-localmemcache`](https://github.com/matsumotory/mruby-localmemcache)：`Cache`
- [`monochromegane/mruby-secure-random`](https://github.com/monochromegane/mruby-secure-random)：`SecureRandom`
- [`mrbgems/ngx_mruby_mrblib`](../../../mrbgems/ngx_mruby_mrblib)：ngx_mrubyのクラスのうち、Rubyで書いた部分
- [`mrbgems/rack-based-api`](../../../mrbgems/rack-based-api)：Rackと互換のAPIの`run`

チェックの`site/scripts/check-reference.mjs`は、この一覧を、`build_config.rb`のhostのビルドにある`conf.gem`の行のうち、コメントでなく条件も無い行と比べます。コメントの行には、mruby-discountやmruby-memcachedのような、デフォルトのビルドが入れないgemの名前があります。そのどれかを入れてビルドするには、その行のコメントを外し、`mruby/build`を消してください。

## CIが<wbr>ビルドして<wbr>テストする<wbr>バージョン

ワークフローの`.github/workflows/test.yml`は、すべてのプルリクエストで、次の組み合わせごとにngx_mrubyをビルドし、`test.sh`を実行します。

| nginx | モジュール | OpenSSL | nginxを動かす環境 |
|---|---|---|---|
| 1.31.6, 1.30.5, 1.28.3, 1.26.3 | 静的と動的 | インストールした1.1.1wと、`--with-openssl-src`でnginxに組み込んだ1.1.1w | valgrind |
| 1.31.6 | 静的 | システムにインストールした1.1.1w | AddressSanitizerとUndefinedBehaviorSanitizer |

- ランナーは、GCC 11のUbuntu 22.04です。同梱のmrubyは4.0.0です。バージョンは`build_config.rb.lock`にあります。
- `nginx_version`は`build.sh`と`test.sh`がダウンロードするバージョン1.31.6を指定します。

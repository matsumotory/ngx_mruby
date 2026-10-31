# インストール

ngx_mrubyを組み込んだnginxで、インラインとファイルのRubyを実行します。root権限を使わず、ループバックだけで試します。

対象は`next`開発ブランチとnginx 1.31.8です。安定リリースではありません。リリース済みの2.xには、[安定版の導入手順](https://ngx.mruby.org/v2/guides/install/)を使ってください。結果を比較する前に、ソースのコミットとビルド設定を記録します。Dockerで先に試すには、[はじめにの例](../start/README.md)を使えます。既存環境の更新前には[リリースノート](../../releases/README.md)を確認してください。

## ソースから<wbr>インストールする

### 前提

C/C++コンパイラ、GNU make、Ruby 3.0以降とrake、bison、git、wget、curlが必要です。同梱のmrubyのビルドは、Ruby 2.xでは`mrbc`をリンクするところで止まります。OpenSSL・PCRE・zlibは開発用ヘッダとライブラリも用意します。ビルドはGitHubからサードパーティのmrbgemsを取得します。Docker Hubのアカウントは不要です。

Ubuntu 22.04では、まず管理者権限でパッケージを入れます。以降のビルドは一般ユーザーで行ってください。

```sh
sudo apt-get update
sudo apt-get install build-essential ruby rake bison git wget curl ca-certificates libssl-dev libpcre3-dev zlib1g-dev
```

この手順の対象はLinuxです。他のOSではパッケージ名が異なります。バージョン管理ツールでRubyを選ぶ場合は、その`ruby`と`rake`を`PATH`に含めてください。

動的モジュールとnginxの版・設定・ABIは一致が必要です。無関係な配布版へのコピーは避けてください。

## 1. github.comから<wbr>ソースを<wbr>取得する

```sh
git clone --branch next https://github.com/matsumotory/ngx_mruby.git
cd ngx_mruby
git rev-parse HEAD
```

`next`は開発PRのマージで進みます。`git rev-parse HEAD`で使用したコミットを記録してください。過去のビルドを再現するときは、ビルド前にそのコミットをチェックアウトします。

mrubyのソースと、後述するサードパーティgemのロックはリポジトリに含まれます。ただし、ロックは外部取得をすべて固定するものではなく、バイナリの完全一致を保証しません。

## 2. mrbgemsを<wbr>設定する

`build_config.rb`には、ビルドがmrubyに入れるmrbgemsが書いてあります。`NGX_MRUBY_CORE_GEMS`のmrubyのコアのgemと、サードパーティのgemです。コアのgemの説明は[コアのgem](#コアのgem)にあります。ビルドのリファレンスの[デフォルトのmrbgems](../reference/build.md#デフォルトのmrbgems)には、デフォルトのビルドに入るサードパーティのgemと、それぞれが加えるクラスがあります。gemを加えるには、`build_config.rb`のhostのビルドに`conf.gem`の行を足します。ほかのgemは、mrubyの[mrbgemsの一覧](https://github.com/mruby/mruby/wiki/Related-Projects)にあります。`build_config.rb`でコメントになっている行には、mruby-discountやmruby-memcachedのような、デフォルトのビルドが入れないgemの名前があります。そのgemを入れてビルドするには、行のコメントを外してください。

`NGX_MRUBY_CORE_GEMS`が挙げるgemが、ビルドするmrubyの`mrbgems`ディレクトリに無いと、mrubyのビルドは止まります。たとえば、`./configure --with-mruby-root`で別のバージョンのmrubyを指定したときです。一覧を書き換えるか、mrubyのビルドの環境で`NGX_MRUBY_ALLOW_MISSING_CORE_GEMS=1`を設定して、通知を出してそれらのgemを飛ばしてください。

mruby-ioはデフォルトに含まれます。ファイル・ソケット・sleep・Redisの処理は、workerをブロックする場合があります。

同梱gemでも、nginxのイベント処理に対応するとは限りません。各APIの制約は[リファレンス](../../class_and_method/README.md)にあります。

3.0.0ではauto-sslを除外しました。[auto-sslのmrbgemと、それと一緒に入っていたクラス](#auto-sslのmrbgemとそれと一緒に入っていたクラス)で移行手順を説明します。

### コアのgem

同梱のmrubyは4.1.0-rc2で、mruby 4.1.0の2つ目のリリース候補です。ngx_mrubyは、mrubyの`full-core.gembox`ではなく、`NGX_MRUBY_CORE_GEMS`が挙げるコアのgemをビルドします。こうすると、ngx_mrubyのスクリプトのクラスとメソッドは、この一覧を変えたときにだけ変わります。一覧は、mruby 3.3.0の`full-core.gembox`が選んでいたgemの集合で、違いは次のとおりです。

- mruby-printはありません。mruby 3.4で削除されました。`Kernel#print`、`#puts`、`#p`はmruby-ioが定義します。

mruby 4.1には、hal-*のgemがありません。mruby-io、mruby-dir、mruby-socketが、POSIXのバックエンドをそれぞれ`ports/posix/`に持つので、一覧にはバックエンドの名前がありません。mruby 4.0.0向けに書いた一覧がhal-posix-io、hal-posix-dir、hal-posix-socketを挙げると、ビルドは止まります。`build_config.rb`の`ngx_mruby_core_gems`は、同梱のmrubyに無い名前があるとビルドを止めるためです。

mruby 4.1.0-rc2のコアのgemのうち、4.1.0-rc2の`full-core.gembox`は入れるのに、この一覧が入れないものは次のとおりです。

| gem | 入れると変わること | 入れない理由 |
|---|---|---|
| mruby-task | `Task`を加え、`Kernel#sleep`を定義し直す。`mrb_state`を開くすべてのプロセスに、SIGALRMのインターバルタイマーの`setitimer`がかかる。`mrb_state`は8つまでになる。上限は`MRB_TASK_MAX_VMS` | ワーカーのタイマーと`sleep`に関わる。ngx_mrubyには、`Nginx::Async`がある |
| mruby-encoding | ビルド全体に`MRB_UTF8_STRING`を定義する。`String#size`、`#[]`、`#index`などが、バイトではなく文字を数える。`String#valid_encoding?`、`#encoding`、`#force_encoding`を加える | リクエストとレスポンスのデータはバイト列で、`String#size`から`Content-Length`を計算するスクリプトは、違う数を得る。オーナーは2026年10月4日に、このgemをデフォルトのビルドから外し、オプトインのままにすると決めた。外したため、mruby 3.3ではmruby-string-extが定義していた`String#valid_encoding?`を呼ぶと、`NoMethodError`が起きる。mruby 3.4からは、mruby-encodingだけがこのメソッドを定義する |
| mruby-env、mruby-process、mruby-regexp | mruby 4.1で加わったgemで、`ENV`、`Process`、`Regexp`を定義する | デフォルトのビルドは、2.xと同じく、これらのクラスをiij/mruby-env、iij/mruby-process、mattn/mruby-onig-regexpから取る。mruby-regexpとmattn/mruby-onig-regexpを両方入れると、どちらも`Regexp`を定義する。iijの2つのgemはこれらのコアのgemと同じ名前を持つ。両方を入れたビルドは試していない。`ENV`と`Process`をコアのgemに移すのは後の変更で、3.0はmruby-onig-regexpを残す。根拠は`docs/proposals/v3-plan.md`の7節の1項 |
| mruby-signal | `Signal`を加える。mruby 4.1で加わった | 新しいAPIで、別に決める |
| mruby-string-bitops | `String`のビット演算を加える。mruby 4.1で加わった | 新しいAPIで、別に決める |
| mruby-strftime | `Time#strftime`を加える | 新しいAPIで、別に決める |
| mruby-benchmark | `Benchmark`を加える | 新しいAPIで、開発のツール |
| mruby-bin-mrb | コンパイラを持たずにバイトコードを実行する`mrb`コマンド。mruby 4.1で加わった | 新しいコマンドは入れない。デフォルトのビルドが持つコマンドは、mruby 3.3.0のときと同じ`mrbc`、`mruby`、`mirb`、`mruby-strip`、`mruby-config`の5つ |

4.1.0-rc2の`full-core.gembox`は、mruby-sleep、mruby-bin-debugger、mruby-testを入れません。ngx_mrubyは、`Kernel#sleep`と`#usleep`を定義するmruby-sleepを残しています。hw-*は、mruby 4.1のハードウェア用のgemです。`full-core.gembox`にも、この一覧にもありません。

mruby 4.1は、Rubyのコードを[Prism](https://github.com/ruby/prism)でコンパイルします。Prismのソースは`mruby/mrbgems/mruby-compiler/lib/prism`にあります。そのため、ngx_mrubyのチェックアウトやソースのアーカイブは、gitのサブモジュールを取ってこなくてもビルドできます。mrubyのビルドは、これまでと同じくRubyを実行し、Prismのテンプレートからソースを生成します。

一覧に載っていないgemを入れてビルドするには、`build_config.rb`の`NGX_MRUBY_CORE_GEMS`にその名前を足し、`mruby/build`を消してビルドし直してください。mruby-encodingを入れるときはリクエストやレスポンスのデータに`String#size`、`#length`、`#[]`、`#slice`、`#index`、`#reverse`を使うスクリプトをすべて確かめ、バイトを扱うところでは`#bytesize`と`#byteslice`を使ってください。`Nginx::Utils.escape`はもともとバイトを扱います。ngx_mruby自身のテストスイートは、mruby-encodingやmruby-taskを入れたビルドでは実行しません。

`String#valid_encoding?`を呼ぶスクリプトでは、上の確認をしたうえでmruby-encodingを入れるか、その呼び出しを消してください。2.xのデフォルトの`build_config.rb`は、`MRB_UTF8_STRING`を定義せずにmruby 3.3.0をビルドします。そのビルドでは、このメソッドはすべての文字列に`true`を返し、`"\xfe"`にも`true`を返しました。そのため、呼び出しを消しても、そのようなスクリプトが受け付けるものは変わりません。`build_config.rb`で`MRB_UTF8_STRING`を定義した2.xのビルドでは、UTF-8として正しくない文字列に`false`が返りました。その確認を残すには、`MRB_UTF8_STRING`とこのメソッドの両方を定義するmruby-encodingを入れてビルドしてください。

### gemの<wbr>コミットと<wbr>build_config.rb.lock

`build_config.rb`はサードパーティのmrbgemsを指定し、その隣にコミットした`build_config.rb.lock`は、それぞれのgemのコミットを記録します。こうすると、ngx_mrubyの同じコミットをチェックアウトすれば、どのマシンでも、後のいつでも、同じgemをビルドできるようになります。mrubyのrakeは、ビルドのたびに最後にこのファイルを書き、次のビルドの最初に読みます。

ロックには`build_config.rb`のmrubyのビルドごとにセクションがあります。ngx_mrubyがリンクするmrubyの`host`と、`test.sh`のテストを実行する`mruby`のバイナリの`test`です。各セクションのエントリーは、gemのリポジトリのURLをキーにして、gemのブランチ、コミット、バージョンを記録します。エントリーがあるのは、`build_config.rb`が`github:`で宣言するgemと、それらが依存してrakeが一緒にクローンするgemです。たとえば`host`には同梱のrack-based-apiが要るksss/mruby-stringioがあります。mruby自身のgemの`mruby/mrbgems/`と、`mrbgems/`の下の同梱のgemは、ソースツリーの一部なのでエントリーがありません。`mruby`のセクションは、同梱のmrubyのバージョンを記録します。

エントリーのあるgemでは、rakeはリポジトリを履歴ごと、`mruby/build/repos/host/`か`mruby/build/repos/test/`にクローンします。エントリーの無いgemに使う`--depth 1`は付けません。そして、記録したコミットをチェックアウトします。HEADはdetachedになります。ビルドの最後に、rakeは使ったクローンからロックを書き直します。デフォルトのgemの一覧では内容が変わらないので、ビルドの後も`git status`はきれいなままです。

rakeは、`mruby/build/repos/`の下にgemのディレクトリが無いときだけ、gemをクローンします。既にあるクローンは、fetchせずにロックのコミットでチェックアウトするので、そのコミットがクローンの中に無ければなりません。ロックを変えたときは、ビルドの前に`mruby/build`を消してください。`build_config.rb.lock`をまだコミットしていなかった頃の、ロックの無いビルドが残したクローンには、そのときブランチの先頭だったコミットしかありません。

gemを別のコミットに移すには、次のようにします。

1. `build_config.rb.lock`で、gemのエントリーがある各セクションの`commit:`を変えます。ブランチの現在の先頭を取るなら、エントリーを消します。
2. `rm -rf mruby/build`でクローンを消します。このコマンドは`build_config.rb.lock`を残します。ここでは`make clean_mruby`は使えません。`make clean_mruby`は何かを消す前にrakeを実行し、rakeは`build_config.rb`を読むときに既にある各クローンをロックのコミットでチェックアウトします。そのため、クローンにそのコミットが無いと、`fatal: reference is not a tree`で止まります。
3. `sh test.sh`か`sh build.sh`で、ビルドします。
4. rakeが書いた`build_config.rb.lock`をコミットします。

`build_config.rb`にgemを加えると、次のビルドはそのブランチの先頭をクローンし、そのgemと、それが依存するgemのエントリーをロックに加えます。変更と一緒にロックをコミットしてください。gemを消してもrakeはそのエントリーを残します。rakeは読んだエントリーをすべて書き戻すからです。そのためエントリーは自分でロックから消してください。同梱のmrubyを更新した後は、`mruby/build`を消してビルドし、更新と一緒にロックをコミットしてください。rakeは新しいバージョンを記録します。新しいmrubyが自分のgemとして持つようになった依存先はクローンしなくなるので、そのエントリーを消してください。

ビルドが取ってくるもののうち、ロックが固定しないものが2つあります。

- mruby/mgem-list。mrubyは、`mgem:`で宣言したgemのリポジトリや、ソースを指定せずに宣言した依存先のうちmruby自身のgemでないもののリポジトリを探すために、このgemの一覧の先頭をクローンします。デフォルトのgemの一覧には、mruby/mgem-listは必要ありません。mruby 4.0.0に更新する前までは、`test`のビルドに要りました。matsumotory/mruby-simplehttpは、`NO_SSL`を設定しない限り、ソースを指定せずにmruby-polarsslに依存し、その一覧がリポジトリのluisbebop/mruby-polarsslを返していました。そのgemはmruby 3.4で削除されたmruby-printに依存するので、今は`build_config.rb`が`test`のビルドに`NO_SSL`を設定しています。テストのクライアントの`SimpleHttp`はHTTPSを使えず、テストスイートはHTTPSのリクエストをcurlと`openssl s_client`で送ります。加えたgemにこの一覧が要る場合、ロックはgemのコミットを固定しますが、URLは一覧が決めます。一覧が別のURLを返すようになると、ロックにはそのエントリーが無いので、rakeはそのリポジトリの先頭をクローンします。そのため、`build_config.rb`はサードパーティのgemを`github:`で宣言します。
- symisc/vedis。matsumotory/mruby-vedisの`mrbgem.rake`は、gemのビルドのディレクトリの`mruby/build/host/mrbgems/mruby-vedis/vedis`が無いとき、`git clone`でvedisをそこにクローンします。このときクローンするのは、デフォルトのブランチの先頭です。

コミットを指定したクローンはリポジトリの履歴をすべて持つので、最初のビルドは、ロックの無いビルドより多くのデータを取ってきます。デフォルトのビルドは19個のクローンを作ります。`mruby/build/repos/host`に12個、`mruby/build/repos/test`に7個です。2026年10月4日に、空の`mruby/build`からビルドした後に測ると、クローンは約9.3 MiBで、内訳は7.7 MiBと1.7 MiBでした。mruby 4.0.0に更新する前は、`test`のビルドがluisbebop/mruby-polarsslとそのサブモジュールのARMmbed/mbedtlsもクローンしていました。当時デフォルトのビルドのクローンが使っていた約178 MiBの大部分は、これらでした。

## 3. バイナリを<wbr>ビルドする

### 3-A. build.shを使う

リポジトリのルートで、手順の対象となるnginxのソースを明示してビルドします。

```sh
NGINX_SOURCE_DIR="$(mktemp -d)/nginx"
git clone --depth 1 --branch release-1.31.8 https://github.com/nginx/nginx "$NGINX_SOURCE_DIR"
NGINX_SRC_ENV="$NGINX_SOURCE_DIR" sh ./build.sh
make install
./build/nginx/sbin/nginx -V
```

`build.sh`の担当は設定とコンパイルです。インストールには、別途`make install`を実行してください。

デフォルトのprefixは`$PWD/build/nginx`です。ビルドするユーザーが書き込めれば、`sudo`は必要ありません。

上流のgit checkoutを指定すると、nginx.orgのtarball取得に依存せずビルドできます。`NGINX_SRC_ENV`を省略すると、checkout内の`nginx_version`を使います。この開発版の設定は1.31.8です。他の版を選ぶ場合は、`nginx -V`と上流の変更を確認してください。

`NGINX_SRC_ENV`は既存のnginxソースを選びます。インストールまで終わる前に、そのツリーを消さないでください。

並列コンパイルは`NUM_THREADS_ENV=4`で4個に制限できます。

インストール先を変える場合は絶対パスを指定します。`NGINX_CONFIG_OPT_ENV`はデフォルトのnginxオプションを置き換えるため、必要なものをすべて列挙してください。

```sh
NGINX_SRC_ENV="$NGINX_SOURCE_DIR" NGINX_CONFIG_OPT_ENV="--prefix=$PWD/build/custom-nginx --with-stream --with-http_stub_status_module --with-cc-opt=-fno-common" sh ./build.sh
make install
```

### 3-B. Makefileを使う

既存のnginxソースには、`configure`と`make`でも同じ設定を指定できます。`NGINX_SOURCE_DIR`はnginxソースの絶対パスであり、インストール先のprefixではありません。

```sh
./configure --with-ngx-src-root="$NGINX_SOURCE_DIR" --with-ngx-config-opt="--prefix=$PWD/build/nginx --with-stream --with-cc-opt=-fno-common"
make
make install
```

現在のオプションは`./configure --help`で確認できます。`--with-build-dir`、`--with-mruby-root`、`--with-ndk-root`、`--with-openssl-src`、`--with-openssl-opt`などがあります。

`--with-mruby-incdir`を指定する場合は、mrubyの`build/host/include`も含めてください。デフォルトは`<mruby_root>/src <mruby_root>/include <mruby_root>/build/host/include`です。ngx_mrubyが使う`<mruby/presym.h>`は、この場所に生成されるヘッダを読み込みます。

### 3-C. nginx側からビルド

既存のnginxビルドへ加えるには、まずmrubyをビルドしてリンク設定を生成します。その後、nginxのconfigureにngx_mrubyと同梱NDKの両方を加えます。他に必要なnginxオプションも維持してください。

```sh
NGX_MRUBY_SOURCE_DIR="$PWD"
./configure --with-ngx-src-root="$NGINX_SOURCE_DIR"
make build_mruby
make generate_gems_config
cd "$NGINX_SOURCE_DIR"
# A git checkout uses auto/configure; a release tarball uses ./configure.
if [ -f auto/configure ]; then NGX_CONFIGURE=./auto/configure; else NGX_CONFIGURE=./configure; fi
"$NGX_CONFIGURE" --prefix="$NGX_MRUBY_SOURCE_DIR/build/nginx" --add-module="$NGX_MRUBY_SOURCE_DIR" --add-module="$NGX_MRUBY_SOURCE_DIR/dependence/ngx_devel_kit" --with-stream
make
make install
```

### ビルドのオプション

#### streamモジュールを有効にする

`build.sh`のデフォルトはstream有効です。独自のnginxオプションには`--with-stream`を含めます。TCP/UDPの検証方法は[streamディレクティブ](../../directives/README.md)と[テスト手順](../../test/README.md)にあります。

#### 自前のOpenSSLでビルドする

通常はシステムのOpenSSL開発パッケージを使います。

独自の版を使う場合は、ソースを展開して版を記録し、その絶対パスを指定してください。

```sh
NGINX_SRC_ENV="$NGINX_SOURCE_DIR" sh ./build.sh --with-openssl-src=/absolute/path/to/openssl-source
make install
```

過去のOpenSSL 1.0.2g取得例を、現在の推奨手順として使わないでください。独自のOpenSSLビルドには別途検証が必要です。

#### 動的モジュールとしてビルドする

ビルド方式を変えるときは、新しいcheckoutを使います。静的ビルドのnginx設定を再利用しないためです。そのシェルで、3-Aと同じ`release-1.31.8`の新しいソースツリーを`NGINX_SOURCE_DIR`へ設定してください。

```sh
NGINX_SRC_ENV="$NGINX_SOURCE_DIR" BUILD_DYNAMIC_MODULE=TRUE sh ./build.sh
make install
./build_dynamic/nginx/sbin/nginx -V
```

デフォルトのprefixは`$PWD/build_dynamic/nginx`です。`events`と`http`より前の**main**コンテキストで、そのインストール先のモジュールを読み込みます。

```nginx
load_module /absolute/path/to/ngx_mruby/build_dynamic/nginx/modules/ngx_http_mruby_module.so;
```

このモジュールと一緒にビルドしたnginxを使い、起動前に`nginx -t`で確認します。下の試用例を動的ビルドで使うときは、`NGX_BIN`をそのバイナリへ変更し、設定に絶対パスの`load_module`行を加えてください。

独自のビルドでは、設定と生成先を次のように揃えます。

- ngx_mrubyのconfigure：`--enable-dynamic-module`
- gem設定の生成：`make generate_gems_config_dynamic`
- nginxへのngx_mruby追加：`--add-dynamic-module`
- 同梱NDKの追加：`--add-module`

#### auto-sslのmrbgemと、それと一緒に入っていたクラス

ngx_mruby 3.0.0には、auto-sslのmrbgemがありません。このgemは`mrbgems/auto-ssl`にあり、`Nginx::SSL::ACME`のクラスを定義していました。mrubyのビルドは、`NGX_MRUBY_AUTO_SSL`をもう読みません。詳しくは[auto-sslのmrbgemと`NGX_MRUBY_AUTO_SSL`が無くなる](../../releases/v3.0.0.ja.md#auto-sslのmrbgemとngx_mruby_auto_sslが無くなる640)にあります。このgemの`Nginx::SSL::ACME::Client`はACMEv1の`new-reg`、`new-authz`、`new-cert`を使いますが、Let's EncryptはACMEv1のサービスを終えています。このgemがTLSのために必要とするpyama86/mruby-polarsslは、2017-03-03からコミットが無く、mruby 4ではビルドできません。`mruby/ext/io.h`をインクルードしますが、mruby 4.0はこのヘッダを`mruby/io.h`に改名しました。ACMEのサーバーから証明書を取得するには、nginx自身のモジュールである[ngx_http_acme_module](https://nginx.org/en/docs/http/ngx_http_acme_module.html)、つまりnginx-acmeを使ってください。`Nginx::SSL::ACME`が必要なサーバーは、2.xのビルドを使い続けてください。詳細は[2.xのドキュメント](https://github.com/matsumotory/ngx_mruby/blob/v2.7.2/docs/class_and_method/README.md#auto-ssl-mrbgem)を参照。

ngx_mruby 2.xは、auto-sslが依存するgemもビルドしていました。pyama86/mruby-acme-client、GPLでライセンスされたpyama86/mruby-polarssl、matsumotory/mruby-httprequest、matsumotory/mruby-simplehttp、mattn/mruby-http、mattn/mruby-base64、takahashim/mruby-forwardable、iij/mruby-tempfileです。デフォルトのビルドのほかのgemはこれらを必要としないので、3.0.0のデフォルトのビルドには、これらが定義するものもありません。

- クラスとモジュールの`Acme`、`CustomHttpRequest`、`OpenSSL`、`PolarSSL`、`HttpRequest`、`SimpleHttp`、`HTTP`、`Base64`、`Forwardable`、`FORWARDABLE`、`Tempfile`、`TempfilePath`
- iij/mruby-tempfileが`Dir`に加える`Dir.tmpdir`と`Dir.mktmpdir`、それらの補助の`Dir._tmpname`。`Dir`のクラス自体は、デフォルトのビルドに残ります。

`Dir.tmpdir`の代わりには、`ENV['TMPDIR'] || '/tmp'`を使ってください。mruby-tempfileの`Dir.tmpdir`は、`/tmp`に戻る前に`TMP`、`TEMP`、`USERPROFILE`も読んでいました。`Dir.mktmpdir`の代わりには、ほかのプロセスが使わない名前で`Dir.mkdir(path, 0700)`でディレクトリを作ってください。名前が既に使われていると`Dir.mkdir`は`Errno::EEXIST`を起こします。ブロック付きの`Dir.mktmpdir`は、ブロックが戻るとディレクトリと中身をすべて消していました。その場合は自分で消してください。`Dir.entries`で各ディレクトリの中身を一覧にし、`File.directory?`でファイルとディレクトリを見分けます。どちらもデフォルトのビルドにあります。ファイルは`File.delete`で、ディレクトリは`Dir.rmdir`で、深いものから先に消します。中身の残るディレクトリに`Dir.rmdir`を使うと、`Errno::ENOTEMPTY`が起きます。`Base64`の代わりには、デフォルトのビルドでも使えるコアの`pack('m0')`と`unpack1('m')`を使ってください。

```ruby
tmpdir = ENV['TMPDIR'] || '/tmp'                              # Dir.tmpdir
path = "#{tmpdir}/myapp-#{Process.pid}-#{SecureRandom.hex(8)}"
Dir.mkdir(path, 0700)                                         # Dir.mktmpdir('myapp-')
```

ほかの定数が要るなら、それを定義するgemを、自分の`build_config.rb`に`conf.gem`の行で加えてください。pyama86/mruby-polarsslに依存するgemは、mruby 4ではビルドが通りません。

## 4. ngx_mrubyを<wbr>インストールする

コンパイル後に`make install`を実行すると、設定済みのprefixへ配置されます。

この手順のprefixは`build/nginx`です。常に`/usr/local/nginx`へ入るわけではありません。

既存の本番prefixを更新する場合は、権限と更新計画を確認してください。以下の試用例は独立した実行先を使います。

## 5. Rubyの<wbr>スクリプトを<wbr>動かす

実行先とログには一時ディレクトリを使います。

- 待受先：`127.0.0.1:18088`
- 停止対象：例で起動したnginx

18088が使用中なら、例のポートを別の未使用番号に統一してください。

インストール後、リポジトリのルートで実行してください。以下は一つのシェルで続けて使うコマンドです。

```sh
(
set -eu
NGX_BIN="$PWD/build/nginx/sbin/nginx"
RUN_DIR="$(mktemp -d)"
mkdir -p "$RUN_DIR/logs"
printf 'Trial runtime: %s\n' "$RUN_DIR"
started=0
cleanup() {
    if [ "$started" = 1 ]; then "$NGX_BIN" -p "$RUN_DIR/" -c nginx.conf -s quit; fi
}
trap cleanup EXIT
cat > "$RUN_DIR/hello.rb" <<'RUBY'
Nginx::Headers_out.new["Content-Type"] = "text/plain"
Nginx.rputs "hello ngx_mruby\n"
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
        listen 127.0.0.1:18088;
        location = /inline {
            mruby_content_handler_code 'Nginx::Headers_out.new["Content-Type"] = "text/plain"; Nginx.rputs "hello ngx_mruby\\n"';
        }
        location = /script {
            mruby_content_handler "$RUN_DIR/hello.rb" cache;
        }
    }
}
CONF
"$NGX_BIN" -p "$RUN_DIR/" -c nginx.conf -t
"$NGX_BIN" -p "$RUN_DIR/" -c nginx.conf
started=1
curl --fail --show-error --silent --include http://127.0.0.1:18088/inline
curl --fail --show-error --silent --include http://127.0.0.1:18088/script
"$NGX_BIN" -p "$RUN_DIR/" -c nginx.conf -t && "$NGX_BIN" -p "$RUN_DIR/" -c nginx.conf -s reload
"$NGX_BIN" -p "$RUN_DIR/" -c nginx.conf -s quit
started=0
)
```

両URLの期待値：

- ステータス：`200`
- ヘッダ：`Content-Type: text/plain`
- 本文：`hello ngx_mruby`＋改行

`Date`・`Server`は環境依存です。

例はcontentフェーズで動き、リクエストをまたぐRuby状態を使いません。reloadはmasterプロセスを残してworkerを入れ替えます。graceful quitは、この実行用ディレクトリのPIDファイルを使います。

### 5-A. スクリプトファイル

`mruby_content_handler`はスクリプトのパスを取ります。例ではnginxの作業ディレクトリに依存しない絶対パスを指定します。

### 5-B. インラインコード

`mruby_content_handler_code`には、nginx設定内のRubyコードを渡します。

heredocの引用は、nginxとshellの両方を考慮してください。

### 5-C. スクリプトハンドラ

別のインターフェースとして`mruby_add_handler on`もあります。[ディレクティブリファレンス](../../directives/README.md)を参照してください。試用例は明示的なlocationを使い、すべての一致する`.rb`ファイルの実行を有効にしません。

スクリプトの`cache`はコンパイル結果をキャッシュします。省略すると、`mruby_cache on`が適用される場合を除き、リクエストごとに読み込みとコンパイルを行います。本番用のキャッシュを選ぶ前に、リファレンスで動作を確認してください。

## 6. nginxを<wbr>起動する

検証・起動・reload・quitには、インストールしたバイナリと同じ`-p`・`-c`を使います。システムの別の`nginx`へ置き換えないでください。そのバイナリにはngx_mrubyが入っていない場合があります。

## 7. 動作を<wbr>確認する

失敗したときは、設定を変える前に次を確認してください。

| 症状 | 確認すること |
|---|---|
| バイナリがない | `build.sh`はコンパイルまでです。`make install`と設定済みprefixを確認します。 |
| `unknown directive` | ビルドしたnginxを使います。動的ビルドはmainの`load_module`と対応バイナリを確認します。 |
| ビルドエラー | 開発用パッケージと、ビルドログの最初のエラーを確認する。 |
| 取得エラー | 対象タグのnginxを取得し、`NGINX_SRC_ENV`で指定。 |
| `bind()`に失敗 | 未使用ポートを選ぶ。他者のプロセスは停止しない。 |
| Ruby実行エラー | `$RUN_DIR/logs/error.log`を参照。絶対パス・権限・コードを確認。 |
| 本文の不一致 | `nginx -t`、URL・ポート・ログを確認。接続成功だけでは不十分です。 |

2026年10月29日、ngx_mruby開発版のコミット`6d65a12ecf166e11a6ece40d56f0f2efb05ea112`とnginx 1.31.8で検証しました。nginxは`release-1.31.8`を`NGINX_SRC_ENV`で指定し、Ubuntu 22.04 aarch64、GCC 11.4.0、Ruby 3.0.2/rake 13.0.6を使用しています。

静的ビルドは並列数4と`make install`で成功しました。第5節をそのまま抽出して実行し、両応答の200・text/plain・16バイト本文と、設定検証・reload・quitを確認しました。gem lockの変更はありません。

検証結果は、記録したコミットに対するものです。将来の`next`全体への保証ではありません。

独自prefix・nginx直接ビルド・動的モジュール・独自OpenSSLは、設定方法の説明です。この実行の検証対象には含めていません。

完全な統合テスト、sanitizer、対象nginxの版は[テスト手順](../../test/README.md)を参照してください。この試用は小さなHTTP例の確認です。独自モジュール・TLS・stream・性能・本番展開の検証ではありません。

## Dockerの<wbr>参考例

別リポジトリの[docker-ngx_mruby](https://github.com/matsumotory/docker-ngx_mruby)は過去の例です。ここで検証した版固定のインストールには含まれません。利用する場合は、イメージ・設定・依存を別途確認してください。

このソースビルドに、レジストリのアカウントは不要です。

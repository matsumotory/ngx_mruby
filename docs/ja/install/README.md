# インストール

このページでは、ngx_mrubyを組み込んだnginxをソースからビルドしてインストールします。インストールの前にngx_mrubyを試すには、「はじめに」のページの[例](../start/README.md)を動かしてください。その例は同じソースをDockerのコンテナの中でビルドし、Rubyのスクリプトを持つnginxを起動します。

## 前提

* git
* GNU make
* ruby
* rake
* bison
* openssl
* Cのコンパイラ。GCCかClang
* curl

## 1. github.comから<wbr>ソースを<wbr>取得する

```sh
$ git clone https://github.com/matsumotory/ngx_mruby.git
```

ngx_mrubyの特定のバージョンをビルドするには、そのバージョンのタグをチェックアウトしてください。

```sh
$ cd /path/to/ngx_mruby
$ git checkout v2.1.2
```

https://github.com/matsumotory/ngx_mruby/archive/master.zip か https://github.com/matsumotory/ngx_mruby/releases から、tarballをダウンロードすることもできます。

## 2. mrbgemsを<wbr>設定する

`build_config.rb`には、ビルドがmrubyに入れるmrbgemsが書いてあります。`NGX_MRUBY_CORE_GEMS`のmrubyのコアのgemと、サードパーティのgemです。コアのgemの説明は[コアのgem](#コアのgem)にあります。ビルドのリファレンスの[デフォルトのmrbgems](../reference/build.md#デフォルトのmrbgems)には、デフォルトのビルドに入るサードパーティのgemと、それぞれが加えるクラスがあります。gemを加えるには、`build_config.rb`のhostのビルドに`conf.gem`の行を足します。ほかのgemは、mrubyの[mrbgemsの一覧](https://github.com/mruby/mruby/wiki/Related-Projects)にあります。`build_config.rb`でコメントになっている行には、mruby-discountやmruby-memcachedのような、デフォルトのビルドが入れないgemの名前があります。そのgemを入れてビルドするには、行のコメントを外してください。

`NGX_MRUBY_CORE_GEMS`が挙げるgemが、ビルドするmrubyの`mrbgems`ディレクトリに無いと、mrubyのビルドは止まります。たとえば、`./configure --with-mruby-root`で別のバージョンのmrubyを指定したときです。一覧を書き換えるか、mrubyのビルドの環境で`NGX_MRUBY_ALLOW_MISSING_CORE_GEMS=1`を設定して、通知を出してそれらのgemを飛ばしてください。

3.0.0ではauto-sslを除外しました。[auto-sslのmrbgemと、それと一緒に入っていたクラス](#auto-sslのmrbgemとそれと一緒に入っていたクラス)で移行手順を説明します。

### コアのgem

同梱のmrubyは4.0.0です。ngx_mrubyは、mrubyの`full-core.gembox`ではなく、`NGX_MRUBY_CORE_GEMS`が挙げるコアのgemをビルドします。こうすると、ngx_mrubyのスクリプトのクラスとメソッドは、この一覧を変えたときにだけ変わります。一覧は、mruby 3.3.0の`full-core.gembox`が選んでいたgemの集合で、違いは次のとおりです。

- mruby-printはありません。mruby 3.4で削除されました。`Kernel#print`、`#puts`、`#p`はmruby-ioが定義します。
- 一覧には、hal-posix-io、hal-posix-dir、hal-posix-socketがあります。mruby 4.0.0では、mruby-io、mruby-dir、mruby-socketは、このどれかのバックエンドを通してOSを使います。これらのgemは、クラスもメソッドも加えません。これらがあるのは4.0.0だけです。mruby 4.1.0-rc2では、POSIXのバックエンドはmruby-io、mruby-dir、mruby-socketの一部になり、hal-*のgemはありません。そのため、mruby 4.1への更新で、この3つの名前を一覧から消します。

mruby 4.0.0のコアのgemのうち、4.0.0の`full-core.gembox`は入れるのに、この一覧が入れないものは次のとおりです。

| gem | 入れると変わること | 入れない理由 |
|---|---|---|
| mruby-taskと、hal-posix-task | `Task`を加え、`Kernel#sleep`を定義し直す。`mrb_state`を開くすべてのプロセスに、SIGALRMのインターバルタイマーの`setitimer`がかかる。`mrb_state`は8つまでになる。上限は`MRB_TASK_MAX_VMS` | ワーカーのタイマーと`sleep`に関わる。ngx_mrubyには、`Nginx::Async`がある |
| mruby-encoding | ビルド全体に`MRB_UTF8_STRING`を定義する。`String#size`、`#[]`、`#index`などが、バイトではなく文字を数える。`String#valid_encoding?`、`#encoding`、`#force_encoding`を加える | リクエストとレスポンスのデータはバイト列で、`String#size`から`Content-Length`を計算するスクリプトは、違う数を得る。オーナーは2026年10月4日に、このgemをデフォルトのビルドから外し、オプトインのままにすると決めた。外したため、mruby 3.3ではmruby-string-extが定義していた`String#valid_encoding?`を呼ぶと、`NoMethodError`が起きる。mruby 3.4からは、mruby-encodingだけがこのメソッドを定義する |
| mruby-strftime | `Time#strftime`を加える | 新しいAPIで、別に決める |
| mruby-benchmark | `Benchmark`を加える | 新しいAPIで、開発のツール |

4.0.0の`full-core.gembox`は、mruby-sleep、mruby-bin-debugger、mruby-testを入れません。ngx_mrubyは、`Kernel#sleep`と`#usleep`を定義するmruby-sleepを残しています。

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

ngx_mrubyのバイナリをビルドする方法は3つあります。

* build.shを使う
* Makefileを使う
* nginxのconfigureとmakeを使う

### 3-A. build.shを使う

build.shを使う方法が、バイナリをビルドするいちばん簡単な方法です。build.shは、nginxのソースを/path/to/ngx_mruby/buildのディレクトリに自動的にダウンロードしてngx_mrubyをビルドし、/path/to/ngx_mruby/build/nginxにインストールします。

```
$ cd /path/to/ngx_mruby
$ sh ./build.sh
```

次のようにすると、別のディレクトリにインストールできます。この例では、/path/to/ngx_mruby/build/nginxではなく/usr/local/nginx-1.15.6に、ngx_mrubyをビルドしてインストールします。

```sh
$ env NGINX_CONFIG_OPT_ENV='--prefix=/usr/local/nginx-1.15.6' sh ./build.sh
```

nginxのソースが既にあるなら、そのソースのディレクトリを指定できます。その場合、nginxのソースはダウンロードしません。

```
$ env NGINX_SRC_ENV='/usr/local/src/nginx-1.15.6' sh ./build.sh
```

### 3-B. Makefileを使う

もっと込み入ったビルドの設定には、configureのスクリプトとMakefileを使います。このスクリプトを実行する前に、[nginx](http://nginx.org/en/download.html)をダウンロードして展開しておいてください。

```sh
$ cd /path/to/ngx_mruby
$ ./configure --with-ngx-src-root=/local/src/nginx-1.15.6 --with-ngx-config-opt=--prefix=/usr/local/nginx-1.15.6
$ make
```

`configure --help`で、設定のオプションがすべて出ます。

```sh
$ ./configure --help
`configure' configures this package to adapt to many kinds of systems.

Usage: ./configure [OPTION]... [VAR=VALUE]...

[snip]

  --with-ngx-src-root=DIR pathname to ngx_src_root [[ngx_src_root]]
  --with-openssl-src=DIR  set path to OpenSSL library sources
  --with-build-dir=DIR    set build directory path
  --with-openssl-opt=OPTIONS
                          set additional build options for OpenSSL
  --with-ngx-config-opt=OPT
                          nginx configure option [[ngx_config_opt]]
  --with-mruby-root=DIR   pathname to mruby_root [[mruby_root]]
  --with-mruby-incdir=DIR include directory for mruby [[mruby_incdir]]
  --with-mruby-libdir=DIR library directory to libmruby [[mruby_libdir]]
  --with-ndk-root=DIR     pathname to ndk_root [[ndk_root]]

[snip]
```

`--with-mruby-incdir`を渡すときは、そのディレクトリの一覧に、mrubyのビルドの`build/host/include`ディレクトリを含めてください。デフォルトの一覧は`<mruby_root>/src <mruby_root>/include <mruby_root>/build/host/include`です。ngx_mrubyは`<mruby/presym.h>`をインクルードし、そのヘッダは、mrubyのビルドがそこに生成するヘッダをインクルードするからです。

### 3-C. nginxのconfigureとmakeを使ってビルドする

ngx_mrubyはnginxのモジュールなので、nginxのconfigureで--add-moduleのオプションを使うだけでビルドできます。

```sh
$ cd /path/to/ngx_mruby
$ ./configure --with-ngx-src-root=/local/src/nginx-1.15.6 --with-ngx-config-opt=--prefix=/usr/local/nginx-1.15.6
$ make build_mruby
$ make generate_gems_config
$ cd /local/src/nginx-1.15.6 
$ ./configure --prefix=/usr/local/nginx-1.15.6 --add-module=/path/to/ngx_mruby --add-module=/path/to/ngx_mruby/dependence/ngx_devel_kit --add-module=/path/to/nginx-module-you-want-to-build
$ make
```

### ビルドの<wbr>オプション

この節では、いくつかのビルドのオプションを説明します。

#### ngx_mrubyのstreamモジュールを使えるようにビルドする

ngx_mrubyのstreamモジュールを使うためには、nginxのconfigureのスクリプトに、オプションを渡す必要があります。

| nginxのバージョン | オプション |
|------------------|-----------|
| 1.11.5以降  | --with-stream |
| 1.9.6から1.11.4   | --with-stream --without-stream_access_module |
| 1.9.5以前 | 非対応 |

build.shでの例です。

```sh
$ env NGINX_CONFIG_OPT_ENV='--prefix=/usr/local/nginx-1.15.6 --with-stream' sh ./build.sh
```

#### 自前のOpenSSLでビルドする

システムのものでないOpenSSLでngx_mrubyをビルドするには、--with-openssl-srcのオプションを使います。

```sh
$ curl ftp://ftp.openssl.org/source/openssl-1.0.2g.tar.gz | tar -zx
$ cd /path/to/ngx_mruby
$ sh ./build.sh --with-openssl-src=/path/to/openssl-1.0.2g
```

configureのスクリプトも、このオプションを受け付けます。

```sh
$ curl ftp://ftp.openssl.org/source/openssl-1.0.2g.tar.gz | tar -zx
$ cd /path/to/ngx_mruby
$ ./configure --with-ngx-src-root=/local/src/nginx-1.15.6 --with-ngx-config-opt=--prefix=/usr/local/nginx-1.15.6 --with-openssl-src=/path/to/openssl-1.0.2g
$ make
```

#### 動的モジュールとしてビルドする

nginx 1.9.11以降は、動的なモジュールに対応しています。build.shを使うと、ngx_mrubyを動的なモジュールとしてビルドできます。このときbuild.shは、'build'ではなく'build_dynamic'のディレクトリを使います。結果は、/path/to/ngx_mruby/build_dynamicの下にあります。

```sh
$ env BUILD_DYNAMIC_MODULE=TRUE sh ./build.sh
```

nginx.confには、次のように、[load_module](http://nginx.org/en/docs/ngx_core_module.html#load_module)のディレクティブを加える必要があります。

```
load_module /path/to/modules/ngx_http_mruby_module.so;
```

build.shを使わない動的なビルドには、3つのステップが要ります。

* ngx_mrubyのconfigureのスクリプトに--enable-dynamic-moduleを渡す
* mrbgems_configの代わりに、mrbgems_config_dynamicを生成しておく
* nginxのconfigureに渡すオプションで、--add-module=PATHではなく、--add-dynamic-module=PATHを使う

例は次のとおりです。

```sh
$ cd /path/to/ngx_mruby
$ ./configure --enable-dynamic-module --with-ngx-src-root=/local/src/nginx-1.15.6 --with-ngx-config-opt=--prefix=/usr/local/nginx-1.15.6
$ make build_mruby
$ make generate_gems_config_dynamic
$ cd /local/src/nginx-1.15.6 
$ ./configure --prefix=/usr/local/nginx-1.15.6 --add-dynamic-module=/path/to/ngx_mruby --add-module=/path/to/ngx_mruby/dependence/ngx_devel_kit --add-module=/path/to/nginx-module-you-want-to-build
$ make
```

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

```sh
$ cd /path/to/ngx_mruby
$ sudo make install
```

## 5. Rubyの<wbr>スクリプトを<wbr>動かす

nginxは、ngx_mrubyのディレクティブがスクリプトのファイルを指定するか、コードそのものを持つところでRubyを実行します。「はじめに」の[ページ](../start/README.md)には、設定とスクリプトと、リロードせずにスクリプトを変える例があります。[ディレクティブ](../../directives/README.md)には、スクリプトのファイル、[インラインのコード](../../directives/README.md#inline-code)、[ハンドラとしてのスクリプトのファイル](../../directives/README.md#script-file-as-a-handler)の書き方があります。

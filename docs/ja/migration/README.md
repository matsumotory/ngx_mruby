# 3.0.0への移行

このガイドは、スクリプト、設定、ビルドを、ngx_mruby 2.xからngx_mruby 3.0.0へ移すためのものです。このガイドが扱う変更は、どれもv3.0.0のリリースノートの[アップグレードの前に読む挙動の変更](../../releases/v3.0.0.ja.md#アップグレードの前に読む挙動の変更)に1回ずつ書いてあります。2.xが何をしたか、3.0.0が何をするか、何に影響するか、何をすればよいかです。このガイドは、そのエントリーのそれぞれにリンクし、手順と例を加えます。エントリーが影響するスクリプトとビルドの見つけ方、スクリプトの変更の形、結果の確かめ方です。先に、動かしているバージョンより新しい2.xのリリースのリリースノートを読んでください。リリースノートは[docs/releases](../../releases/README.md)にあります。

ngx_mruby 2.xは、mruby 3.3.0を同梱しています。ngx_mruby 3の開発のラインは、mruby 4.1.0-rc2を同梱しています。これは、mruby 4.1.0の2つ目のリリース候補です。v3の計画の`docs/proposals/v3-plan.md`は、7節の決定1で、mruby 4.1.0をv3のmrubyとしています。オーナーは2026年10月29日に、タグを待たずに4.1.0-rc2を同梱すると決めました。4.1.0のタグが付いたら、開発のラインは4.1.0に移ります。同梱のmrubyのエントリーは、ngx_mrubyについて見つけて測った変更で、すべての変更の一覧ではありません。mruby自身が利用者に見える変更をまとめた一覧は、`mruby/`の`doc/mruby3.4.md`、`doc/mruby4.0.md`と、4.1の`NEWS.md`です。

## 手順

1. モジュールのビルドの方法を確かめます。[ビルド](#ビルド)の節を見てください。
2. エントリーが影響するスクリプトを見つけて、書き換えます。[スクリプト](#スクリプト)の節を見てください。
3. ログのパーサとアラートの設定を更新します。[ログの監視](#ログの監視)の節を見てください。
4. mrubyのC APIを使うmrbgemやほかのCのコードをメンテナンスしているなら、そのコードを確かめます。[C拡張とmrbgems](#c拡張とmrbgems)の節を見てください。
5. 結果を確かめます。[結果を確かめる](#結果を確かめる)の節を見てください。

## ビルド

- Ruby 3.0以降でビルドしてください。同梱のmrubyのビルドは、Ruby 2.xでは止まります。詳しくは[同梱のmrubyのビルドにRuby 3.0以降が要る](../../releases/v3.0.0.ja.md#同梱のmrubyのビルドにruby-30以降が要る678)にあります。`ruby --version`は、`PATH`にあるRubyのバージョンを出力します。
- このリリースの`build_config.rb`を使うなら、モジュールをビルドし直してください。同梱のmrubyも一緒にビルドします。詳しくは[同梱のmrubyが3.3.0から4.1.0-rc2になる](../../releases/v3.0.0.ja.md#同梱のmrubyが330から410-rc2になる561-678)にあります。
- 自前の`build_config.rb`を使うなら、コアのgemを選ぶ行を見つけてください。詳しくは[自前の`build_config.rb`は、mruby 4.1のコアgemの変更に合わせる必要がある](../../releases/v3.0.0.ja.md#自前のbuild_configrbはmruby-41のコアgemの変更に合わせる必要がある561-678)にあります。

  ```sh
  grep -nE 'gembox|mruby-print|hal-posix|mruby-task|mruby-encoding|mruby-sleep|mruby-env|mruby-process|regexp|ngx_mruby_core_gems' build_config.rb
  ```

  ngx_mrubyのデフォルトのビルドが入れるコアのgemを残すには、このリリースの`build_config.rb`から`NGX_MRUBY_CORE_GEMS`と`ngx_mruby_core_gems`をコピーし、そのファイルと同じように、`conf.gembox 'full-core'`の代わりに`ngx_mruby_core_gems(conf)`を呼んでください。gemを減らすビルドでは、`NGX_MRUBY_CORE_GEMS - %w[...]`を渡します。一覧に無いgemを加えるには、[コアのgem](../install/README.md#コアのgem)に従ってください。
- 新しくチェックアウトしたツリーやソースのアーカイブからのビルドは、サードパーティのmrbgemsを、`build_config.rb.lock`が記録するコミットで取ってきます。詳しくは[サードパーティのmrbgemを`build_config.rb.lock`が記録するコミットでビルドする](../../releases/v3.0.0.ja.md#サードパーティのmrbgemをbuild_configrblockが記録するコミットでビルドする558)にあります。`mruby/build`を残しているツリーでは、ロックを変えたら、次のビルドの前に`mruby/build`を消してください。消さないと、クローンに新しいコミットが無いときに、rakeが`fatal: reference is not a tree`で止まります。

  ```sh
  rm -rf mruby/build
  ```

  gemを別のコミットでビルドするには、[gemのコミットとbuild_config.rb.lock](../install/README.md#gemのコミットとbuild_configrblock)に従ってください。
- デフォルトのビルドには、auto-sslのmrbgemと、それと一緒に入っていたクラスがありません。詳しくは[既定のビルドからauto-sslのmrbgemと、それに伴うクラスが無くなる](../../releases/v3.0.0.ja.md#既定のビルドからauto-sslのmrbgemとそれに伴うクラスが無くなる556)にあります。それらを使うスクリプトを探す手順は、[スクリプト](#スクリプト)の節に書いてあります。
- このリリースのどのビルドにもauto-sslのmrbgemはなく、mrubyのビルドは`NGX_MRUBY_AUTO_SSL`をもう読みません。詳しくは[auto-sslのmrbgemと`NGX_MRUBY_AUTO_SSL`が無くなる](../../releases/v3.0.0.ja.md#auto-sslのmrbgemとngx_mruby_auto_sslが無くなる640)にあります。この変数は効かないので、ビルドの環境から外してください。`Nginx::SSL::ACME`で証明書を取得しているサーバーは、アップグレードの前にnginxの[ngx_http_acme_module](https://nginx.org/en/docs/http/ngx_http_acme_module.html)、つまりnginx-acmeに移るか、2.xを使い続けてください。次のコマンドで、それを使うビルドと設定を探します。

  ```sh
  grep -rnE 'NGX_MRUBY_AUTO_SSL|auto-ssl|Nginx::SSL::ACME' /path/to/build/scripts /path/to/nginx/conf
  ```
- `./configure --with-mruby-incdir`を使うなら、ディレクトリの一覧に`<mruby_root>/build/host/include`を加えてください。詳しくは[C拡張：`mruby.h`をインクルードするソースに、生成されたヘッダが必要になる](../../releases/v3.0.0.ja.md#c拡張mrubyhをインクルードするソースに生成されたヘッダが必要になる561)にあります。
- 自前やサードパーティのmrbgemsを使っているなら、[C拡張とmrbgems](#c拡張とmrbgems)の節を見てください。

## スクリプト

ほとんどのエントリーは、検索できるメソッドの名前を挙げています。次のコマンドは、設定のスクリプトのファイルからそれらを探します。`/path/to/scripts`は、`*_handler`のディレクティブが指定するファイルのディレクトリに置き換えてください。

```sh
grep -rnE 'valid_encoding\?|allbits\?|anybits\?|nobits\?|remove_const|module_function|append_features|prepend_features|extend_object|singleton_method_added|\.(included|extended|prepended|inherited|method_added)\(|initialize_copy|respond_to_missing|respond_to\?|method_defined\?|method_missing|instance_methods|\.methods|iv_var|default_proc *=|FileTest|srand|Random\.new|Set\.new|Set\[|flatten_merge|RuntimeError|\.server *=|upstream_server *=|SystemStackError' /path/to/scripts
```

`nginx.conf`のファイルにある`*_code`のディレクティブのインラインのコードも、同じように検索してください。次の項目では、名前だけでは足りないところで何を探すかを書き、変更の例を示します。

- [`Hash#inspect`と`Hash#to_s`の形式が変わる](../../releases/v3.0.0.ja.md#hashinspectとhashto_sの形式が変わる561)：値がHashかHashのArrayになるところで`inspect`、`to_s`、`"#{...}"`、`%s`を使う`sprintf`や`format`を探してください。スクリプトやテストが比べる文字列の`=>`も探してください。

  ```ruby
  h = {"q" => "x"}
  Nginx.rputs h.to_s               # 2.x: {"q"=>"x"}   3.0.0: {"q" => "x"}
  Nginx.rputs JSON.generate(h)     # {"q":"x"} on both
  ```

- [`Set#inspect`と`Set#to_s`の形式が変わり、`Set#flatten_merge`が無くなる](../../releases/v3.0.0.ja.md#setinspectとsetto_sの形式が変わりsetflatten_mergeが無くなる561)：Setについても、同じように検索してください。`set.to_a.join(",")`は、どちらのバージョンでも同じ文字列を返します。上の検索は、`flatten_merge`も見つけます。`s.flatten_merge(t)`は、`s.merge(Set.new(t).flatten)`に書き換えます。`t`がSetかArrayなら、この式はどちらのバージョンでも、2.xの`s.flatten_merge(t)`と同じSetを返します。`s.merge(t.flatten)`がそのSetを返すのは、`t`がSetのときだけです。`t`がArrayだと、`Array#flatten`は中のArrayを平坦化してSetを残し、`flatten_merge`とは逆になります。

  ```ruby
  t = [2, Set.new([3])]
  Set.new([1]).flatten_merge(t)            # 2.x: the Set of 1, 2 and 3   3.0.0: NoMethodError
  Set.new([1]).merge(Set.new(t).flatten)   # the Set of 1, 2 and 3 on both
  Set.new([1]).merge(t.flatten)            # the Set of 1, 2 and a Set that holds 3, on both
  ```

- [`NoMethodError`のメッセージがレシーバのクラスを示す](../../releases/v3.0.0.ja.md#nomethoderrorのメッセージがレシーバのクラスを示す561)：`rescue NoMethodError`の近くの`message`と、スクリプトの中の`undefined method`を探してください。

  ```ruby
  e.message == "undefined method 'foo'"   # 2.x: true   3.0.0: false (the message goes on with " for NilClass")
  ```

  メッセージを比べる代わりに、`NoMethodError`そのものをrescueしてください。
- [`private`と`protected`の制限が効く](../../releases/v3.0.0.ja.md#privateとprotectedの制限が効く561-678)：`self`以外のレシーバで呼んでいるものを探してください。対象は、`initialize`、`initialize_copy`、`respond_to_missing?`、`method_missing`、トップレベルで`def`で定義したメソッド、`raise`、`sprintf`、`puts`のような`Kernel`のメソッド、`private`か`protected`の下のメソッドです。ただし、ハンドラのコードでは、トップレベルで`def`で定義したメソッドはpublicのままなので、レシーバを付けた呼び出しを変える必要はありません。詳しくは[#502の構想](../../proposals/archive/handler-code-frame.md#14-what-handler-code-shares-today)の1.4節にあります。`Kernel.Integer(x)`のような`Kernel`自身に対する呼び出しは、どちらのバージョンでも動きます。`1.Integer("3")`のように、`Kernel`のメソッドを別のオブジェクトに対して呼ぶと、例外が出ます。`protected`のメソッドは、CRubyと同じく、同じクラスのメソッドの中からなら、そのクラスのオブジェクトをレシーバにして呼べます。上の検索は`instance_methods`と`methods`を見つけます。この2つはprivateのメソッドを含みません。そのような呼び出しの前に`respond_to?`で確かめても役に立ちません。`respond_to?`は、privateのメソッドにも`true`を返します。

  ```ruby
  class Router
    def call(r)
      pick(r)                  # no receiver: works on both
    end

    private

    def pick(r)
      r.uri
    end
  end

  Router.new.pick(r)           # 2.x: works   3.0.0: NoMethodError
  Router.new.send(:pick, r)    # works on both

  1.Integer("3")               # 2.x: 3   3.0.0: NoMethodError (private method 'Integer' called for Integer)
  Kernel.Integer("3")          # 3 on both
  Integer("3")                 # 3 on both
  ```

- [`Module#remove_const`、`#private`、`#public`、`#protected`、`#module_function`とフックがprivateになる](../../releases/v3.0.0.ja.md#moduleremove_constprivatepublicprotectedmodule_functionとフックがprivateになる561)：上の検索でほとんど見つかります。クラスやモジュールに対して呼んだ`.private(`、`.public(`、`.protected(`も探してください。たとえば、`Foo.remove_const(:X)`は`Foo.send(:remove_const, :X)`に書き換えます。
- [`append_features`、`prepend_features`、`extend_object`のオーバーライドが呼ばれなくなる](../../releases/v3.0.0.ja.md#append_featuresprepend_featuresextend_objectのオーバーライドが呼ばれなくなる561)：上の検索で見つかります。

  ```ruby
  module Plugin
    def self.append_features(base)   # 3.0.0: never called, and no error
      base.extend(ClassMethods)
      super
    end
  end

  module Plugin
    def self.included(base)          # called on both
      base.extend(ClassMethods)
    end
  end
  ```

- [`allbits?`、`anybits?`、`nobits?`が`Integer`だけのメソッドになる](../../releases/v3.0.0.ja.md#allbitsanybitsnobitsがintegerだけのメソッドになる561)：上の検索で見つかります。Floatの`x.allbits?(1)`は`x.to_i.allbits?(1)`に書き換えます。
- [`FileTest`がモジュールになる](../../releases/v3.0.0.ja.md#filetestがモジュールになる561)：上の検索で、`FileTest`が見つかります。書き換える必要があるのは、`FileTest.exist?`のようなメソッドの呼び出し以外の使い方だけになります。
- [メソッドの本体で定数に代入すると`SyntaxError`になる](../../releases/v3.0.0.ja.md#メソッドの本体で定数に代入するとsyntaxerrorになる561)：スクリプトをコンパイルすると、見つかります。[結果を確かめる](#結果を確かめる)の節を見てください。

  ```ruby syntax-error
  def setup
    Table = {}                       # 3.0.0: SyntaxError when the script is compiled
    Object.const_set(:Table, {})     # works on both
  end
  ```

- [文字列の中の`"#@ivar"`、`"#@@cvar"`、`"#$global"`が変数を展開する](../../releases/v3.0.0.ja.md#文字列の中のivarcvarglobalが変数を展開する678)：ダブルクォートの文字列、ヒアドキュメント、バッククォートのコマンドの中の`#@`と`#$`を探してください。次の検索はコメントも見つけます。見つけた行を1行ずつ読んでください。

  ```sh
  grep -rnE '#[@$]' /path/to/scripts
  ```

  ```ruby
  @id = 7
  Nginx.rputs "Ticket #@id"     # 2.x: Ticket #@id   3.0.0: Ticket 7
  Nginx.rputs "Ticket \#@id"    # Ticket #@id on both
  Nginx.rputs 'Ticket #@id'     # Ticket #@id on both
  ```

- [自分自身を持つ`Array`、`Hash`、`Struct`を比べられる](../../releases/v3.0.0.ja.md#自分自身を持つarrayhashstructを比べられる678)：上の検索は`SystemStackError`を見つけます。書き換える必要があるのは、そうした比較の周りでこの例外を`rescue`するスクリプトだけです。
- [Floatの値にビット演算が無くなる](../../releases/v3.0.0.ja.md#floatの値にビット演算が無くなる561)：Floatになりうる値に使った`<<`、`>>`、`&`、`|`、`^`、`~`を探してください。Floatになりうる値は`to_f`や`Float()`の結果とFloatとの演算の結果です。2.xと同じ数を得る方法は、エントリーにあります。

  ```ruby
  x = 1.5
  x << 1                # 2.x: 3   3.0.0: NoMethodError
  (x * 2).to_i          # 3, the number of 2.x for x << 1
  x.to_i << 1           # 2, another number
  ```

- [`String#valid_encoding?`が既定のビルドに無くなる](../../releases/v3.0.0.ja.md#stringvalid_encodingが既定のビルドに無くなる561)：上の検索で見つかります。2.xのデフォルトの`build_config.rb`では、このメソッドは、どの文字列にも`true`を返しました。そのため、次のような確認はリクエストを拒否したことがなく、消してもかまいません。

  ```ruby
  Nginx.return Nginx::HTTP_BAD_REQUEST unless s.valid_encoding?
  ```

- [シードを与えた`Random`が別の数を返す](../../releases/v3.0.0.ja.md#シードを与えたrandomが別の数を返す561)：上の検索で`srand`と`Random.new`が見つかります。シードを与えた乱数の生成器の数を期待するテストも探してください。
- [`Hash#default_proc=`がProcでないオブジェクトに`TypeError`を出す](../../releases/v3.0.0.ja.md#hashdefault_procがprocでないオブジェクトにtypeerrorを出す561)：上の検索で見つかります。`h.default_proc = proc { |hash, key| hash[key] = [] }`のように、Procを渡してください。
- [キーワード引数を受けるブロックに、キーワード引数を付けて`yield`すると動く](../../releases/v3.0.0.ja.md#キーワード引数を受けるブロックにキーワード引数を付けてyieldすると動く561)：変えるものはありません。この場合に備えて書いた`rescue ArgumentError`には、もう到達しません。
- [ハンドラのコードで、ブロックや`for`の本体の中の`return`がコードを終える](../../releases/v3.0.0.ja.md#ハンドラのコードでブロックやforの本体の中のreturnがコードを終える561)：スクリプトで変えるものはありません。ハンドラのコードのトップレベルにあるブロックや`for`の本体の中の`return`は、もう`LocalJumpError`を起こしません。ハンドラは、コードが`return`の前に設定したレスポンスで答えます。2.xは500で答えていました。2.7.0は、contentハンドラがそれまでに書いた出力とともに200で答えていました。`unexpected return (LocalJumpError)`のログのアラートは、この場合にはもう出ません。
- [出力なしで終わるcontentハンドラが、500でなく、空のボディの200で応答する](../../releases/v3.0.0.ja.md#出力なしで終わるcontentハンドラが500でなく空のボディの200で応答する574)：ボディを書かずに終わることがある`mruby_content_handler`と`mruby_content_handler_code`のハンドラを見てください。条件が成り立つときだけ書くハンドラ、`""`や`nil`になりうる値を`Nginx.rputs`に渡すハンドラ、レスポンスのヘッダだけを設定するハンドラ、`Nginx.return Nginx::HTTP_OK`か、201と204以外の200から299のステータスで終わるハンドラです。3.0.0では、これらは`Content-Length: 0`とともにそのステータスで答えます。ステータスを設定していなければ200です。2.7.1では、500で答えていました。500に頼っていたハンドラは、意図するステータスを設定してください。

  ```ruby
  body = Nginx::Request.new.headers_in["X-Answer"].to_s
  Nginx.rputs body                       # body "": 2.7.1 answers 500   3.0.0 answers 200 with Content-Length: 0

  if body.empty?
    Nginx.return Nginx::HTTP_NOT_FOUND   # 404 on both
  else
    Nginx.rputs body
  end
  ```

- [空のボディで終わる出力のボディフィルタが、接続を閉じずにレスポンスを送る](../../releases/v3.0.0.ja.md#空のボディで終わる出力のボディフィルタが接続を閉じずにレスポンスを送る574)：変えるものはありません。`Nginx::Filter#body=`や`#output`で`""`を設定するボディフィルタや、ボディの無いレスポンスのボディを空のままにするボディフィルタは、ステータスを`Content-Length: 0`とともに送ります。2.7.2までの2.xは、1バイトも送らずに接続を閉じていました。2.7.3も、このレスポンスを送ります。
- [`Nginx::Var`のアクセサが、ワーカーで最初に使われたときに`Nginx::Var`のメソッドになる](../../releases/v3.0.0.ja.md#nginxvarのアクセサがワーカーで最初に使われたときにnginxvarのメソッドになる610)：上の検索で`respond_to?`、`method_defined?`、`instance_methods`、`methods`が見つかります。そのうち、`Nginx::Var`のインスタンスか`Nginx::Var`そのものに対するものを見てください。変数についての答えは、そのワーカーが前にその名前にアクセスしたかどうかで変わるようになりました。代わりに`exist?`を使ってください。

  ```ruby
  v = Nginx::Var.new
  v.respond_to?(:request_method)   # 2.x: false   3.0.0: true after the first v.request_method in the worker
  v.exist?("request_method")       # true on both
  ```

  スクリプトが`Object`や`Kernel`に定義したメソッドのうち、スクリプトが`v.NAME`で読む変数と同じ名前のものも探してください。たとえば、ハンドラのコードのトップレベルの`def`で定義したメソッドです。ワーカーに変数のアクセサができると、`v.NAME`はそのメソッドを呼ばずに変数を読みます。そのメソッドの名前を変えてください。検索は`method_missing`も見つけます。`Nginx::Var#method_missing`をラップするスクリプトは、アクセサができる名前について、最初のアクセスしか見ません。たとえば、`Nginx::Var`にprependしたモジュールの`method_missing`が`super`を呼ぶ場合です。ラッパーがしていたことは、変数を読むコードへ移してください。
- [`Nginx::Connection`、`Nginx::Server`、`Nginx::Request`が、`Nginx::Var`を呼ばずに変数を読む](../../releases/v3.0.0.ja.md#nginxconnectionnginxservernginxrequestがnginxvarを呼ばずに変数を読む610)：スクリプトが`Nginx::Var`に定義したメソッドを探してください。`class Nginx::Var`、`Nginx::Var.class_eval`、`define_method`による定義と、上の検索で見つかる`iv_var`です。`Nginx::Var`のメソッドを変えても、`Nginx::Connection#remote_ip`やエントリーにあるほかのメソッドの戻り値は、もう変わりません。代わりに、`Nginx::Connection`のような、そのメソッドを持つクラスにメソッドを定義してください。定義は、nginxが設定を読むときに1回だけ動く`mruby_init_code`に書きます。ハンドラのコードは、同じ`mrb_state`の中でリクエストのたびに動きます。そのため、ハンドラのコードに書くと、2回目の`alias_method`で`nginx_remote_ip`が新しい`remote_ip`のコピーになり、それが自分自身を呼ぶことになります。

  ```nginx
  mruby_init_code '
      class Nginx::Connection
        alias_method :nginx_remote_ip, :remote_ip
        def remote_ip
          Nginx::Request.new.headers_in["X-Real-IP"] || nginx_remote_ip   # works on both
        end
      end
  ';
  ```

- [`Dir`をmrubyのコアgemが定義するようになり、閉じた`Dir`が`RuntimeError`でなく`IOError`を出す](../../releases/v3.0.0.ja.md#dirをmrubyのコアgemが定義するようになり閉じたdirがruntimeerrorでなくioerrorを出す559)：上の検索で、`RuntimeError`が見つかります。そのうち、閉じることのある`Dir`か、`Dir`を閉じるブロックを付けた`Dir.open`の例外をrescueしているものを見てください。

  ```ruby
  d = Dir.open(path)
  d.close
  begin
    d.read
  rescue RuntimeError            # 2.x: rescued   3.0.0: not rescued (IOError)
  end
  begin
    d.read
  rescue IOError, RuntimeError   # rescued on both
  end
  ```

- [`Nginx::Upstream#server=`と`Nginx::Stream::Connection#upstream_server=`が、serverにできない文字列に`ArgumentError`を出す](../../releases/v3.0.0.ja.md#nginxupstreamserverとnginxstreamconnectionupstream_serverがserverにできない文字列にargumenterrorを出す680)：上の検索は、2つのsetterと`RuntimeError`を見つけます。そのうち、setterの例外をrescueする箇所を見てください。

  ```ruby
  u = Nginx::Upstream.new "backend"
  begin
    u.server = "192.0.2.1:notaport"
  rescue RuntimeError                # 2.x: rescued   3.0.0: not rescued (ArgumentError)
  end
  begin
    u.server = "192.0.2.1:notaport"
  rescue ArgumentError, RuntimeError # rescued on both
  end
  ```

- [`Nginx::Upstream#server=`が、ホスト名を名前解決せずに`ArgumentError`を出す](../../releases/v3.0.0.ja.md#nginxupstreamserverがホスト名を名前解決せずにargumenterrorを出す680)：上の検索は、このsetterを見つけます。スクリプトがsetterに渡す値を見てください。リクエストやファイルから読む値も確かめてください。

  ```ruby
  u.server = "localhost:8080"        # 2.x: resolved while the worker waits   3.0.0: ArgumentError
  u.server = "127.0.0.1:8080"        # works on both
  ```

  IPv4アドレスは4つの10進数で書いてください。`127.1`も例外になります。nginxの動作中に変わらない名前は、`upstream {}`ブロックの`server`の行に書き、setterを呼ばないでください。nginxは、この名前のすべてのアドレスを使います。アドレスが2つ以上あると、`Nginx::Upstream.new`はそのupstreamに`RuntimeError`を出すので、その呼び出しも削除するか、`server`の行にIPアドレスを書いてください。解決できない名前があると、nginxは起動しません。

- [既定のビルドからauto-sslのmrbgemと、それに伴うクラスが無くなる](../../releases/v3.0.0.ja.md#既定のビルドからauto-sslのmrbgemとそれに伴うクラスが無くなる556)：次のコマンドでデフォルトのビルドに無くなった定数と`Dir`の2つのメソッドを探します。

  ```sh
  grep -rnE 'Nginx::SSL::ACME|Acme|HttpRequest|OpenSSL|PolarSSL|SimpleHttp|(^|[^:])HTTP::|Base64|Forwardable|FORWARDABLE|Tempfile|tmpdir' /path/to/scripts
  ```

  `Base64`、`Dir.tmpdir`、`Dir.mktmpdir`には、デフォルトのビルドで使える代わりがあります。

  ```ruby
  Base64.encode(s)          # 3.0.0: NameError (uninitialized constant Base64)
  [s].pack('m0')            # the same string on both
  Base64.decode(b)          # 3.0.0: NameError
  b.unpack1('m')            # the same string on both
  Dir.tmpdir                # 3.0.0: NoMethodError
  ENV['TMPDIR'] || '/tmp'   # works on both
  ```

  `Dir.mktmpdir`の代替は、[auto-sslのmrbgemと、それと一緒に入っていたクラス](../install/README.md#auto-sslのmrbgemとそれと一緒に入っていたクラス)にあります。ほかの定数に必要なgemは`conf.gem`で追加します。

- [`Nginx::Async.sleep`で待つaccessハンドラとpost_readハンドラが、待たないときと同じように終わる](../../releases/v3.0.0.ja.md#nginxasyncsleepで待つaccessハンドラとpost_readハンドラが待たないときと同じように終わる715)：`mruby_access_handler*`と`mruby_post_read_handler*`のコードで`Nginx::Async.sleep`を探してください。`satisfy any`では、sleepの後に結果なしで終わるaccessハンドラが、リクエストを許可します。拒むべきハンドラは、sleepの後にステータスを返してください。

  ```ruby
  Nginx::Async.sleep 100
  # 2.x: without a result, the request reached its content and the connection closed
  # 3.0.0: without a result, nginx allows the request under satisfy any
  Nginx.return Nginx::HTTP_FORBIDDEN unless allowed?   # on both: denies under satisfy all; under satisfy any nginx tries the other access handlers
  ```

- [出力を書くaccessハンドラとpost_readハンドラが、レスポンスの後にリクエストを終える](../../releases/v3.0.0.ja.md#出力を書くaccessハンドラとpost_readハンドラがレスポンスの後にリクエストを終える715)：変えるものはありません。このハンドラは1回だけ応答し、nginxは接続を保ちます。2.xはフェーズを続けて接続を閉じていました。このハンドラが出していた`header already sent`の行に対するログのアラートは、もう発生しません。
- [結果を設定しないハンドラが、前のハンドラの結果を引き継がない](../../releases/v3.0.0.ja.md#結果を設定しないハンドラが前のハンドラの結果を引き継がない715)：すべてのリクエストで`Nginx.return`を呼ぶserver rewrite、rewrite、post_read、accessのハンドラを探してください。例えば`mruby_server_rewrite_handler_code 'Nginx.return Nginx::DECLINED'`です。出力もステータスも無く終わることのある後のcontentハンドラと、`satisfy any`で結果なしで終わることのあるaccessハンドラは、この値を引き継がなくなります。先へ進むべきハンドラは、自分でその値を返してください。

  ```ruby
  # mruby_content_handler_code, on a server whose server rewrite handler returns Nginx::DECLINED
  Nginx.rputs body if body    # no body: 2.x went on to the static module   3.0.0 answers 200 with Content-Length: 0
  Nginx.return Nginx::DECLINED unless body   # goes on to the static module on both
  ```

- [`Nginx::Async.sleep`で待つ`mruby_set`のハンドラが変数を設定し、リクエストが先へ進む](../../releases/v3.0.0.ja.md#nginxasyncsleepで待つmruby_setのハンドラが変数を設定しリクエストが先へ進む715)：`mruby_set`と`mruby_set_code`で`Nginx::Async.sleep`を探してください。sleepの後に`Nginx.return`でリクエストを終えていたコードは、そのステータスを後のハンドラから返してください。例えば、変数を読むrewriteハンドラから返します。

- [結果なしで終わるrewriteハンドラとserver rewriteハンドラが、次のフェーズのハンドラへ進む](../../releases/v3.0.0.ja.md#結果なしで終わるrewriteハンドラとserver-rewriteハンドラが次のフェーズのハンドラへ進む720)：`Nginx.return`無しか`Nginx.return Nginx::OK`で終わることのある`mruby_rewrite_handler*`と`mruby_server_rewrite_handler*`のハンドラを見てください。2.xでは、nginxはこのリクエストに応答せずに終えていました。3.0.0では、リクエストはlocationのcontentへ進みます。リクエストを終えるハンドラは、意図するステータスを返してください。

  ```ruby
  # mruby_rewrite_handler_code
  Nginx::Var.new.set "backend", "a"          # no result: 2.x sends no response   3.0.0 goes on
  Nginx.return Nginx::HTTP_FORBIDDEN if deny # 403 on both
  ```

- [`Nginx::Async::HTTP.sub_request`がcontentハンドラで、`Nginx::Async.sleep`の後でも動く](../../releases/v3.0.0.ja.md#nginxasynchttpsub_requestがcontentハンドラでnginxasyncsleepの後でも動く722)：`mruby_content_handler*`のコードで、`sub_request`の周りの`RuntimeError`の`rescue`を探して削除してください。呼び出しはレスポンスを返します。

  ```ruby
  Nginx::Async.sleep 100
  res = Nginx::Async::HTTP.sub_request "/backend"   # 2.7.3: RuntimeError, 500   3.0.0: the response
  Nginx.rputs res.body
  ```

- [`Nginx::Async::HTTP.sub_request`で待つハンドラが、コードを1回だけ実行し、待たないときと同じように終わる](../../releases/v3.0.0.ja.md#nginxasynchttpsub_requestで待つハンドラがコードを1回だけ実行し待たないときと同じように終わる722)：ほとんどのスクリプトでは、変えるものはありません。3.0.0では、`sub_request`を呼ぶaccessハンドラとpost_readハンドラは、リクエストにつき1回だけ動きます。サブリクエストの後にコードがもう一度動くことに頼っていた処理は、サブリクエストのレスポンスを使える呼び出しの後に書いてください。

- [UDPのstreamのセッションがコードを1回だけ実行し、コードが待っている間に届いたデータグラムでは始め直さない](../../releases/v3.0.0.ja.md#udpのstreamのセッションがコードを1回だけ実行しコードが待っている間に届いたデータグラムでは始め直さない727)：`listen ... udp`のサーバーのコードで`Nginx::Stream::Async.sleep`を探してください。3.0.0では、コードはセッションにつき1回だけ動き、sleepの間に届いたデータグラムでは始め直しません。
- [`worker_shutdown_timeout`が切れたときに待っているstreamのセッションが、そこで終わる](../../releases/v3.0.0.ja.md#worker_shutdown_timeoutが切れたときに待っているstreamのセッションがそこで終わる727)：変えるものはありません。`worker_shutdown_timeout`がある設定で、タイムアウトが切れたときにまだsleepしているstreamのセッションは、sleepの後のコードを実行せずに終わります。
- [ローカルのURIへの`Nginx.redirect`が、ハンドラが終わったときに効く](../../releases/v3.0.0.ja.md#ローカルのuriへのnginxredirectがハンドラが終わったときに効く728)：ハンドラで、パスを渡す`Nginx.redirect`を探してください。3.0.0では、呼び出しの後のコードがリダイレクト先より先に動き、書いた出力と設定したステータスはクライアントへ送られません。そのコードが設定したレスポンスのヘッダと、変えたリクエストの引数は、リダイレクト先に届きます。

  ```ruby
  Nginx.redirect "/backend"
  Nginx.rputs "fallback"       # 2.x: sent with the answer of /backend   3.0.0: not sent, warn line
  return                        # leave the handler when the code after the call should not run
  ```
- [`mruby_set`のハンドラでは`Nginx::Async::HTTP.sub_request`が`RuntimeError`を出す](../../releases/v3.0.0.ja.md#mruby_setのハンドラではnginxasynchttpsub_requestがruntimeerrorを出す735)：`mruby_set`と`mruby_set_code`で、`Nginx::Async::HTTP.sub_request`を探してください。サブリクエストを待てるrewriteかaccessのハンドラで呼び、`Nginx::Var#set`で変数を設定してください。
- [`mruby_set`の値をStringに変換できないと500で応答する](../../releases/v3.0.0.ja.md#mruby_setの値をstringに変換できないと500で応答する735)：コードがString以外の値を返しうる`mruby_set`と`mruby_set_code`を探し、Stringを返すようにしてください。

`Dir.children`、`Dir#each_child`、`Dir.empty?`と、`Dir`に対する`Enumerable`のメソッドは、2.xのスクリプトには新しいものです。最初の2つは`.`と`..`を含みません。詳しくは[新機能](../../releases/v3.0.0.ja.md#新機能)にあります。

## ログの<wbr>監視

- [`Exception#inspect`の形式が変わり、`error.log`の`mrb_run failed`の行も変わる](../../releases/v3.0.0.ja.md#exceptioninspectの形式が変わりerrorlogのmrb_run-failedの行も変わる561)：ログのパーサとアラートのルールで、`mrb_run failed`の行に対するパターンと、行の最後にある括弧の中の例外のクラスを探してください。

  ```
  2.x:    mrb_run failed: return 500 HTTP status code to client: error: boom (RuntimeError)
  3.0.0:  mrb_run failed: return 500 HTTP status code to client: error: #<RuntimeError: boom>
  ```

  `\(RuntimeError\)$`のようなパターンは、`#<RuntimeError: `に書き換えます。
- [`NoMethodError`のメッセージがレシーバのクラスを示す](../../releases/v3.0.0.ja.md#nomethoderrorのメッセージがレシーバのクラスを示す561)：メッセージの後に` for <class>`が続くので、`undefined method 'foo'`で終わるパターンはもう一致しなくなりました。
- [nginxが設定を読む間のメッセージのレベルが`notice`から`info`になる](../../releases/v3.0.0.ja.md#nginxが設定を読む間のメッセージのレベルがnoticeからinfoになる565)：ログのパーサ、アラートのルール、起動のスクリプトで、`mechanism enabled`、`compile info`、`target variable`、`ngx_mruby NOTICE`を探してください。nginxは、起動しても、もうこれらの行を書きません。`nginx -t`は、これらを`[info]`で起動時のログに書きます。起動時のログは`-e`で指定したファイルで、指定しなければnginxに組み込んだエラーログのパスです。デフォルトでは、プレフィックスの下の`logs/error.log`です。nginxが起動時のログの行を端末にも出すのは`warn`以上だけなので、`nginx -t`の出力にはこれらの行が出ません。

  ```
  2.x, start:                 [notice] ... ngx_mruby/<version> (mruby/3.3.0) mechanism enabled in ...
  3.0.0, start:               no such line
  3.0.0, nginx -t:            [info] ... ngx_mruby/<version> (mruby/4.1.0) mechanism enabled in ...   (startup log only)
  3.0.0, nginx -t -e stderr:  [info] ... ngx_mruby/<version> (mruby/4.1.0) mechanism enabled in ...   (terminal)
  ```

  モジュールが読み込まれたことをこれらの行で確かめるには、`nginx -t -e stderr`を実行してその出力を読むか、`nginx -t`の後に起動時のログを読んでください。

  ```sh
  nginx -t -e stderr 2>&1 | grep 'mechanism enabled'
  ```

- [構文エラーのメッセージがPrismのものになる](../../releases/v3.0.0.ja.md#構文エラーのメッセージがprismのものになる678)：`unexpected end of file`のような、`syntax error`の後の文面に対するパターンは、もう一致しません。`SyntaxError`と、ファイルの名前と行に一致させてください。

  ```
  2.x:    file (eval) line 1: syntax error, unexpected end of file
  3.0.0:  file (eval) line 1: syntax error, unexpected end-of-input; expected an expression after the operator
  ```

- [出力なしで終わるcontentハンドラが、500でなく、空のボディの200で応答する](../../releases/v3.0.0.ja.md#出力なしで終わるcontentハンドラが500でなく空のボディの200で応答する574)：`response body is empty. return NGX_HTTP_INTERNAL_SERVER_ERROR`に対するパターンは、メインのリクエストのcontentハンドラが出力なしで終わり、ステータスを設定していないか、nginxが自分では答えない200から299のステータスを設定しているときには、もう一致しません。200未満のステータスと、ほかのハンドラとサブリクエストで出力なしの`Nginx::HTTP_OK`には、今も一致しています。
- [空のボディで終わる出力のボディフィルタが、接続を閉じずにレスポンスを送る](../../releases/v3.0.0.ja.md#空のボディで終わる出力のボディフィルタが接続を閉じずにレスポンスを送る574)：nginxがこれらのレスポンスを送るので、`zero size buf in writer`のアラートは、もう出ません。

## C拡張と<wbr>mrbgems

次のコマンドは、gemのCのソースや、mrubyを組み込むプログラムのCのソースで、下のエントリーが扱う箇所を探します。

```sh
grep -rnE 'Data_Wrap_Struct|mrb_data_object_alloc|MRB_SET_INSTANCE_TT|MRB_ARGS_|mruby/ext/io\.h|mrb_alloca|mrb_open|allocf|MRB_NO_PRESYM' src/
```

- [C拡張：`MRB_TT_DATA`と宣言していないクラスのオブジェクトでは、Cのデータをラップできない](../../releases/v3.0.0.ja.md#c拡張mrb_tt_dataと宣言していないクラスのオブジェクトではcのデータをラップできない561)：`Data_Wrap_Struct`や`mrb_data_object_alloc`がオブジェクトを作るクラスには、どれも`mrb_define_class`の後にこの宣言が要ります。

  ```c
  struct RClass *c = mrb_define_class(mrb, "Uname", mrb->object_class);
  MRB_SET_INSTANCE_TT(c, MRB_TT_DATA);
  ```

- [C拡張：mrubyが、Cのメソッドに渡す引数の数を引数仕様で検査する](../../releases/v3.0.0.ja.md#c拡張mrubyがcのメソッドに渡す引数の数を引数仕様で検査する561)：各`mrb_define_method`の引数の仕様と、その`mrb_get_args`が読むものを、両方向で比べてください。`MRB_ARGS_REQ(2)`で定義し、`mrb_get_args(mrb, "S", &s)`で文字列を1つ読み、引数1つで呼ばれるメソッドは、`ArgumentError`を起こします。このメソッドは、`MRB_ARGS_REQ(1)`で定義してください。`MRB_ARGS_REQ(1)`で定義し、`"o|o"`を読み、引数2つで呼ばれるメソッドも例外を起こします。このメソッドは`MRB_ARGS_ARG(1, 1)`で定義してください。
- [C拡張：ヘッダと関数の名前が変わり、失敗したときの`mrb_open()`の戻り値が変わる](../../releases/v3.0.0.ja.md#c拡張ヘッダと関数の名前が変わり失敗したときのmrb_openの戻り値が変わる561)：例を示します。

  ```c
  #include <mruby/io.h>                    /* was <mruby/ext/io.h> */
  void *buf = mrb_temp_alloc(mrb, size);   /* was mrb_alloca(mrb, size) */
  mrb_state *mrb = mrb_open();             /* also in place of mrb_open_allocf(my_allocf, ud) */
  if (MRB_OPEN_FAILURE(mrb)) { /* ... */ } /* was: if (mrb == NULL) */

  /* a custom allocator, in place of mrb_default_allocf() or my_allocf */
  void *mrb_basic_alloc_func(void *ptr, size_t size) { /* ... */ }
  ```

- [C拡張：`mruby.h`をインクルードするソースに、生成されたヘッダが必要になる](../../releases/v3.0.0.ja.md#c拡張mrubyhをインクルードするソースに生成されたヘッダが必要になる561)：そのようなソースをmrubyのビルドの外でコンパイルするところでは、`-I<mruby>/include`の隣に`-I<mruby>/build/host/include`を加えてください。

## 結果を<wbr>確かめる

1. すべてのスクリプトを、mruby 4.1.0-rc2の`mrbc`でコンパイルします。このリリースを`sh build.sh`か`sh test.sh`でビルドした後なら、`mruby/bin/mrbc -c`でスクリプトの構文を確かめられます。`mrbc -c`は`Syntax OK`を出力するか、エラーの行を出力して終了ステータス1で終わります。メソッドの本体で定数に代入したときのエラーの行は、`<file>:2:3: syntax error, dynamic constant assignment`です。

   ```sh
   for f in /path/to/scripts/*.rb; do mruby/bin/mrbc -c "$f" || echo "check: $f"; done
   ```

2. スクリプトのうち`Nginx`のクラスを呼ばない部分を、両方のバージョンのmrubyで実行します。mruby 4.0.0のエントリーは、2026年10月4日から10月14日の間に、この方法で測りました。同じRubyのスクリプトを2つの`mruby`のバイナリで実行しました。1つはngx_mruby 2.xに同梱のmruby 3.3.0から、もう1つは、mruby 4.0.0からビルドしたものです。どちらもUbuntu 22.04とgcc 11を使うDockerのコンテナの中でビルドし、mrubyの`default`のgemboxか、各バージョンのngx_mrubyのビルドのコアのgemを使いました。コアのgemは、3.3.0では`full-core`とiij/mruby-dir、4.0.0では`NGX_MRUBY_CORE_GEMS`です。mruby 4.1.0-rc2のエントリーは、2026年10月29日と10月31日に測りました。使ったのは、ngx_mrubyのhostのビルドが4.0.0と4.1.0-rc2で作った`mruby`コマンドと、mruby 3.3.0を`default`のgemboxでビルドした`mruby`コマンドです。「ngx_mrubyのテストスイートでもこの変化が出ました」と書いたエントリーは、ngx_mruby自身のレスポンスかログの行も変わったものです。同じことをするには、各バージョンの`mruby/`ディレクトリを別々のディレクトリにコピーし、それぞれで`rake MRUBY_CONFIG=default`を実行して、両方の`bin/mruby`でスクリプトを実行します。rakeは`mruby/build`にビルドし、そこにはモジュールのビルドが使うmrubyがあります。そのため、このrakeをngx_mrubyのチェックアウトの`mruby/`で実行しないでください。
3. テスト用のサーバに、このリリースのモジュールと設定を入れて動かし、各ハンドラに届くリクエストを送ります。そして、`error.log`で、`NoMethodError`、`TypeError`、`ArgumentError`、`SyntaxError`を含む`mrb_run failed`の行を探します。

次のものは同じ方法で確かめて変わっていなかったので、確かめる必要はありません。`String#size`と`#length`はバイトを数えます。mruby-encodingのgemはデフォルトのビルドに入っていません。詳しくは[コアのgem](../install/README.md#コアのgem)にあります。ほかに、引数の数が違うときの`ArgumentError`、`Exception#message`、`Struct#inspect`、`Float#to_s`、Integerの除算と剰余、mruby-sleepの`Kernel#sleep`と`#usleep`も変わっていません。

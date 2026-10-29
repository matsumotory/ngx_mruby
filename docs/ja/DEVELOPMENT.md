# ngx_mrubyの開発

このページには、ngx_mrubyの開発者に役立つヒントを、順不同で集めています。

Cのモジュールの`src/`、`mrbgems/`のgem、ビルドを変える前に、AGENTS.mdの[Design principles](../../AGENTS.md#design-principles)を読んでください。そこには、オーナーの決定と、セッションがその決定を当てはめる方法が書いてあります。オーナーの決定は、ワーカーごとに1つの`mrb_state`を持つこと、ブロックしないこと、今の性能を保ち、性能を測ることです。当てはめる方法には、どの変更をどう測るかも含まれます。

## 推奨する<wbr>開発環境

ngx_mrubyの開発には、vagrantを使っています。

開発するときは、同じ開発環境を使うとよいでしょう。

### 開発環境を<wbr>用意する

```
cd ngx_mruby
vagrant up       # run provisioner automatically
vagrant ssh
```

### ubuntu 18.04の<wbr>開発環境で<wbr>テストする

```
cd ngx_mruby/
sh test.sh
```

### Cの<wbr>ソースコードを<wbr>フォーマットする

スクリプトの`apply-clang-format`を実行します。

```
cd ngx_mruby
sh apply-clang-format
```

## 新しい<wbr>バージョンの<wbr>nginxに<wbr>対応する

[nginx_version](../../nginx_version)と[.travis.yml](../../.travis.yml)を編集します。例は https://github.com/matsumotory/ngx_mruby/commit/02ddb38b68702d9abe8fb0a8c172ee1d80ad2b2d にあります。

TODO：古いバージョンのnginxへの対応を終える方針は、まだ書いていません。

## mrubyを<wbr>更新する

このリポジトリのツリーにある[mruby](../../mruby)を最新のバージョンに更新するには、スクリプトの[update-mruby-subtree](../../update-mruby-subtree)を使えます。このスクリプトは、mrubyのupstreamのリポジトリをdep-mrubyとして加え、すべての変更を今のブランチへpullします。

```
git checkout -b BRANCH
sh update-mruby-subtree
```

特定のコミットに更新するときは、refを指定できます。

```
sh update-mruby-subtree REF
```

このスクリプトは`git subtree pull --prefix=mruby --squash dep-mruby REF`を実行します。そのため、マージは、`mruby/`の履歴にある最後のsubtreeのsquashから始まります。そのsquashが古いときや、subtreeのpullでないコミットが`mruby/`を変えていたときは、pullは`mruby/`の下のコンフリクトで止まります。コンフリクトを手で解決しないでください。`mruby/`の下のファイルは、決して手で編集しません。代わりに、止まったマージの中で、次のコマンドでsubtreeをrefのツリーと同じ内容に置き換え、マージをコミットします。

```
git rm -r -q --cached mruby
rm -rf mruby
git read-tree --prefix=mruby/ -u REF^{tree}
```

タグをローカルのタグとしてfetchしていないときは、ここでは`REF`にコミットのidを使ってください。`update-mruby-subtree`は、refを`FETCH_HEAD`にだけfetchします。`git read-tree`は、ツリーのすべてのファイルを書きます。このリポジトリの`.gitignore`が`git add`から外すファイルも書きます。たとえば、`mruby/Makefile`と、`mruby/lib/mruby/build/`の下のファイルです。コミットする前に、インデックスの`mruby/`の下にrefのツリーがあることを確かめてください。次の2つのコマンドは、同じidを出力しなければなりません。

```
git write-tree --prefix=mruby/
git rev-parse REF^{tree}
```

それから、マージをコミットし、2つのidをコミットメッセージに書きます。

```
git commit
```

コミットの後は、`git rev-parse HEAD:mruby`も同じidを出力します。

`git subtree`が作ったsquashのコミットは、マージの2つ目の親です。このコミットは`git-subtree-split: <commit of REF>`を記録するので、次の更新は、古いsquashではなく、このコミットからマージします。マージは、`mruby/`の外を何も含めずに、単独でコミットしてください。ビルドの変更は、その後のコミットでします。

[build_config.rb](../../build_config.rb)の`NGX_MRUBY_CORE_GEMS`は、ngx_mrubyがビルドするmrubyのコアのgemを、名前で挙げます。そのため、mrubyを更新しただけでは、ビルドするコアのgemは変わりません。一覧のgemが新しい`mruby/mrbgems`に無いと、mrubyのビルドは止まります。そのgemを一覧から消すか置き換えるかは、別の決定として決めてください。更新の作業中にビルドを続けるには、`NGX_MRUBY_ALLOW_MISSING_CORE_GEMS=1`を設定します。ビルドは、無いgemを、通知を出して読み飛ばします。新しいmrubyが加えたgemは、一覧に加えるまでビルドしません。

更新の後は、`mruby/build`を消して`sh test.sh`でビルドし、rakeが更新とともに書いた`build_config.rb.lock`をコミットしてください。ロックは、mrubyのバージョンを記録します。rakeはビルドの最後にロックを書きます。一方、`NGX_MRUBY_CORE_GEMS`のチェックは、rakeが`build_config.rb`を読み込む間にビルドを止めます。そのため、一覧のすべてのgemが見つかるか、`NGX_MRUBY_ALLOW_MISSING_CORE_GEMS=1`を設定するまで、rakeは新しいロックを書きません。新しいmrubyが自分のgemとして持つようになった依存先は、もうクローンしません。しかし、rakeはロックにそのエントリーを残すので、そのエントリーを消してください。詳しくは、[インストール](install/README.md#gemのコミットとbuild_configrblock)の「gemのコミットとbuild_config.rb.lock」にあります。

## ngx_devel_kitを<wbr>更新する

このリポジトリのツリーにある[ngx_devel_kit](../../dependence/ngx_devel_kit)を最新のバージョンに更新するには、スクリプトの[update-devkit-subtree](../../update-devkit-subtree)を使えます。このスクリプトは、ngx_devel_kitのupstreamのリポジトリをdep-ngx_devel_kitとして加え、すべての変更を今のブランチへpullします。

```
git checkout -b BRANCH
sh update-devkit-subtree
```

特定のコミットに更新するときは、refを指定できます。

```
sh update-devkit-subtree REF
```

## v3を<wbr>masterへ<wbr>昇格する

v3を昇格するまでは、`master`が2.xの系列です。v3は`next`で開発し、`v2.x`は`master`を自動でコピーしたブランチです。`master`へのpushのたびに、ワークフローの[mirror-v2x.yml](../../.github/workflows/mirror-v2x.yml)が、`v2.x`を`master`へfast-forwardします。昇格では、v3.0.0の時点で`next`を`master`へマージします。こうすると、`master`は3.xの系列になり、`v2.x`が2.xの系列を引き継ぎます。詳しくは[Branch strategy](../../README.md#branch-strategy)にあります。この節は、昇格の手順です。

エージェントがプルリクエストを用意し、チェックを実行します。[AGENTS.md](../../AGENTS.md#branches-and-pull-requests)に書いてあるとおり、タグを作り、リリースを公開するのはオーナーです。下の手順では、昇格を始める許可と、手順2と3のリポジトリの設定も、オーナーに任せています。これらの部分は推奨です。下の「決まっていないこと」を見てください。

2026-10-04の時点で、リポジトリにはルールセットが4つあります。手順3は、そのうち最初の2つを変えます。

- `protected-lines`は、`master`と`next`に掛かります。変更は、プルリクエストを通してだけ入ります。`ci-ok`のチェックが通らなければなりません。削除とforce pushはできません。
- `v2x-mirror`は、`v2.x`に掛かります。削除とforce pushはできません。プルリクエストのルールはありません。そのルールがあると、ミラーのワークフローのpushが拒まれるからです。
- `release-tags`は、`v*`のタグに掛かります。タグを作り、動かし、消せるのは、リポジトリの管理者だけです。
- `no-branch-shaped-tags`は、`v*.x`、`next`、`master`、`main`のタグに掛かります。だれもこれらのタグを作れません。そのため、`v2.x`のような名前は、いつもブランチを指します。

### 条件

手順1の前に、オーナーは次のすべてが成り立つことを確かめ、昇格を始める許可を出します。

1. `next`に`v3.0.0-rc.N`のプレリリースのタグを付けてあります。そのタグでCIが通り、そのタグに対して報告された不具合のうち、リリースを止めるものはありません。最後のリリース候補をどれだけの期間公開しておくかは、決まっていません。下の「決まっていないこと」を見てください。
2. v3の移行ガイドと、v3.0.0のリリースノートが完成しています。
3. 昇格する前に出す2.xの最後のリリースには、`master`でタグを付けてあります。そのリリースノートのエントリーも記録してあります。そのタグの後にマージした2.xの修正は、`v2.x`から出す次の2.xのリリースに入ります。
4. 下の決まっていないことを決め、v3の計画かこの節に記録してあります。手順4では、昇格した後のブランチの状態を説明します。その説明は、`next`が何になるか、修正が系列の間をどう移るか、サイトがどのバージョンを示すかで変わります。

### 手順

1. **最後に`master`を`next`へマージします。エージェントの作業です。**ほかの`master`から`next`へのマージと同じく、プルリクエストで`master`を`next`へマージします。こうすると、`next`にすべての2.xの修正が入ります。ここから手順5まで、`master`へはほかに何もマージしません。2.xの修正が待てないときは、手順2の前にその修正をマージし、この手順を繰り返します。
2. **ミラーを止めます。オーナーの作業です。**`v2.x`と`master`が同じコミットを指すことを確かめます。このとき、`git ls-remote origin refs/heads/master refs/heads/v2.x`は、1つのidを2回出力します。idが違うときは、`gh workflow run mirror-v2x.yml --ref master`で、`master`でワークフローを実行します。`gh run list --workflow=mirror-v2x.yml`で実行が終わるまで待ち、もう一度確かめます。実行が失敗したときは、そのジョブのログに`v2.x`の直し方が書いてあります。たとえば、`master`に無いコミットが`v2.x`にあるときや、`workflows`の権限が無いためにpushが拒まれたときです。idが一致するまで、ワークフローを無効にしないでください。一致したら、`gh workflow disable mirror-v2x.yml`で無効にします。これ以降、`v2.x`は2.xの最後のコミットに留まります。この手順は、手順5の前にしてください。手順5で作るマージコミットの最初の親は`v2.x`の先頭なので、そのpushでワークフローが動くと、`v2.x`が3.xへfast-forwardされます。手順4は手順5のマージコミットからワークフローのファイルを消すので、それでもワークフローは動きません。ここで無効にすると、手順4に頼らずに`v2.x`を守れます。
3. **ほかの系列と同じように`v2.x`を保護します。オーナーの作業です。**`protected-lines`の対象に`refs/heads/v2.x`を加え、`v2x-mirror`を消します。それ以降、`v2.x`は、`ci-ok`が通ったプルリクエストを通してだけ変わります。CIを変える必要はありません。[test.yml](../../.github/workflows/test.yml)は、既に`v*.x`へのpushとプルリクエストで動きます。
4. **`next`を準備します。エージェントの作業です。**`next`への2つのプルリクエストを、次の順にマージします。
   - 1つ目のプルリクエストは、`.github/workflows/mirror-v2x.yml`を消し、昇格の後のブランチを説明します。説明するのは、README.mdのブランチの運用、AGENTS.mdのブランチのテーブルとルール、SECURITY.mdのサポートするバージョン、`.github/PULL_REQUEST_TEMPLATE.md`の「Target branch」です。2.xの修正は`v2.x`を対象にし、v3の修正は`master`を対象にします。このプルリクエストは、`.github/dependabot.yml`に、`target-branch: "v2.x"`を持つ2つ目の`github-actions`のエントリーも加えます。こうすると、手順5からは、`master`のこのファイルにそのエントリーがあります。Dependabotはこのファイルをデフォルトブランチからだけ読み、`target-branch`の無いエントリーではデフォルトブランチだけを更新します。そのため、新しいエントリーが無いと、2.xをサポートする間、`v2.x`のワークフローでSHAに固定したactionが更新されません。
   - 2つ目は、`docs/releases/v3.0.0.md`についての、[「タグの前に」](releases/README.md#タグの前に)のチェックのプルリクエストです。その節が`next`について書くとおり、範囲は最後の`v3.0.0-rc.N`のタグから始まります。このプルリクエストは、そのタグの後に`master`を`next`へマージしたことで入った2.xのプルリクエストに、2.xのファイルのエントリーがあることを確かめます。そのマージには、手順1のマージも含まれます。また、タグがまだ無い2.xのリリースについて、そのエントリーを`v3.0.0.md`へコピーします。それらは、条件3で書いた2.xの最後のリリースより後にマージした、2.xの修正のエントリーです。v3.0.0がそれらの修正を最初に出すので、コピーします。このプルリクエストの後は、手順5まで、`next`へほかに何もマージしません。
5. **昇格します。エージェントの作業で、その日にオーナーが許可を出してから始めます。**headが`next`でベースが`master`のプルリクエストを作ります。ほかのすべてのプルリクエストと同じく、[AGENTS.md](../../AGENTS.md#review-and-merge)の「Review and merge」の条件が成り立ったときに、マージコミットでマージします。ただし、マージするのは、手順6ですぐにタグを付けることを、オーナーがその日に確かめた後だけです。こうすると、`master`がタグの無い3.xの系列になる時間がありません。手順1で`master`を`next`へマージしたので、このプルリクエストにコンフリクトはありません。`master`はデフォルトブランチのままです。デフォルトブランチについては、何も変わりません。
6. **タグを付けてリリースします。オーナーの作業で、手順5の直後にします。**手順5のマージコミットに`v3.0.0`のタグを付け、そのGitHubのリリースを、リリースノートとともに公開します。リリースには、プレリリースの印を付けません。チェックのプルリクエストのマージコミットではなくこのコミットにタグを付けるのは、[「タグの前に」](releases/README.md#タグの前に)にある「後のコミット」の場合です。チェックのプルリクエストの後にマージしたプルリクエストについて、チェックを繰り返します。そのようなプルリクエストは手順5の昇格だけで、エントリーは要りません。手順1の後は`master`が`next`の祖先なので、手順5で作るマージコミットのツリーは`next`と同じです。そのため、設定、スクリプト、ビルドから見えるものは何も変わりません。
7. **告知します。エージェントの作業です。**`master`へのプルリクエストで、v3.0.0をリリースした日と、その12か月後に2.xのサポートが終わる日を、README.mdとSECURITY.mdに加えます。`v2.x`へのプルリクエストでは、次のことをします。
   - `v2.x`のREADME.md、AGENTS.md、SECURITY.md、プルリクエストのテンプレートで、`v2.x`を2.xの系列として説明します。
   - `v2.x`にある`mirror-v2x.yml`のコピーを消します。このワークフローを起動するのは`master`へのpushだけなので、そのコピーは動きません。
   - `v2.x`のファイルにある`master`への絶対のリンクを、`v2.x`へ向けます。`v2.x`では、これらのリンクの先が3.xのファイルになるからです。対象は、このリポジトリの`tree/master`と`blob/master`のURL、README.mdにあるCIのバッジの`badge.svg?branch=master`、`docs/install/README.md`にあるダウンロードのリンクの`archive/master.zip`です。URLは、2026-10-04の時点で、README.md、`docs/`、プルリクエストのテンプレートに24個あります。
   - `docs/install/README.md`、`Dockerfile`、`misc/provision.sh`にある、デフォルトブランチのクローンに`-b v2.x`を加えます。対象は、`-b`の無い`git clone https://github.com/matsumotory/ngx_mruby.git`です。これが無いと、`v2.x`のインストールガイドに従った2.xの利用者も、`v2.x`のチェックアウトからDockerfileをビルドした利用者も、3.xを得ます。

   リンク、バッジ、クローンは、次のコマンドで一覧できます。`git grep -n -E 'ngx_mruby/(tree|blob|archive)/master|branch=master|clone https://github\.com/matsumotory/ngx_mruby'`。サイトをv3に切り替えることになったときは、その変更もこの手順でマージします。切り替えるかどうかは、「決まっていないこと」にあります。
8. **昇格の後の運用です。**2.xの修正は`v2.x`を対象にし、v3の修正は`master`を対象にします。オーナーは、2.xの各リリースを、リポジトリの最新のリリースにならないように公開します。最新のリリースは3.xのままにします。コマンドは`gh release create <tag> --latest=false`です。REST APIでは、公開したリリースの`make_latest`のデフォルトは`true`です。Webのフォームでは、「Set as latest release」を選ばないでください。

### 決まっていない<wbr>こと

v3の計画は、次のことをまだ決めていません。どれにも推奨があります。条件4は、手順1の前にこれらを決めることを求めています。

- **昇格の後に`next`が何になるか。**推奨：次のマイナーリリースの3.1を開発するブランチとして残し、プレリリースのタグを付けます。こうすると、`master`は、デフォルトブランチの利用者がビルドする、リリースした3.xの系列のままになります。今の`master`が、リリースした2.xの系列であるのと同じです。もう1つの選択肢は、`next`をやめて、3.1を`master`で開発することです。
- **v3.0.0の前に、最後のリリース候補をどれだけの期間公開しておくか。**推奨：リリースを止める新しい報告が無いまま、少なくとも2週間です。
- **昇格の後、両方の系列に要る修正をどう移すか。**推奨：先に`master`を直し、その修正を`backport/v2.x/<topic>`のブランチで`v2.x`へバックポートします。この名前は、AGENTS.mdが既にバックポートに付けている名前です。`v2.x`を`master`へマージすると、2.xのためだけの変更も入ります。
- **昇格の許可を出し、手順2と3でリポジトリの設定を変えるのはだれか。**推奨：オーナーです。条件1が成り立つかは判断です。手順6のタグはオーナーが付け、設定には管理者の権限が要ります。設定を誤ると、`v2.x`が3.xへ動くおそれがあります。AGENTS.mdは、昇格の許可、リポジトリの設定、`gh-pages`へのプルリクエストを、まだ扱っていません。`gh-pages`はサイトのブランチで、次の項目で扱います。AGENTS.mdのブランチのテーブルには`master`、`next`、`v2.x`しか無いので、今は、エージェントは`gh-pages`へのプルリクエストをマージできません。「Review and merge」の条件1が成り立たないからです。
- **昇格の後、サイトがどのバージョンを示すか。**サイトのngx.mruby.orgは、GitHub Pagesで`gh-pages`のブランチから配信しています。このサイトは1ページだけで、最後に変わったのは2020年です。v3の計画は、サイトが完成したら`v3.0.0-rc.1`のタグを付けるとしています。これは計画の6節のステップ8です。推奨：v3.0.0からは、サイトはv3を示し、`v2.x`のブランチにある2.xのドキュメントへ、`https://github.com/matsumotory/ngx_mruby/tree/v2.x/docs`でリンクします。こうすると、2.xの利用者もそのドキュメントを見つけられます。エージェントは、手順5の前に、切り替えを`gh-pages`へのプルリクエストとして用意し、手順7で、オーナーがタグを付けた後にマージします。マージするのは、AGENTS.mdが`gh-pages`を扱うようになってからです。前の項目を見てください。

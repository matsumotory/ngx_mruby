# ドキュメント

これは、ブランチ`next`で開発しているngx_mruby 3.xのドキュメントです。ページは4種類あります。ngx_mrubyを動かしてみるページ、作業ごとのガイド、リファレンス、それらの背景にあるコンセプトです。

## ページの<wbr>一覧

- [はじめに](start/README.md)：DockerでRubyのハンドラを持つnginxを動かしてから、スクリプトを書き換えます
- ガイド：[インストール](../install/README.md)、[バックエンドへリクエストを振り分ける](guides/routing.md)、[ファイルに載せたクライアントを拒否する](guides/access-control.md)、[APIキーごとにレートを制限する](guides/rate-limit.md)、[レスポンスのボディを変える](guides/body-filter.md)、[RubyでTCPの接続を許可する](guides/tcp.md)、[ユースケースの一覧](../use_case/README.md)、開発版の[エージェントプロキシ](guides/agent-proxy.md)
- リファレンス：[ディレクティブ](../directives/README.md)、[Rubyのクラスとメソッド](../class_and_method/README.md)、[ビルド](../reference/build.md)
- コンセプト：[リクエストのフェーズ](concepts/request-phases.md)、[フィルタ](concepts/filters.md)、[ブロックせずに待つ](concepts/async.md)、[ライフタイム](concepts/lifetimes.md)の4つのページ
- リリース：[リリースノート](../releases/README.md)、[ngx_mruby 2.xから3.0.0への移行](../migration/README.md)。リリースノートは、アップグレードする前に読む挙動の変更から始まります
- セキュリティ：[セキュリティポリシー](../../SECURITY.md)、[信頼境界](../security/trust-boundary.md)。信頼境界のページには、ngx_mrubyが何を信頼し、何をクライアントの入力として扱い、スクリプトが何に責任を持つかを書いています
- 開発に参加する：[開発に参加する](../../CONTRIBUTING.md)、[テスト](../test/README.md)、[ngx_mrubyの開発](../DEVELOPMENT.md)、[作業の状態](../HANDOFF.md)

## ブランチと<wbr>リリース

- [ブランチの運用](../../README.md#branch-strategy)：`master`、`next`、`v2.x`が何を持つか、2.xに留まるには何に固定すればよいか
- [v3をmasterへ昇格する](../DEVELOPMENT.md#promoting-v3-to-master)：メンテナーのための昇格の手順

## ライセンス

ngx_mrubyのソフトウェアライセンスは[MITライセンス](../../MITL)です。

<!--
The h2 headings of this page have <wbr> at their phrase boundaries
(docs/proposals/site.md, 4.4). site/scripts/check-japanese.mjs checks that
the built h2 keep them as elements, and fails when no h2 of docs/ja/ has one.
-->

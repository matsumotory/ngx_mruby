# ドキュメント

nginx内のRubyでリクエストの処理を組み立てます。ここは<strong>v3の開発ブランチ<code>next</code></strong>の文書です。実装済みの挙動と今後の計画を区別しています。リリース済みの2.7系は[安定版のドキュメント](https://ngx.mruby.org/v2/ja/)を参照してください。

## 動く例を<wbr>試す

- [モデル振り分けを試す](start/README.md#modelで転送先を選ぶ)：Rubyの対応表で転送先と認証情報を変え、同じ内容を再送します。プロバイダのキーは不要です。
- [インストール](install/README.md)：nginxに合わせたビルドと必要な環境、オプション、更新時の確認。

## アプリに<wbr>規則を加える

- [LLMプロキシ](guides/agent-proxy.md)：利用者キーの検査、モデル振り分け、同時実行制限、ストリーム中継。計画中の拡張は明示しています。
- [HTTPの振り分け](guides/routing.md)：リクエストの情報からバックエンドを選択。
- [アクセス制御](guides/access-control.md)：ローカルの拒否リストにある接続元を拒否。
- [レート制限](guides/rate-limit.md)：APIキーごとの制限。
- [レスポンスのフィルタ](guides/body-filter.md)：レスポンスボディの変更。
- [TCPの中継](guides/tcp.md)：接続元を確認。
- [MCPゲートウェイの設計案](guides/mcp-gateway.md)：未検証の構成と、未確認の範囲や境界。

## APIや<wbr>ビルド設定を調べる

- [ディレクティブ](../directives/README.md)：nginxがRubyを呼ぶ場所と設定。
- [Rubyのクラスとメソッド](../class_and_method/README.md)：ハンドラで使えるAPI。
- [ビルドのリファレンス](reference/build.md)：コンパイルオプションと同梱gem。

## リクエストの流れを<wbr>理解する

- [リクエストのフェーズ](concepts/request-phases.md)：ハンドラの実行順。
- [ヘッダ・ボディ断片の制約](concepts/filters.md)。
- [ブロックせずに待つ](concepts/async.md)：nginxへ処理を委ねる方法。
- [ライフタイム](concepts/lifetimes.md)：worker内の共有状態とリクエスト単位の状態。

## 運用と<wbr>アップグレード

- [リリースノート](../releases/README.md)：挙動の変更。
- [2.xからの移行](migration/README.md)：v3へ移る際に必要な変更。
- [信頼境界](../security/trust-boundary.md)：モジュールと各スクリプトが検証する範囲。
- [セキュリティポリシー](../../SECURITY.md)：サポート対象と非公開での脆弱性報告。

## 開発に参加し<wbr>進捗を追う

- [開発に参加する](../../CONTRIBUTING.md)：変更の範囲、レビュー、貢献の手順。
- [テスト](../test/README.md)：テストの種類と実行方法。
- [開発の手順](../DEVELOPMENT.md)：ブランチの運用と共同作業の引継ぎ。
- [現在の作業](../HANDOFF.md)：日付付きの作業・公開記録。
- [ブランチの運用](../../README.md#branch-strategy)：保守・開発系列。
- [その他のユースケース](use_case/README.md)：追加の例と、それぞれの前提。

## ライセンス

ngx_mrubyは[MITライセンス](../../MITL)で提供します。

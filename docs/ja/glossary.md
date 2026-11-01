# 用語集

このページは、ngx_mrubyのドキュメント、サイト、PRで、モデル、エージェント、そのプロトコル、通信、前段の部品を呼ぶ語を決めます。1つの語は、1つの対象だけを指します。そのため、読み手は2つのページで同じ語を読めば、同じ範囲を読み取れます。英語の語の項は、英語版のページと対応させるため、見出しを英語のまま書きます。和文での書き方は、次の[語の使い方](#語の使い方)の節にあります。通信の種類は、「モデルAPIの通信」のように語に「の通信」を付けて名前にします。英語版のページは[Glossary](../glossary.md)にあります。

## 語の使い方

- 和文では、AIゲートウェイ、MCPゲートウェイ、AIアプリケーション、エージェント、モデル、モデルAPI、マルチモーダルのモデル、リクエスト、AIクローラー、ボットのようにカタカナで書きます。MCP、A2A、API、log handler、JSONのフィールド名（`model`など）、MCPやA2Aの仕様の役割の名前として書くhost、client、serverのような識別子は、英語のまま書きます。オーナーは2026-11-02にこの書き方を決めました。
- 和文では、一般の意味のメッセージとレスポンスも、カタカナで書きます。APIの名前を指すときは、Messages API、Responses APIのように名前と分かる形で書き、MessagesやResponsesだけを書く形は使いません。
- 通信は種類ごとに名前を書きます。モデルAPIの通信、MCPの通信、A2Aの通信、サイトへ来るAIのクローラーとエージェントのリクエスト、log handlerのテレメトリの5つです。この5つの通信は、プロトコルも向きも違います。
- モデルAPI、MCPサーバー、エージェントの前段に置く部品はAIゲートウェイと書きます。そのうちMCPの部分は、MCPゲートウェイと書きます。
- LLMは、テキストの言語モデルを指すときだけ書きます。モデル、通信、部品の総称にはしません。
- AI trafficは、ページが複数の種類の通信を1語で指す必要があるときに限って書きます。そのページの初出で、どの種類の通信を含むかを定義します。ゲートウェイの製品とボット対策の報告書は、この語を別の通信に使っています。詳しくは[通信](#通信)の節にあります。
- 製品や仕様を引用するときは、引用の中ではその製品や仕様の語を残します。たとえば、LiteLLMの「LLM traffic」です。自分の文では、このページの語を使います。

オーナーは2026-11-02にこれらの規則を選びました。記録は[サイトの構想](../proposals/site.md#7-decisions-2026-10-15)の7節にあります。標準や論文が定義していない語は、その語の説明にそう書きます。

## モデル

### model

- 意味：提供元が名前を付け、APIか重みの配布で出す学習済みのモデルです。扱うのがテキスト、画像、音声、動画のどれかは問いません。ユーザーインターフェースやツールを足したソフトウェア全体はAI systemで、モデルとは分けます。
- ngx_mrubyでの使い方：総称です。個々のモデルは、提供元が付けたモデルの名前で書きます。
- 和文での書き方：モデル、モデルAPI、マルチモーダルのモデルと、カタカナで書きます。JSONのフィールド名の`model`は、英語のまま書きます。
- 出典：
  - [EU AI Act, Recital 97](https://artificialintelligenceact.eu/recital/97/)
  - [OpenAI, Models](https://developers.openai.com/api/docs/models)
  - [Gemini API, Models](https://ai.google.dev/gemini-api/docs/models)

### LLM (large language model)

- 意味：テキストを扱う、規模の大きい事前学習済みの言語モデルです。研究では、画像や音声へ広げたモデルをmultimodal LLMと修飾して呼びます。提供元の発表の中には、マルチモーダルのモデルをLLMと呼ぶものもあります。
- ngx_mrubyでの使い方：テキストの言語モデルを指すときだけ使います。
- 出典：
  - [Zhao et al., LLM survey](https://arxiv.org/abs/2303.18223)
  - [Yin et al., MLLM survey](https://arxiv.org/abs/2306.13549)
  - [Meta, The Llama 4 herd](https://ai.meta.com/blog/llama-4-multimodal-intelligence/)

### multimodal model

- 意味：テキスト、画像、音声、動画のうち、2つ以上のモダリティを処理できるモデルを指します。
- ngx_mrubyでの使い方：モダリティを区別する箇所で、修飾に使います。テキストだけのモデルが外れるので、総称にしません。
- 出典：
  - [NIST AI 100-2 E2025](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf)
  - [Gemini API, Models](https://ai.google.dev/gemini-api/docs/models)

### foundation model

- 意味：広いデータで大規模に学習し、多様な下流のタスクへ適応できるモデルです。
- ngx_mrubyでの使い方：学習の仕方と汎用性を論じる箇所だけで使います。提供元ごとに用法がそろわないので、総称にしません。
- 出典：
  - [Bommasani et al. 2021](https://arxiv.org/abs/2108.07258)
  - [NIST AI 100-2 E2025](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf)
  - [NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)

### frontier model

- 意味：ある時点で能力が最も高い汎用モデルの1つです。対象は時点で変わります。
- ngx_mrubyでの使い方：総称にはしません。ゲートウェイは、自前でホストする小さいモデルにも古いモデルにも、同じ規則を当てるためです。
- 出典：
  - [Frontier Model Forum](https://www.frontiermodelforum.org/about-us/)
  - [Anderljung et al. 2023](https://arxiv.org/abs/2307.03718)

## モデルのAPI

### model API

- 意味：提供元がモデルを出すHTTPのAPIです。OpenAI互換のchat completions、OpenAIのResponses API、AnthropicのMessages API、Gemini API、画像や音声のモデルのAPIを含みます。
- ngx_mrubyでの使い方：総称です。個々のAPIは提供元の名前で書きます。この語を定義した標準はありません。ngx_mrubyは、どのモダリティも含む語としてこの語を使います。Microsoftは、これらのAPIをlanguage model APIsとして並べ、複数の提供元をまとめたendpointをunified model APIと呼んでいます。
- 出典：
  - [Microsoft, AI gateway](https://learn.microsoft.com/en-us/azure/api-management/genai-gateway-capabilities)

### inference

- 意味：学習済みのモデルに入力を与えて出力を作らせる処理と、そのリクエストです。提供元がホストするモデルにも、自分でホストするモデルにも使います。
- ngx_mrubyでの使い方：自分が運用するサーバーでモデルを動かす場合は、self-hosted inferenceと書きます。
- 出典：
  - [Hugging Face, Inference](https://huggingface.co/docs/huggingface_hub/main/guides/inference)
  - [Amazon Bedrock user guide](https://docs.aws.amazon.com/bedrock/latest/userguide/what-is-bedrock.html)
  - [Agent Router README](https://raw.githubusercontent.com/envoyproxy/ai-gateway/main/README.md)

### LLM API、LLM provider API

- 意味：MCPのarchitectureの文書とMicrosoftが、提供元のAPIを呼ぶ語です。
- ngx_mrubyでの使い方：使いません。テキストのモデルのAPIに範囲が狭まるためです。モデルAPIと書きます。
- 出典：
  - [MCP architecture (2026-07-28)](https://modelcontextprotocol.io/docs/2026-07-28/learn/architecture.md)
  - [Microsoft, AI gateway](https://learn.microsoft.com/en-us/azure/api-management/genai-gateway-capabilities)

## 呼ぶ側とサイトへ来る側

### AI application

- 意味：モデルを使うソフトウェアです。MCPではhostの役を担います。Claude、ChatGPT、Claude Code、VS Codeが例です。エージェントとは限りません。
- ngx_mrubyでの使い方：モデルAPIやMCPサーバーを呼び出す側のソフトウェア全般を指します。
- 出典：
  - [MCP, What is MCP](https://modelcontextprotocol.io/docs/getting-started/intro)
  - [MCP architecture (2026-07-28)](https://modelcontextprotocol.io/docs/2026-07-28/learn/architecture.md)

### AI client

- 意味：一部のページが、MCPのアプリが動くソフトウェアを呼ぶ語です。
- ngx_mrubyでの使い方：使いません。MCPのclientは、hostの中で1つのserverとの接続を持つ部品を指すためです。AIアプリケーションと書きます。
- 出典：
  - [MCP, What is MCP](https://modelcontextprotocol.io/docs/getting-started/intro)
  - [MCP architecture (2026-07-28)](https://modelcontextprotocol.io/docs/2026-07-28/learn/architecture.md)

### agent

- 意味：モデルが処理の進め方とツールの使い方を自分で決めるシステムです。NISTは、モデルを要件にせず、目標に向けて行動するソフトウェアとして、より広く定義します。
- ngx_mrubyでの使い方：この性質を持つAIアプリケーションを指します。サイトへ来る自動のリクエストは、下の語で書きます。
- 出典：
  - [Anthropic, Building agents](https://www.anthropic.com/engineering/building-effective-agents)
  - [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/)
  - [NIST AI 100-2 E2025](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf)

### agentic system

- 意味：決まったコードの経路でモデルとツールを組むworkflowと、エージェントの両方をまとめて指します。
- ngx_mrubyでの使い方：この2つを区別せずに指す箇所で使います。
- 出典：
  - [Anthropic, Building agents](https://www.anthropic.com/engineering/building-effective-agents)
  - [A2A specification](https://a2a-protocol.org/latest/specification/)

### AI crawler

- 意味：学習、検索、利用者が頼んだ操作のために、サイトのページを取りに来る自動のclientです。
- ngx_mrubyでの使い方：nginxが配信するサイトへ来る側を指します。そのリクエストは、モデルAPIの通信と逆向きです。
- 出典：
  - [Cloudflare, AI crawlers by purpose](https://blog.cloudflare.com/ai-crawler-traffic-by-purpose-and-industry/)

### training crawler

- 意味：モデルの開発のために、データを大量に集めるAIクローラーです。
- ngx_mrubyでの使い方：クローラーの目的を区別する箇所で使います。
- 出典：
  - [HUMAN Security 2026 report](https://www.humansecurity.com/wp-content/uploads/HUMAN_Report_2026-State-of-AI-Traffic-and-Cyberthreat-Benchmark.pdf)

### AI scraper

- 意味：RAGやAIの検索のために、利用者のリクエストを受けた時点で情報を取りに来るclientです。
- ngx_mrubyでの使い方：クローラーの目的を区別する箇所で使います。
- 出典：
  - [HUMAN Security 2026 report](https://www.humansecurity.com/wp-content/uploads/HUMAN_Report_2026-State-of-AI-Traffic-and-Cyberthreat-Benchmark.pdf)

### verified bot

- 意味：身元と目的を明かしているとCloudflareが確かめたボットかエージェントを指します。
- ngx_mrubyでの使い方：Cloudflareの語なので、社名を添えて書きます。
- 出典：
  - [Cloudflare, Verified bots](https://developers.cloudflare.com/bots/concepts/bot/verified-bots/)

### signed agent

- 意味：Cloudflareの語で、1つの会社でなくエンドユーザーの指示で動くエージェントを指します。エージェントが使う基盤がWeb Bot AuthでHTTPのリクエストに署名し、Cloudflareがその署名を検証します。エージェントがCloudflareのsigned agentのpolicyを守ることも、条件の1つです。
- ngx_mrubyでの使い方：サイトがエージェントのリクエストの署名を確かめる箇所で、社名を添えて書きます。
- 出典：
  - [Cloudflare, Signed agents](https://blog.cloudflare.com/signed-agents/)

## プロトコル

### MCP (Model Context Protocol)

- 意味：AIアプリケーションを外部のツールとデータにつなぐプロトコルです。hostの中のclientが1つのserverと接続し、serverはtools、resources、promptsを出します。メッセージはJSON-RPC 2.0です。2026-07-28のバージョンでは、MCPは状態を持たないプロトコルです。serverは`server/discover`へのレスポンスで、対応するバージョンと機能を返します。
- ngx_mrubyでの使い方：MCPはモデルAPIではありません。serverがclientを通してモデルのcompletionを求めるSamplingは、2026-07-28のバージョンの仕様で廃止予定になりました。
- 出典：
  - [MCP architecture (2026-07-28)](https://modelcontextprotocol.io/docs/2026-07-28/learn/architecture.md)
  - [MCP architecture (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/architecture)

### A2A (Agent2Agent Protocol)

- 意味：エージェント同士が通信するための標準です。A2Aのserverは、自分の能力とskillを書いたAgent CardというJSONの文書を公開します。
- ngx_mrubyでの使い方：MCPはエージェントとそのツールを、A2Aはエージェントとエージェントをつなぎます。
- 出典：
  - [A2A protocol](https://a2a-protocol.org/latest/)
  - [A2A and MCP](https://a2a-protocol.org/latest/topics/a2a-and-mcp/)
  - [A2A specification](https://a2a-protocol.org/latest/specification/)

### agent-to-LLM、agent-to-tool、agent-to-agent

- 意味：エージェントが出す通信を、モデルの呼び出し、MCPによるツールの呼び出し、A2Aによるエージェント同士の通信の3つに分けて名前を付ける語です。
- ngx_mrubyでの使い方：ページがどの通信を扱うかを書く枠に使います。サイトへ来るリクエストは、この3つに入りません。自分の文では、agent-to-LLMでなくモデルAPIの通信と書きます。
- 出典：
  - [agentgateway README](https://raw.githubusercontent.com/agentgateway/agentgateway/main/README.md)
  - [Kong, agent-to-agent traffic](https://konghq.com/company/press-room/press-release/kong-ai-gateway-now-supports-agent-to-agent-traffic-becoming-the-most-comprehensive-ai-gateway-for-the-agentic-era)

## 通信

最初の5つは、上の語から作ったngx_mrubyの語です。出典の資料は、同じ種類の通信を説明しています。

### モデルAPIの通信

- 意味：AIアプリケーションからモデルAPIへのリクエストと、そのレスポンスです。ストリームかどうかは問いません。
- ngx_mrubyでの使い方：モデルの振り分け、利用者キーとAPI用のキー、モデルAPIの間のfallbackを書く箇所で使います。
- 出典：
  - [Microsoft, AI gateway](https://learn.microsoft.com/en-us/azure/api-management/genai-gateway-capabilities)

### MCPの通信

- 意味：MCPのclientとserverの間のJSON-RPCのメッセージです。
- ngx_mrubyでの使い方：ツールの認可など、MCPの用途を書く箇所で使います。
- 出典：
  - [Kong, MCP traffic](https://developer.konghq.com/ai-gateway/v1/mcp/)

### A2Aの通信

- 意味：A2Aでやり取りするエージェント同士のメッセージです。
- ngx_mrubyでの使い方：エージェント同士の呼び出しを書く箇所で使います。
- 出典：
  - [A2A protocol](https://a2a-protocol.org/latest/)

### サイトへ来るAIのクローラーとエージェントのリクエスト

- 意味：AIクローラー、AIスクレイパー、エージェントが、WebサイトやAPIへ送るリクエストです。目的が学習か検索か利用者の操作かは問いません。
- ngx_mrubyでの使い方：クローラーとボットの制御を書く箇所で使います。
- 出典：
  - [HUMAN Security 2026 report](https://www.humansecurity.com/wp-content/uploads/HUMAN_Report_2026-State-of-AI-Traffic-and-Cyberthreat-Benchmark.pdf)
  - [Cloudflare, Web Bot Auth](https://blog.cloudflare.com/web-bot-auth/)

### log handlerのテレメトリ

- 意味：logのフェーズのhandlerが記録するリクエストのメタデータです。ステータス、レイテンシ、振り分けの結果がその例です。
- ngx_mrubyでの使い方：収集先へ送る処理を書く箇所で使います。この処理は、案内のページが計画として説明しています。
- 出典：
  - [AIゲートウェイの認可と制限](guides/edge-control.md#キャッシュと観測)

### AI traffic

- 意味：用法が2つある語です。ゲートウェイの製品は、モデルAPI、MCPサーバー、エージェントへの通信に使います。ボット対策の報告書は、AIのクローラー、スクレイパー、エージェントがWebサイトへ送るリクエストに使います。ゲートウェイの製品のページの中にも、モデルの呼び出しだけを指す箇所があります。
- ngx_mrubyでの使い方：ページが複数の種類の通信を1語で指す必要があるときだけ使い、初出で含む種類を定義します。この語を定義した標準と論文はありません。
- 出典：
  - [Kong, agent-to-agent traffic](https://konghq.com/company/press-room/press-release/kong-ai-gateway-now-supports-agent-to-agent-traffic-becoming-the-most-comprehensive-ai-gateway-for-the-agentic-era)
  - [WSO2, AI Gateway](https://wso2.com/api-platform/docs/ai-gateway/1.2.0.md)
  - [Kong, AI Gateway](https://developer.konghq.com/ai-gateway/)
  - [HUMAN Security 2026 report](https://www.humansecurity.com/wp-content/uploads/HUMAN_Report_2026-State-of-AI-Traffic-and-Cyberthreat-Benchmark.pdf)

### LLM traffic、inference traffic

- 意味：モデルの呼び出しだけを指す語です。LLM trafficは提供元のAPIへの呼び出しに、inference trafficはモデルサーバーへの通信に使われます。
- ngx_mrubyでの使い方：総称にはしません。MCP、A2A、サイトへ来るリクエストを含まないためです。
- 出典：
  - [Kong, AI Gateway](https://developer.konghq.com/ai-gateway/)
  - [LiteLLM, AI Gateway](https://docs.litellm.ai/docs/simple_proxy)
  - [F5, NGINX Gateway Fabric](https://community.f5.com/kb/technicalarticles/f5-nginx-gateway-fabric---the-one-gateway-for-ai-powered-applications/345619)

### agentic traffic、agent traffic

- 意味：ボット対策では、AIエージェントとエージェント型のブラウザ（agentic browser）がWebサイトへ送るリクエストを指します。ゲートウェイの製品では、A2Aの通信か、モデルとMCPとA2Aの3種類の通信をまとめて指します。
- ngx_mrubyでの使い方：総称にはしません。意味が製品や業界でぶつかるうえ、学習用のAIクローラーと、エージェントでないAIアプリケーションからのモデルの呼び出しが外れるためです。
- 出典：
  - [HUMAN Security 2026 report](https://www.humansecurity.com/wp-content/uploads/HUMAN_Report_2026-State-of-AI-Traffic-and-Cyberthreat-Benchmark.pdf)
  - [agentgateway introduction](https://agentgateway.dev/docs/standalone/latest/about/introduction/)

## 部品

### AI gateway

- 意味：モデル、エージェント、ツールの前段に置き、その通信の認証、振り分け、制限、観測をするゲートウェイです。APIゲートウェイの機能を広げて作る製品が多くあります。このページのために調べたAIゲートウェイの製品は、Webサイトへ来るリクエストの制御を、範囲に入れていません。
- ngx_mrubyでの使い方：ngx_mrubyがモデルAPI、MCPサーバー、エージェントの前段に置く部品の名前です。
- 出典：
  - [Microsoft, AI gateway](https://learn.microsoft.com/en-us/azure/api-management/genai-gateway-capabilities)
  - [LiteLLM, AI Gateway](https://docs.litellm.ai/docs/simple_proxy)
  - [WSO2, AI Gateway](https://wso2.com/api-platform/docs/ai-gateway/1.2.0.md)
  - [Kong, AI Gateway](https://developer.konghq.com/ai-gateway/)
  - [Cloudflare, AI Gateway](https://developers.cloudflare.com/ai-gateway/)

### MCP gateway

- 意味：MCPサーバーの前に置くreverse proxyと管理の層です。MCPの通信に限って、認可、レート制限、MCPツールの振り分けをします。
- ngx_mrubyでの使い方：AIゲートウェイのうち、MCPの部分を指します。
- 出典：
  - [microsoft/mcp-gateway](https://github.com/microsoft/mcp-gateway)
  - [Kong, MCP traffic](https://developer.konghq.com/ai-gateway/v1/mcp/)

### inference gateway

- 意味：Kubernetes Gateway API Inference Extensionの語です。自前でホストするモデルサーバーの前に置き、Endpoint Pickerで送り先のサーバーを選ぶproxyを指します。
- ngx_mrubyでの使い方：総称にはしません。ngx_mrubyがこの意味で、自前のモデルサーバーの前に立つ場合だけ使います。
- 出典：
  - [Inference Extension README](https://raw.githubusercontent.com/kubernetes-sigs/gateway-api-inference-extension/main/README.md)

### LLM proxy、LLM gateway

- 意味：一部の製品が、AIゲートウェイのうちモデルAPIの呼び出しを中継する部分に付ける名前です。WSO2の製品のLLM Proxyと、agentgatewayのLLM Gatewayが、その例に当たります。
- ngx_mrubyでの使い方：部品の名前にはしません。MCPとA2Aはモデルの呼び出しでなく、製品ごとに範囲もそろわないためです。AIゲートウェイ、またはそのモデルAPIの部分と書きます。
- 出典：
  - [WSO2, AI Gateway](https://wso2.com/api-platform/docs/ai-gateway/1.2.0.md)
  - [agentgateway README](https://raw.githubusercontent.com/agentgateway/agentgateway/main/README.md)
  - [MCP architecture (2026-07-28)](https://modelcontextprotocol.io/docs/2026-07-28/learn/architecture.md)

## ngx_mrubyのページの例

- ホームページの題「AIアプリケーションの認証と転送をRubyで制御する。」は、モデルAPIを呼び出す側のソフトウェアを、AIアプリケーションと書いています。題の下の例は、チャットと文書要約のリクエストを、`model`のフィールドの値で振り分けます。題の下の本文は、部品を、AIアプリケーションとモデルAPIの間に置くAIゲートウェイと呼んでいます。
- 計画の用途「モデルAPIのエラーで転送先を変える」は、テキストの言語モデルに限らないので、モデルAPIと書いています。
- [AIゲートウェイの認可と制限](guides/edge-control.md)の「AIクローラーの制御」の節は、サイトへ来るAIのクローラーとエージェントのリクエストを扱うので、語が合います。
- [edge-controlの構想](../proposals/edge-control.md)の題は「AI traffic」と書いています。この構想は、MCPの通信、モデルAPIの通信、サイトへ来るAIのクローラーとエージェントのリクエスト、log handlerのテレメトリを扱います。そのため、この語には、初出でこの4つの通信を含むという定義が要ります。
- [ドキュメントの一覧](README.md)は、[モデルAPIの部分の案内](guides/agent-proxy.md)へのリンクを「モデルAPIの中継」と書いています。このページは、AIゲートウェイのうちモデルAPIの部分だけを扱い、ほかの部分の案内は別のページにあります。

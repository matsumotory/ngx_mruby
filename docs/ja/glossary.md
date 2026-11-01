# 用語集

このページは、ngx_mrubyのドキュメント、サイト、PRで、モデル、agent、そのプロトコル、通信、前段の部品を呼ぶ語を決めます。1つの語は1つの対象だけを指します。そのため、読み手は2つのページで同じ語を読めば、同じ範囲を読み取れます。日本語のページでも、英語の語は訳さずに書きます。通信の種類は、「model APIの通信」のように英語の語に「の通信」を付けて書きます。英語版のページは[Glossary](../glossary.md)にあります。

## 語の使い方

- 通信は種類ごとに名前を書きます。model APIの通信、MCPの通信、A2Aの通信、サイトへ来るAIのcrawlerとagentのrequest、log handlerのテレメトリの5つです。この5つは、プロトコルも向きも違います。
- model API、MCPのserver、agentの前段に置く部品はAI gatewayと書きます。そのうちMCPの部分は、MCP gatewayと書きます。
- LLMは、テキストの言語モデルを指すときだけ書きます。モデル、通信、部品の総称にはしません。
- AI trafficは、ページが複数の種類の通信を1語で指す必要があるときだけ書きます。そのページの初出で、どの種類の通信を含むかを定義します。gatewayの製品とbot対策の報告書は、この語を別の通信に使っています。詳しくは[通信](#通信)の節にあります。
- 製品や仕様を引用するときは、引用の中ではその製品や仕様の語を残します。たとえば、LiteLLMの「LLM traffic」です。自分の文では、このページの語を使います。

オーナーは2026-11-02にこの規則を選びました。記録は[サイトの構想](../proposals/site.md#7-decisions-2026-10-15)の7節にあります。標準や論文が定義していない語は、その語の説明にそう書きます。

## モデル

### model

- 意味：提供元が名前を付け、APIか重みの配布で出す学習済みのモデルです。扱うのがテキスト、画像、音声、動画のどれかは問いません。ユーザーインターフェースやツールを足したソフトウェア全体はAI systemで、モデルとは分けます。
- ngx_mrubyでの使い方：総称です。個々のモデルは、提供元が付けたモデルの名前で書きます。
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
- ngx_mrubyでの使い方：総称にはしません。gatewayは、自前でホストする小さいモデルにも古いモデルにも、同じ規則を当てるためです。
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

- 意味：学習済みのモデルに入力を与えて出力を作らせる処理と、そのrequestです。提供元がホストするモデルにも、自分でホストするモデルにも使います。
- ngx_mrubyでの使い方：自分が運用するサーバーでモデルを動かす場合は、self-hosted inferenceと書きます。
- 出典：
  - [Hugging Face, Inference](https://huggingface.co/docs/huggingface_hub/main/guides/inference)
  - [Amazon Bedrock user guide](https://docs.aws.amazon.com/bedrock/latest/userguide/what-is-bedrock.html)
  - [Agent Router README](https://raw.githubusercontent.com/envoyproxy/ai-gateway/main/README.md)

### LLM API、LLM provider API

- 意味：MCPのarchitectureの文書とMicrosoftが、提供元のAPIを呼ぶ語です。
- ngx_mrubyでの使い方：使いません。テキストのモデルのAPIに範囲が狭まるためです。model APIと書きます。
- 出典：
  - [MCP architecture (2026-07-28)](https://modelcontextprotocol.io/docs/2026-07-28/learn/architecture.md)
  - [Microsoft, AI gateway](https://learn.microsoft.com/en-us/azure/api-management/genai-gateway-capabilities)

## 呼ぶ側とサイトへ来る側

### AI application

- 意味：モデルを使うソフトウェアです。MCPではhostの役を担います。Claude、ChatGPT、Claude Code、VS Codeが例です。agentとは限りません。
- ngx_mrubyでの使い方：model APIやMCPのserverを呼び出す側のソフトウェアを指します。
- 出典：
  - [MCP, What is MCP](https://modelcontextprotocol.io/docs/getting-started/intro)
  - [MCP architecture (2026-07-28)](https://modelcontextprotocol.io/docs/2026-07-28/learn/architecture.md)

### AI client

- 意味：一部のページが、MCPのアプリが動くソフトウェアを呼ぶ語です。
- ngx_mrubyでの使い方：使いません。MCPのclientは、hostの中で1つのserverとの接続を持つ部品を指すためです。AI applicationと書きます。
- 出典：
  - [MCP, What is MCP](https://modelcontextprotocol.io/docs/getting-started/intro)
  - [MCP architecture (2026-07-28)](https://modelcontextprotocol.io/docs/2026-07-28/learn/architecture.md)

### agent

- 意味：モデルが処理の進め方とツールの使い方を自分で決めるシステムです。NISTは、モデルを要件にせず、目標に向けて行動するソフトウェアとして、より広く定義します。
- ngx_mrubyでの使い方：この性質を持つAI applicationを指します。サイトへ来る自動のrequestは、下の語で書きます。
- 出典：
  - [Anthropic, Building agents](https://www.anthropic.com/engineering/building-effective-agents)
  - [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/)
  - [NIST AI 100-2 E2025](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf)

### agentic system

- 意味：決まったコードの経路でモデルとツールを組むworkflowと、agentの両方をまとめて指します。
- ngx_mrubyでの使い方：この2つを区別せずに指す箇所で使います。
- 出典：
  - [Anthropic, Building agents](https://www.anthropic.com/engineering/building-effective-agents)
  - [A2A specification](https://a2a-protocol.org/latest/specification/)

### AI crawler

- 意味：学習、検索、利用者が頼んだ操作のために、サイトのページを取りに来る自動のclientです。
- ngx_mrubyでの使い方：nginxが配信するサイトへ来る側を指します。そのrequestは、model APIの通信と逆向きです。
- 出典：
  - [Cloudflare, AI crawlers by purpose](https://blog.cloudflare.com/ai-crawler-traffic-by-purpose-and-industry/)

### training crawler

- 意味：モデルの開発のために、データを大量に集めるAI crawlerです。
- ngx_mrubyでの使い方：crawlerの目的を区別する箇所で使います。
- 出典：
  - [HUMAN Security 2026 report](https://www.humansecurity.com/wp-content/uploads/HUMAN_Report_2026-State-of-AI-Traffic-and-Cyberthreat-Benchmark.pdf)

### AI scraper

- 意味：RAGやAIの検索のために、requestの時点で情報を取りに来るclientです。
- ngx_mrubyでの使い方：crawlerの目的を区別する箇所で使います。
- 出典：
  - [HUMAN Security 2026 report](https://www.humansecurity.com/wp-content/uploads/HUMAN_Report_2026-State-of-AI-Traffic-and-Cyberthreat-Benchmark.pdf)

### verified bot

- 意味：身元と目的を明かしているとCloudflareが確かめたbotかagentです。
- ngx_mrubyでの使い方：Cloudflareの語なので、社名を添えて書きます。
- 出典：
  - [Cloudflare, Verified bots](https://developers.cloudflare.com/bots/concepts/bot/verified-bots/)

### signed agent

- 意味：Cloudflareの語で、1つの会社でなくエンドユーザーの指示で動くagentを指します。agentが使う基盤がWeb Bot AuthでHTTPのrequestに署名し、Cloudflareがその署名を検証します。agentがCloudflareのsigned agentのpolicyを守ることも、条件の1つです。
- ngx_mrubyでの使い方：サイトがagentのrequestの署名を確かめる箇所で、社名を添えて書きます。
- 出典：
  - [Cloudflare, Signed agents](https://blog.cloudflare.com/signed-agents/)

## プロトコル

### MCP (Model Context Protocol)

- 意味：AI applicationを外部のツールとデータにつなぐプロトコルです。hostの中のclientが1つのserverと接続し、serverはtools、resources、promptsを出します。メッセージはJSON-RPC 2.0です。2026-07-28のバージョンでは、MCPは状態を持たないプロトコルです。serverは`server/discover`への応答で、対応するバージョンと機能を返します。
- ngx_mrubyでの使い方：MCPはmodel APIではありません。serverがclientを通してモデルのcompletionを求めるSamplingは、2026-07-28のバージョンで廃止予定になりました。
- 出典：
  - [MCP architecture (2026-07-28)](https://modelcontextprotocol.io/docs/2026-07-28/learn/architecture.md)
  - [MCP architecture (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/architecture)

### A2A (Agent2Agent Protocol)

- 意味：agent同士が通信するための標準です。A2Aのserverは、自分の能力とskillを書いたAgent CardというJSONの文書を公開します。
- ngx_mrubyでの使い方：MCPはagentとそのツールを、A2Aはagentとagentをつなぎます。
- 出典：
  - [A2A protocol](https://a2a-protocol.org/latest/)
  - [A2A and MCP](https://a2a-protocol.org/latest/topics/a2a-and-mcp/)
  - [A2A specification](https://a2a-protocol.org/latest/specification/)

### agent-to-LLM、agent-to-tool、agent-to-agent

- 意味：agentが出す通信を、モデルの呼び出し、MCPによるツールの呼び出し、A2Aによるagent同士の通信の3つに分けて名前を付ける語です。
- ngx_mrubyでの使い方：ページがどの通信を扱うかを書く枠に使います。サイトへ来るrequestは、この3つに入りません。自分の文では、agent-to-LLMでなくmodel APIの通信と書きます。
- 出典：
  - [agentgateway README](https://raw.githubusercontent.com/agentgateway/agentgateway/main/README.md)
  - [Kong, agent-to-agent traffic](https://konghq.com/company/press-room/press-release/kong-ai-gateway-now-supports-agent-to-agent-traffic-becoming-the-most-comprehensive-ai-gateway-for-the-agentic-era)

## 通信

最初の5つは、上の語から作ったngx_mrubyの語です。出典の資料は、同じ種類の通信を説明しています。

### model APIの通信

- 意味：AI applicationからmodel APIへのrequestと、そのレスポンスです。ストリームかどうかは問いません。
- ngx_mrubyでの使い方：モデルの振り分け、利用者キーとAPI用のキー、model APIの間のfallbackを書く箇所で使います。
- 出典：
  - [Microsoft, AI gateway](https://learn.microsoft.com/en-us/azure/api-management/genai-gateway-capabilities)

### MCPの通信

- 意味：MCPのclientとserverの間のJSON-RPCのメッセージです。
- ngx_mrubyでの使い方：ツールの認可など、MCPの用途を書く箇所で使います。
- 出典：
  - [Kong, MCP traffic](https://developer.konghq.com/ai-gateway/v1/mcp/)

### A2Aの通信

- 意味：A2Aでやり取りするagent同士のメッセージです。
- ngx_mrubyでの使い方：agent同士の呼び出しを書く箇所で使います。
- 出典：
  - [A2A protocol](https://a2a-protocol.org/latest/)

### サイトへ来るAIのcrawlerとagentのrequest

- 意味：AI crawler、AI scraper、agentが、WebサイトやAPIへ送るrequestです。目的が学習か検索か操作かは問いません。
- ngx_mrubyでの使い方：crawlerとbotの制御を書く箇所で使います。
- 出典：
  - [HUMAN Security 2026 report](https://www.humansecurity.com/wp-content/uploads/HUMAN_Report_2026-State-of-AI-Traffic-and-Cyberthreat-Benchmark.pdf)
  - [Cloudflare, Web Bot Auth](https://blog.cloudflare.com/web-bot-auth/)

### log handlerのテレメトリ

- 意味：logのフェーズのhandlerが記録するrequestのメタデータです。ステータス、レイテンシ、振り分けの結果がその例です。
- ngx_mrubyでの使い方：収集先へ送る処理を書く箇所で使います。この処理は、案内のページが計画として説明しています。
- 出典：
  - [ngx_mruby, AIの入口を制御する](guides/edge-control.md#キャッシュと観測)

### AI traffic

- 意味：用法が2つある語です。gatewayの製品は、model API、MCPのserver、agentへの通信に使います。bot対策の報告書は、AIのcrawler、scraper、agentがWebサイトへ送るrequestに使います。gatewayのページの中にも、モデルの呼び出しだけを指す箇所があります。
- ngx_mrubyでの使い方：ページが複数の種類の通信を1語で指す必要があるときだけ使い、初出で含む種類を定義します。この語を定義した標準と論文はありません。
- 出典：
  - [Kong, agent-to-agent traffic](https://konghq.com/company/press-room/press-release/kong-ai-gateway-now-supports-agent-to-agent-traffic-becoming-the-most-comprehensive-ai-gateway-for-the-agentic-era)
  - [WSO2, AI Gateway](https://wso2.com/api-platform/docs/ai-gateway/1.2.0.md)
  - [Kong, AI Gateway](https://developer.konghq.com/ai-gateway/)
  - [HUMAN Security 2026 report](https://www.humansecurity.com/wp-content/uploads/HUMAN_Report_2026-State-of-AI-Traffic-and-Cyberthreat-Benchmark.pdf)

### LLM traffic、inference traffic

- 意味：モデルの呼び出しだけを指す語です。LLM trafficは提供元のAPIへの呼び出しに、inference trafficはモデルサーバーへの通信に使われます。
- ngx_mrubyでの使い方：総称にはしません。MCP、A2A、サイトへ来るrequestを含まないためです。
- 出典：
  - [Kong, AI Gateway](https://developer.konghq.com/ai-gateway/)
  - [LiteLLM, AI Gateway](https://docs.litellm.ai/docs/simple_proxy)
  - [F5, NGINX Gateway Fabric](https://community.f5.com/kb/technicalarticles/f5-nginx-gateway-fabric---the-one-gateway-for-ai-powered-applications/345619)

### agentic traffic、agent traffic

- 意味：bot対策では、AI agentとagentic browserがWebサイトへ送るrequestを指します。gatewayの製品では、A2Aの通信か、モデルとMCPとA2Aの3種類の通信をまとめて指します。
- ngx_mrubyでの使い方：総称にはしません。意味が製品や業界でぶつかるうえ、training crawlerと、agentでないAI applicationからのモデルの呼び出しが外れるためです。
- 出典：
  - [HUMAN Security 2026 report](https://www.humansecurity.com/wp-content/uploads/HUMAN_Report_2026-State-of-AI-Traffic-and-Cyberthreat-Benchmark.pdf)
  - [agentgateway introduction](https://agentgateway.dev/docs/standalone/latest/about/introduction/)

## 部品

### AI gateway

- 意味：モデル、agent、ツールの前段に置き、その通信の認証、振り分け、制限、観測をするgatewayです。API gatewayの機能を広げて作る製品が多くあります。このページのために調べたAI gatewayの製品は、Webサイトへ来るrequestの制御を、範囲に入れていません。
- ngx_mrubyでの使い方：ngx_mrubyがmodel API、MCPのserver、agentの前段に置く部品の名前です。
- 出典：
  - [Microsoft, AI gateway](https://learn.microsoft.com/en-us/azure/api-management/genai-gateway-capabilities)
  - [LiteLLM, AI Gateway](https://docs.litellm.ai/docs/simple_proxy)
  - [WSO2, AI Gateway](https://wso2.com/api-platform/docs/ai-gateway/1.2.0.md)
  - [Kong, AI Gateway](https://developer.konghq.com/ai-gateway/)
  - [Cloudflare, AI Gateway](https://developers.cloudflare.com/ai-gateway/)

### MCP gateway

- 意味：MCPのserverの前に置くreverse proxyと管理の層です。MCPの通信に限って、認可、レート制限、ツールの振り分けをします。
- ngx_mrubyでの使い方：AI gatewayのうち、MCPの部分を指します。
- 出典：
  - [microsoft/mcp-gateway](https://github.com/microsoft/mcp-gateway)
  - [Kong, MCP traffic](https://developer.konghq.com/ai-gateway/v1/mcp/)

### inference gateway

- 意味：Kubernetes Gateway API Inference Extensionの語です。自前でホストするモデルサーバーの前に置き、Endpoint Pickerで送り先のサーバーを選ぶproxyを指します。
- ngx_mrubyでの使い方：総称にはしません。ngx_mrubyがこの意味で、自前のモデルサーバーの前に立つ場合だけ使います。
- 出典：
  - [Inference Extension README](https://raw.githubusercontent.com/kubernetes-sigs/gateway-api-inference-extension/main/README.md)

### LLM proxy、LLM gateway

- 意味：一部の製品が、AI gatewayのうちmodel APIの呼び出しを中継する部分に付ける名前です。WSO2の製品のLLM Proxyと、agentgatewayのLLM Gatewayが、その例に当たります。
- ngx_mrubyでの使い方：部品の名前にはしません。MCPとA2Aはモデルの呼び出しでなく、製品ごとに範囲もそろわないためです。AI gateway、またはそのmodel APIの部分と書きます。
- 出典：
  - [WSO2, AI Gateway](https://wso2.com/api-platform/docs/ai-gateway/1.2.0.md)
  - [agentgateway README](https://raw.githubusercontent.com/agentgateway/agentgateway/main/README.md)
  - [MCP architecture (2026-07-28)](https://modelcontextprotocol.io/docs/2026-07-28/learn/architecture.md)

## ngx_mrubyのページの例

- ホームページは、アプリがLLMを使い、プロキシがアプリとLLM APIの間に立つと書いています。この例は、チャットと文書要約のrequestを、`model`のフィールドの値でテキストの言語モデルへ振り分けます。そのため、LLMの語が合います。
- 計画の用途「LLM APIのエラー時に転送先を選び直す」は、テキストの言語モデルを扱う間は語が合います。画像や音声のモデルのAPIも扱う場合は、model APIと書きます。
- [AIの入口を制御する](guides/edge-control.md)の「クローラーの制御」の節は、サイトへ来るAIのcrawlerとagentのrequestを扱うので、語が合います。
- [edge-controlの構想](../proposals/edge-control.md)の題は「AI traffic」と書いています。この構想は、MCPの通信、model APIの通信、サイトへ来るAIのcrawlerとagentのrequest、log handlerのテレメトリを扱います。そのため、この語には、初出でこの4つを含むという定義が要ります。
- 部品そのものを名指す文は、AI gatewayと書きます。[ドキュメントの一覧](README.md)から[エージェントプロキシ](guides/agent-proxy.md)の案内へ張ったリンクの「LLMプロキシ」がその例です。ページがmodel APIの部分だけを扱うなら、そのことも書き添えます。

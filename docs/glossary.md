# Glossary

This page fixes the terms that the documentation, the site and the pull
requests of ngx_mruby use for models, agents, their protocols, their
traffic and the components in front of them. Each term names one thing, so
a reader who meets the term on two pages reads the same scope. The Japanese
pages use the same terms, in English ([用語集](ja/glossary.md)).

## How to use these terms

- Name each kind of traffic: model API traffic, MCP traffic, A2A traffic,
  requests from AI crawlers and agents to a site, and the telemetry that a
  log handler records. They differ in protocol and in direction.
- Call the component in front of model APIs, MCP servers and agents an AI
  gateway, and its MCP part an MCP gateway.
- Write LLM only where you mean a text language model. LLM is not the
  general term for models, for traffic or for the component.
- Write AI traffic only where a page needs one term for several kinds of
  traffic, and define at its first use which kinds it covers on that page.
  Gateway products and bot-management reports use it for different traffic
  (see [Traffic](#traffic)).
- When you quote a product or a specification, keep its own term in the
  quotation (for example, LiteLLM's "LLM traffic"). Your own sentences use
  the terms of this page.

The owner chose these rules on 2026-11-02 (section 7 of
[the site proposal](proposals/site.md#7-decisions-2026-10-15)). Where no
standard or paper defines a term, its entry says so.

## Models

### model

- Meaning: A trained model that a provider names and offers through an API or as weights, whatever it takes in or puts out: text, images, audio or video. The software around it, such as a user interface and tools, is an AI system, not the model.
- In ngx_mruby's documents: The general term. Name a single model by the name its provider gives it.
- Sources:
  - [EU AI Act, Recital 97](https://artificialintelligenceact.eu/recital/97/)
  - [OpenAI, Models](https://developers.openai.com/api/docs/models)
  - [Gemini API, Models](https://ai.google.dev/gemini-api/docs/models)

### LLM (large language model)

- Meaning: A large pretrained language model of text. Research calls models extended to images and audio multimodal LLMs (MLLM), and some provider announcements also call multimodal models LLMs.
- In ngx_mruby's documents: Only where a text language model is meant.
- Sources:
  - [Zhao et al., LLM survey](https://arxiv.org/abs/2303.18223)
  - [Yin et al., MLLM survey](https://arxiv.org/abs/2306.13549)
  - [Meta, The Llama 4 herd](https://ai.meta.com/blog/llama-4-multimodal-intelligence/)

### multimodal model

- Meaning: A model that processes more than one modality, such as text, images, audio and video.
- In ngx_mruby's documents: A qualifier, where the modalities matter. Not the general term: it leaves out text-only models.
- Sources:
  - [NIST AI 100-2 E2025](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf)
  - [Gemini API, Models](https://ai.google.dev/gemini-api/docs/models)

### foundation model

- Meaning: A model trained on broad data at scale that can be adapted to a wide range of downstream tasks.
- In ngx_mruby's documents: Only where training and generality are the subject. Not the general term: providers do not use it alike.
- Sources:
  - [Bommasani et al. 2021](https://arxiv.org/abs/2108.07258)
  - [NIST AI 100-2 E2025](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf)
  - [NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)

### frontier model

- Meaning: A general-purpose model among the most capable at a given time. The set changes over time.
- In ngx_mruby's documents: Not the general term: a gateway applies the same policy to a small self-hosted model and to an older model.
- Sources:
  - [Frontier Model Forum](https://www.frontiermodelforum.org/about-us/)
  - [Anderljung et al. 2023](https://arxiv.org/abs/2307.03718)

## Model APIs

### model API

- Meaning: The HTTP API through which a provider offers its models: OpenAI-compatible chat completions, the OpenAI Responses API, the Anthropic Messages API, the Gemini API, and the APIs of image and audio models.
- In ngx_mruby's documents: The general term. Name a single API by its provider's name. No standard defines the term; ngx_mruby uses it because it covers every modality. Microsoft lists these APIs as language model APIs and calls an endpoint over several providers a unified model API.
- Sources:
  - [Microsoft, AI gateway](https://learn.microsoft.com/en-us/azure/api-management/genai-gateway-capabilities)

### inference

- Meaning: Running a trained model on an input to produce an output, and the request that asks for it, whether a provider or you host the model.
- In ngx_mruby's documents: Write self-hosted inference where the model runs on servers you operate.
- Sources:
  - [Hugging Face, Inference](https://huggingface.co/docs/huggingface_hub/main/guides/inference)
  - [Amazon Bedrock user guide](https://docs.aws.amazon.com/bedrock/latest/userguide/what-is-bedrock.html)
  - [Agent Router README](https://raw.githubusercontent.com/envoyproxy/ai-gateway/main/README.md)

### LLM API, LLM provider API

- Meaning: The APIs of model providers, in the words of the MCP architecture overview and of Microsoft.
- In ngx_mruby's documents: Not used: they narrow the APIs to text models. Write model API.
- Sources:
  - [MCP architecture (2026-07-28)](https://modelcontextprotocol.io/docs/2026-07-28/learn/architecture.md)
  - [Microsoft, AI gateway](https://learn.microsoft.com/en-us/azure/api-management/genai-gateway-capabilities)

## Callers and visitors

### AI application

- Meaning: Software that uses a model. In MCP it is the host; Claude, ChatGPT, Claude Code and VS Code are examples. It is not necessarily an agent.
- In ngx_mruby's documents: The caller of a model API or of an MCP server.
- Sources:
  - [MCP, What is MCP](https://modelcontextprotocol.io/docs/getting-started/intro)
  - [MCP architecture (2026-07-28)](https://modelcontextprotocol.io/docs/2026-07-28/learn/architecture.md)

### AI client

- Meaning: The software in which MCP apps run, in the words of some pages.
- In ngx_mruby's documents: Not used: in MCP, a client is the part of the host that holds the connection to one server. Write AI application.
- Sources:
  - [MCP, What is MCP](https://modelcontextprotocol.io/docs/getting-started/intro)
  - [MCP architecture (2026-07-28)](https://modelcontextprotocol.io/docs/2026-07-28/learn/architecture.md)

### agent

- Meaning: A system in which a model decides how to proceed and which tools to use. NIST defines an agent more widely, as software that acts toward a goal, with no model required.
- In ngx_mruby's documents: An AI application with this property. For automated requests that arrive at a site, use the terms below.
- Sources:
  - [Anthropic, Building agents](https://www.anthropic.com/engineering/building-effective-agents)
  - [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/)
  - [NIST AI 100-2 E2025](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf)

### agentic system

- Meaning: Workflows, which combine a model and tools along fixed code paths, and agents, together.
- In ngx_mruby's documents: Where workflows and agents need not be told apart.
- Sources:
  - [Anthropic, Building agents](https://www.anthropic.com/engineering/building-effective-agents)
  - [A2A specification](https://a2a-protocol.org/latest/specification/)

### AI crawler

- Meaning: An automated client that fetches a site's pages for training, for search, or for an action a user asked for.
- In ngx_mruby's documents: A visitor of a site that nginx serves. Its requests travel the other way from model API traffic.
- Sources:
  - [Cloudflare, AI crawlers by purpose](https://blog.cloudflare.com/ai-crawler-traffic-by-purpose-and-industry/)

### training crawler

- Meaning: An AI crawler that collects data in bulk to develop models.
- In ngx_mruby's documents: Where the purpose of a crawler matters.
- Sources:
  - [HUMAN Security 2026 report](https://www.humansecurity.com/wp-content/uploads/HUMAN_Report_2026-State-of-AI-Traffic-and-Cyberthreat-Benchmark.pdf)

### AI scraper

- Meaning: A client that fetches information at request time for retrieval-augmented generation or AI search.
- In ngx_mruby's documents: Where the purpose of a crawler matters.
- Sources:
  - [HUMAN Security 2026 report](https://www.humansecurity.com/wp-content/uploads/HUMAN_Report_2026-State-of-AI-Traffic-and-Cyberthreat-Benchmark.pdf)

### verified bot

- Meaning: A bot or agent that Cloudflare has confirmed is transparent about who it is and what it does.
- In ngx_mruby's documents: Cloudflare's term; name Cloudflare with it.
- Sources:
  - [Cloudflare, Verified bots](https://developers.cloudflare.com/bots/concepts/bot/verified-bots/)

### signed agent

- Meaning: An agent that acts for an end user, not for one company, and signs its HTTP requests with Web Bot Auth.
- In ngx_mruby's documents: Where a site checks the signature of an agent's requests.
- Sources:
  - [Cloudflare, Signed agents](https://blog.cloudflare.com/signed-agents/)

## Protocols

### MCP (Model Context Protocol)

- Meaning: A protocol that connects AI applications to external tools and data. A client in the host connects to one server, which offers tools, resources and prompts. Messages are JSON-RPC 2.0. In the 2026-07-28 version the protocol is stateless, and a server answers `server/discover` with the versions and capabilities it supports.
- In ngx_mruby's documents: MCP is not a model API. Sampling, through which a server asks the client for a model completion, is deprecated in the 2026-07-28 version.
- Sources:
  - [MCP architecture (2026-07-28)](https://modelcontextprotocol.io/docs/2026-07-28/learn/architecture.md)
  - [MCP architecture (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/architecture)

### A2A (Agent2Agent Protocol)

- Meaning: A standard for communication between agents. An A2A server publishes an Agent Card, a JSON document that describes its capabilities and skills.
- In ngx_mruby's documents: MCP connects an agent to its tools; A2A connects agents to each other.
- Sources:
  - [A2A protocol](https://a2a-protocol.org/latest/)
  - [A2A and MCP](https://a2a-protocol.org/latest/topics/a2a-and-mcp/)
  - [A2A specification](https://a2a-protocol.org/latest/specification/)

### agent-to-LLM, agent-to-tool, agent-to-agent

- Meaning: Names for the parts of the traffic that an agent sends: model calls, tool calls over MCP, and calls between agents over A2A.
- In ngx_mruby's documents: A frame for saying which traffic a page covers. Requests that arrive at a site are outside it. In your own sentences, write model API traffic instead of agent-to-LLM.
- Sources:
  - [agentgateway README](https://raw.githubusercontent.com/agentgateway/agentgateway/main/README.md)
  - [Kong, agent-to-agent traffic](https://konghq.com/company/press-room/press-release/kong-ai-gateway-now-supports-agent-to-agent-traffic-becoming-the-most-comprehensive-ai-gateway-for-the-agentic-era)

## Traffic

The first five terms are ngx_mruby's own terms, built from the terms above.
Their sources describe the same kind of traffic.

### model API traffic

- Meaning: The requests from AI applications to a model API and its responses, streamed or not.
- In ngx_mruby's documents: Model routing, client keys and upstream keys, and fallback between model APIs.
- Sources:
  - [Microsoft, AI gateway](https://learn.microsoft.com/en-us/azure/api-management/genai-gateway-capabilities)

### MCP traffic

- Meaning: The JSON-RPC messages between an MCP client and an MCP server.
- In ngx_mruby's documents: Tool authorization and the other MCP uses.
- Sources:
  - [Kong, MCP traffic](https://developer.konghq.com/ai-gateway/v1/mcp/)

### A2A traffic

- Meaning: The messages between agents over A2A.
- In ngx_mruby's documents: Calls between agents.
- Sources:
  - [A2A protocol](https://a2a-protocol.org/latest/)

### requests from AI crawlers and agents to a site

- Meaning: The requests that AI crawlers, AI scrapers and agents send to a website or an API, whatever their purpose: training, search or an action.
- In ngx_mruby's documents: Crawler and bot control.
- Sources:
  - [HUMAN Security 2026 report](https://www.humansecurity.com/wp-content/uploads/HUMAN_Report_2026-State-of-AI-Traffic-and-Cyberthreat-Benchmark.pdf)
  - [Cloudflare, Web Bot Auth](https://blog.cloudflare.com/web-bot-auth/)

### telemetry of the log handler

- Meaning: The request metadata that a log-phase handler records, such as status, latency and routing decisions.
- In ngx_mruby's documents: Export to a collector, which the guide describes as planned.
- Sources:
  - [ngx_mruby, AI edge control](guides/edge-control.md#cache-and-telemetry-hooks)

### AI traffic

- Meaning: A term with two uses. Gateway products use it for traffic to model APIs, MCP servers and agents. Bot-management reports use it for the requests of AI crawlers, scrapers and agents to websites. Some gateway pages use it for model calls only.
- In ngx_mruby's documents: Only where a page needs one term for several kinds of traffic, defined at its first use with the kinds it covers. No standard or paper defines it.
- Sources:
  - [Kong, agent-to-agent traffic](https://konghq.com/company/press-room/press-release/kong-ai-gateway-now-supports-agent-to-agent-traffic-becoming-the-most-comprehensive-ai-gateway-for-the-agentic-era)
  - [WSO2, AI Gateway](https://wso2.com/api-platform/docs/ai-gateway/1.2.0.md)
  - [Kong, AI Gateway](https://developer.konghq.com/ai-gateway/)
  - [HUMAN Security 2026 report](https://www.humansecurity.com/wp-content/uploads/HUMAN_Report_2026-State-of-AI-Traffic-and-Cyberthreat-Benchmark.pdf)

### LLM traffic, inference traffic

- Meaning: Model calls only: LLM traffic for calls to providers' APIs, inference traffic for traffic to model servers.
- In ngx_mruby's documents: Not used as the general term: they leave out MCP, A2A and the requests that arrive at a site.
- Sources:
  - [Kong, AI Gateway](https://developer.konghq.com/ai-gateway/)
  - [LiteLLM, AI Gateway](https://docs.litellm.ai/docs/simple_proxy)
  - [F5, NGINX Gateway Fabric](https://community.f5.com/kb/technicalarticles/f5-nginx-gateway-fabric---the-one-gateway-for-ai-powered-applications/345619)

### agentic traffic, agent traffic

- Meaning: In bot management, the requests of AI agents and agentic browsers to websites. In gateway products, either A2A traffic or model, MCP and A2A traffic together.
- In ngx_mruby's documents: Not used as the general term: its meanings conflict between products and industries, and it leaves out training crawlers and model calls from applications that are not agents.
- Sources:
  - [HUMAN Security 2026 report](https://www.humansecurity.com/wp-content/uploads/HUMAN_Report_2026-State-of-AI-Traffic-and-Cyberthreat-Benchmark.pdf)
  - [agentgateway introduction](https://agentgateway.dev/docs/standalone/latest/about/introduction/)

## Components

### AI gateway

- Meaning: A gateway in front of models, agents and tools that authenticates, routes, limits and observes their traffic. Many products build it on an API gateway. The AI gateway products surveyed for this page do not include the control of the requests that arrive at a website.
- In ngx_mruby's documents: The name of the component that ngx_mruby places in front of model APIs, MCP servers and agents.
- Sources:
  - [Microsoft, AI gateway](https://learn.microsoft.com/en-us/azure/api-management/genai-gateway-capabilities)
  - [LiteLLM, AI Gateway](https://docs.litellm.ai/docs/simple_proxy)
  - [WSO2, AI Gateway](https://wso2.com/api-platform/docs/ai-gateway/1.2.0.md)
  - [Kong, AI Gateway](https://developer.konghq.com/ai-gateway/)
  - [Cloudflare, AI Gateway](https://developers.cloudflare.com/ai-gateway/)

### MCP gateway

- Meaning: A reverse proxy and management layer in front of MCP servers, for authorization, rate limits and tool routing of MCP traffic.
- In ngx_mruby's documents: The MCP part of the AI gateway.
- Sources:
  - [microsoft/mcp-gateway](https://github.com/microsoft/mcp-gateway)
  - [Kong, MCP traffic](https://developer.konghq.com/ai-gateway/v1/mcp/)

### inference gateway

- Meaning: In the Kubernetes Gateway API Inference Extension, a proxy in front of self-hosted model servers that chooses a server with an Endpoint Picker.
- In ngx_mruby's documents: Not the general term. Only where ngx_mruby stands in front of self-hosted model servers in this sense.
- Sources:
  - [Inference Extension README](https://raw.githubusercontent.com/kubernetes-sigs/gateway-api-inference-extension/main/README.md)

### LLM proxy, LLM gateway

- Meaning: The name that some products give to the part of an AI gateway that relays model API calls, such as WSO2's LLM Proxy.
- In ngx_mruby's documents: Not used as the name of the component: MCP and A2A are not model calls, and the products do not agree on the scope. Write AI gateway, or its model API part.
- Sources:
  - [WSO2, AI Gateway](https://wso2.com/api-platform/docs/ai-gateway/1.2.0.md)
  - [MCP architecture (2026-07-28)](https://modelcontextprotocol.io/docs/2026-07-28/learn/architecture.md)

## Examples in ngx_mruby's pages

- The home page says that apps use an LLM and that the proxy stands between
  apps and LLM APIs. Its example routes chat and summarization requests by
  their `model` field to text language models, so LLM fits there.
- The planned use "Select another LLM endpoint after an API error" fits
  while it covers text language models. If it covers image or audio model
  APIs as well, write model API.
- "AI crawler traffic policy" in the [AI edge control guide](guides/edge-control.md)
  covers requests from AI crawlers and agents to a site, and fits.
- The title of [the edge-control proposal](proposals/edge-control.md) says
  "AI traffic". The proposal covers MCP traffic, model API traffic,
  requests from AI crawlers and bots to a site, and the telemetry of the log
  handler, so the term needs a definition with these four kinds at its
  first use.
- A text that names the component itself, such as the link "LLM proxy" to
  the [agent proxy guide](guides/agent-proxy.md) in the
  [documents index](README.md), writes AI gateway, and says where the page
  covers only its model API part.

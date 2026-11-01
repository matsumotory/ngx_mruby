# AI edge control

**Planned v3 uses, not ready-made integrations.** ngx_mruby can put Ruby
policy inside nginx without moving the byte relay into an application. The
[working LLM recipe](agent-proxy.md) already checks client keys, selects models
and relays streams on `next`. The four directions below extend that boundary;
they are not four completed products or a promise that every part ships in v3.0.

## MCP access policy

When an end user calls MCP tools from an AI application, this configuration
would restrict the operations and data that user can access.

The MCP server operator would place ngx_mruby between the AI application and
MCP server. The proxy would check the authenticated user against the MCP tool
name and arguments in `tools/call` before forwarding to a configured service.
It would reject updates from a search-only user or requests for documents
outside that user's access scope. The MCP server would still enforce data access.

Identity validation and tool authorization are separate. Validate token issuer,
audience and scope with the resource server's authorization machinery; Ruby uses
the validated identity, not a self-declared agent ID. Include the verified user identity and permitted
data scope in policy and accounting keys. Check routing metadata against the JSON-RPC body,
and preserve the service's discovery contract, errors and cancellation behavior.
A gateway is not automatically an OAuth server or a tool-discovery aggregator.

[The MCP design](mcp-gateway.md) specifies the first mock recipe and protocol
revision. Three transports need distinct compatibility tests: Streamable HTTP
of 2026-07-28, the Streamable HTTP revisions 2025-03-26 to 2025-11-25 (with
`Mcp-Session-Id`, a GET stream and `Last-Event-ID`), and the older HTTP+SSE.
Do not retry a modifying tool call or forward a token to a different audience.

Also bound call bursts, concurrent streams and payload size with nginx limits.
A configured profile can return protocol-correct retry guidance without deciding
whether the AI has completed its investigation. Rate signals alone do not identify
a semantic loop; test legitimate repeated reads before enforcing a heuristic.

The ledger rows [MCP tool authorization and tenant validation](../proposals/edge-control.md#mcp-tool-authorization) and [loop and burst protection](../proposals/edge-control.md#mcp-burst-control) list the features these uses need and their status.

### Adapt the interface, not the domain

A configured client profile can offer granular tools or a `search`/`fetch` entry
alongside them, backed by the same service. Keep `tools/list` and `tools/call`
consistent; hiding a tool is not access control. Route to a versioned adapter
rather than assuming a permanent tool contract for every client of one brand.

Progressive document retrieval lets the AI read a bounded passage and ask for
more. The backend owns source IDs, versions, offsets and continuation tokens.
The proxy may select that profile or enforce budgets, but must not cut JSON/SSE
or invent a continuation. The client must know when the source is incomplete.

The ledger rows [client-specific tool profiles](../proposals/edge-control.md#mcp-tool-profiles) and [progressive document retrieval](../proposals/edge-control.md#mcp-progressive-retrieval) list the features these uses need and their status.

### Guide and observe the next step

Typed empty, partial and failed results can carry truthful recovery guidance.
Preserve the distinction between no matches, permission denial and unavailable
data. Domain suggestions belong to the service; a gateway must not change query
meaning or promote text from an untrusted document into instructions.

Observe tool sequences through minimal outcome metadata and bounded retention,
not raw queries or documents by default. Correlation is an observability contract,
not an MCP session. Non-blocking export needs the planned queue described below.

Search and reading tools can interact with the user's usual AI to produce
Agentic RAG, while that AI keeps planning and stopping. Let clients evolve
without making the gateway another agent orchestration engine.

The ledger rows [next-step guidance](../proposals/edge-control.md#mcp-next-step-guidance) and [interaction trajectories](../proposals/edge-control.md#mcp-trajectory-logging) list the features these uses need and their status.

## LLM fallback policy

An application operator wants to keep endpoint selection and provider keys out
of each app. The proposed policy selects an allowlisted fallback for an upstream
429 or selected 5xx response, before any response reaches the client. It must
also decide when to stop and return the original error. A local concurrency
limit is not a provider failure and must not trigger another upstream attempt.

nginx supplies `proxy_next_upstream` and named `error_page` locations. Their
retry rules are not a complete cross-provider policy. nginx passes a POST to the
next server only when `proxy_next_upstream` also lists `non_idempotent`, and
listing it is the replay decision of this section. POST replay can duplicate
work and charges; bound attempts and total time, respect provider cooldowns,
and require a replay-safe operation and a replayable body. Never restart a
stream after bytes have reached the client. A reset after streaming begins is
reported as an interrupted response, not hidden by concatenating a second one.

Each destination needs its own credentials, Host and TLS SNI. Compatible API
paths, model capabilities and body formats are prerequisites: replacing a key
does not convert Messages to Responses. Rebuilding headers for each peer attempt
inside one location needs the planned balancer API. The
[provider transport plan](agent-proxy.md#implementation-status-and-the-v3-target)
keeps this distinct from today's mock relay.

The ledger row [LLM API fallback](../proposals/edge-control.md#llm-api-fallback) lists the features this use needs and its status.

## AI crawler traffic policy

A site or API operator wants to protect an expensive endpoint while keeping a
lighter public representation available. Ruby can combine request properties
with configured rules; nginx applies request-rate and concurrency limits or
routes to a separate text endpoint. A changing policy belongs at this edge when
copying it into every application would be harder to maintain.

User-Agent, IP and payload shape are signals, not proof of identity or intent.
Only trust forwarded addresses from configured proxies. Bound body inspection
and avoid a full parse of an arbitrary upload. Keep verified clients separate
from heuristic bot classes, and return an explicit rejection or an intentionally
published lightweight representation. Test false positives with ordinary clients.

A honeypot is an optional isolated route, not a default punishment or a claim of
bot detection. It must not expose private data, trigger outbound work or consume
unbounded resources. Shared adaptive counters and their reload behavior remain
part of the planned shared-dictionary work, not a distributed quota service.

The ledger row [AI crawlers and bots](../proposals/edge-control.md#ai-crawler-and-bot-control) lists the features this use needs and its status.

## Cache and telemetry hooks

A team wants to observe request status, latency and routing decisions without
sending prompts or credentials to a collector. Today's log handler can record
request metadata. It cannot wait for a network response: `Nginx::Async` is
rejected in the log phase, and a blocking client stalls the worker.

The planned exporter uses a bounded worker queue and a worker timer over a
non-blocking transport. Define overflow, sampling, shutdown and delivery-failure
behavior before implementing it. Metrics may be dropped with a counter; an
audit trail that requires durable delivery needs a separate explicit contract.
Neither path should quietly turn collector failure into a stalled response.

Semantic caching is a separate request-time decision, not a log-phase feature.
An external service owns embedding, similarity search and cached answers; the
proxy may consult it through a future non-blocking hook. Partition by tenant,
authorization scope, model, prompt/version and policy version, and define expiry
and invalidation. On a timeout or an
uncertain match, use the original upstream. Do not cache tool side effects or
claim that similar prompts have equivalent answers without domain-specific tests.

The ledger rows [telemetry from the log handler](../proposals/edge-control.md#log-handler-telemetry) and [semantic cache](../proposals/edge-control.md#semantic-cache) list the features these uses need and their status.

## Design and verification

The [v3 edge-control proposal](../proposals/edge-control.md) records dependencies,
failure behavior and acceptance tests. It extends the existing agent-proxy plan
without adding a second relay engine, embedding runtime or generic API converter.
Mock recipes, interoperability tests and measurements must land before these
uses are described as verified. Start today with the
[local model-routing trial](../../examples/start/README.md#model-routing).

[The use-case ledger](../proposals/edge-control.md#use-cases-and-the-features-they-need) lists every use
with the features it needs and its status.

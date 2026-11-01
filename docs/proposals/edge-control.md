# v3: a thin control layer for AI traffic

Status: design direction requested on 2026-11-01. This proposal records what v3
should enable, not completed features or a commitment to ship every recipe in
v3.0. The public [use-case guide](../guides/edge-control.md) and homepage distinguish
this direction from the tested agent-proxy mechanisms on `next`.
Next step: the first mock recipe, MCP tool authorization with two tenants and
read/write mock tools ("Tool authorization and tenant validation" below). It
starts after the core stabilization of Pillar B, beside step 7 of the plan, and
is tracked in the queue of [docs/HANDOFF.md](../HANDOFF.md).

## Purpose

Let application and platform developers keep changing access, routing and traffic
policy at nginx instead of distributing it across applications or installing an
entire orchestration stack. Ruby expresses the decision; nginx owns transport and
byte relay. The design must remain useful as models and AI clients improve, without
putting their planning, reasoning or tool-selection loop into ngx_mruby.

Search and source-retrieval tools can interact with the user's usual AI to
produce Agentic RAG: search, read, reconsider and search again. Planning and
stopping remain in that AI. The backend remains authoritative for provenance,
document versions, query meaning and access to individual data. The gateway
supports this interaction without copying domain policy into its routing layer.

## Shared architecture

1. Establish a trusted request context: verified principal, tenant, accepted
   protocol version and configured client profile. Never infer authorization
   from User-Agent, an unsigned client label or a request argument alone.
2. Apply bounded policy using request metadata and explicitly limited body
   inspection. Map to allowlisted upstreams, tool profiles and rate-limit classes.
   Reject inconsistent or unsupported requests before side effects.
3. Keep transport with nginx. Preserve status, required headers and stream order.
   Domain transformations belong to a versioned adapter/backend with tests, not
   arbitrary string replacement on streamed JSON.
4. Record a minimal outcome with a correlation ID. Non-blocking export is a
   separate bounded worker facility, not network I/O from the log handler.

Reuse the execution-context work and phase validity of
[core stabilization](core-stabilization.md), plus the shared dictionary, JSON
field reader, worker timers, sockets and provider-transport work of
[the v3 plan](v3-plan.md#agent-proxy-the-v30-use-case). Prefer nginx `map`,
`limit_req` and `limit_conn` where a fixed configuration is enough. New APIs need
measured evidence that the existing mechanisms cannot express the required policy.
No second proxy engine, embedded vector database, OAuth implementation or general
Messages/Responses converter is proposed here.

## Protecting MCP services

### Tool authorization and tenant validation

For `tools/call`, a verified principal and tenant select an allowed tool set.
Validate method, tool name and the relationship of tenant-bearing arguments to
that context. A backend must still enforce object-level authorization; the
proxy's coarse rejection is not a substitute. Header/body disagreement, an
unknown tool, malformed arguments or an unavailable authorization dependency
must fail closed under a defined protocol-correct response.

The first planned recipe uses two tenants and read/write mock tools. A read-only
agent is denied a write tool, and a caller cannot switch tenants in arguments.
The permitted call reaches only its allowlisted backend, once. This is a recipe
outline, not copyable Ruby for an authorization API that does not exist yet.

### Loop and burst protection

Bound request rate, concurrent calls, body size and permitted work classes.
Use nginx's shared counters with nonempty tenant/principal keys; worker-local Ruby
globals do not implement a shared quota. Classification chooses configured limits,
not an already-existing per-request arbitrary rate setter. Distinguish a short
call from a long stream and a resource limit from a provider's rate-limit response.

When the gateway rejects work, preserve HTTP/MCP error semantics for the negotiated
version and provide only truthful retry guidance. It cannot recognize every
semantic loop from request frequency, and repeated legitimate reads must not be
silently blocked as errors. Test dry-run classification and ordinary-client false
positives before an enforcement recipe is presented as usable.

## Adapting MCP interfaces

### Client-specific tool profiles

A deployment may offer a granular set of search/read tools to one client and a
`search`/`fetch` profile to another, backed by the same domain service. Select a
configured profile explicitly; do not assume every client has
one permanent contract. The profile must define both `tools/list` schemas and
`tools/call` behavior. Hiding a tool in discovery is not authorization.

The first planned recipe exposes two mock profiles through separate configured
routes. Both discover and invoke only the declared schemas. Mapping a profile's
arguments and results is the adapter's job; the gateway selects it and enforces
its policy. Cache discovery by tenant, permission set, profile and version so one
client cannot receive another's tool surface. Unknown profiles are rejected.

### Progressive document retrieval

A client may request a bounded passage first and continue when more context is
needed. The domain service owns passage boundaries, document ID, version,
provenance, offsets and the opaque continuation token. The gateway may enforce
response/request budgets or select that retrieval profile; it must not truncate
raw JSON or SSE, invent tokens, or turn an incomplete source into a complete one.

Validate continuation ownership and expiry, preserve the source version across
chunks, and tell the client when a version change requires a fresh retrieval.
The mock must reconstruct the original document exactly, expose completion, and
reject a token from another tenant. Measure both time to first useful passage and
additional calls; smaller responses are not automatically better research.

## Guiding and observing MCP use

### Recovery guidance

A backend can return typed empty, unsupported, partial or temporarily unavailable
results with concrete next steps. A profile adapter may expose those signals in
the client's expected shape. It must not turn a permission failure into "no
results", a timeout into "not found", or invent a successful search from an error.
Domain-specific suggestions come from the service, not untrusted document text.
Keep tool errors distinct from JSON-RPC protocol errors.

Test that clients can distinguish these states and that suggestions preserve the
original query's meaning and do not encourage infinite retry. Preserve provenance
and retrieval completeness. Whether guidance actually improves an investigation
requires client-level evaluation; passing a JSON schema is not evidence of that.

### Interaction trajectories

Observe the sequence of method/tool, profile, outcome, duration and correlation ID
without collecting raw queries, documents, arguments, tokens or provider keys by
default. A deployment-specific opt-in policy must define any richer collection.
A correlation ID for observation is not an MCP protocol session: revision
2026-07-28 has no protocol sessions, while clients of the revisions 2025-03-26
to 2025-11-25 still send `Mcp-Session-Id`, and the gateway decides what it
does with that header. Cross-request linkage needs a documented,
validated mechanism with bounded retention, not a fabricated session identifier.

The current log handler cannot wait for network I/O. Reuse planned worker timers
and non-blocking sockets behind a bounded queue, specify dropped-event counters,
shutdown/reload behavior and delivery semantics. Durable audit requirements may
need a separate service and admission policy. Do not claim exactly-once export.

## LLM fallback, bot policy and semantic cache

- **Fallback:** select compatible endpoints before response bytes reach the
  client. `proxy_next_upstream` supports 429 and selected 5xx, not all 5xx, and
  passes a POST on only with `non_idempotent`, which is the replay decision;
  529 uses a named `error_page` location. Bound retries and elapsed time, require
  replay-safe work and a replayable body, and separate local admission rejection
  from upstream failure. Preserve provider cooldown signals. Each destination owns
  its credentials, Host and SNI; clear incompatible authentication headers.
  Per-attempt header reconstruction in one location depends on the planned
  balancer. No replay after a partial stream or automatic duplication of tool
  side effects. Compatible model and wire format are required; no translation.
- **Bot policy:** combine bounded heuristics with verified identities where
  available, choose configured rate/connection classes or a published lightweight
  endpoint. User-Agent is not proof; trust forwarding headers only from configured
  proxies. Optional honeypots are isolated, bounded and contain no private data;
  they cannot trigger outbound actions. Measure false positives.
- **Semantic cache:** an external service owns embedding, similarity and entries.
  Lookup happens before generation through a future non-blocking request hook,
  not in log phase. Partition by tenant, authorization scope, model, prompt and
  policy versions; define TTL, invalidation, maximum lookup time and cache-outage
  fallback. Never cache modifying tool calls. Evaluate false matches against
  domain-specific correctness criteria, not hit rate alone.

## Delivery and acceptance

First preserve current correctness and the Pillar B stabilization order. Then add
mock recipes alongside the existing agent-proxy work, one policy boundary at a
time. The owner requested these directions; detailed API shapes, compatibility
profiles and release placement remain under design. A later implementation PR
must resolve them and update the corresponding status, not silently promote this
proposal to a shipped contract.

Every recipe must pass the following before it is advertised as verified:

- Explicit protocol/API versions and local mocks, plus a separate real-client
  compatibility result where claimed. For MCP, Streamable HTTP of 2026-07-28, the
  Streamable HTTP revisions 2025-03-26 to 2025-11-25 (with `Mcp-Session-Id`, the
  GET stream and `Last-Event-ID`) and legacy HTTP+SSE are distinct cases, including Origin, token audience, cancellation,
  discovery and required error headers. No unconditional retry of `tools/call`.
- Allow/deny, cross-tenant access, malformed and oversized input, timeout,
  disconnect, unavailable dependencies, reload and shutdown. Side effects happen
  at most as often as the documented replay contract permits.
- No raw payloads or credentials in default telemetry, bounded queue and cache
  failure behavior, visible loss accounting, and preserved document provenance.
- Functional assertions on actual responses, plus perf/soak comparisons required
  by AGENTS.md. Record instructions per request, throughput, p95 latency, memory
  per open stream, Ruby calls and queue pressure. Do not add Ruby work for every
  byte or event unless its bounded need and measured cost justify it.
- Client-level experiments compare task success, correct recovery, unnecessary
  calls and source completeness. No security, quality or speed superiority claim
  follows from implementing a hook alone.

## Sources and current evidence

- [MCP transport, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
- [MCP authorization, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [nginx retry rules](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_next_upstream)
  and [request buffering](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_request_buffering)
- [nginx request limiting](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html)
- [Current async phase checks](../../src/http/ngx_http_mruby_async.c) and
  [log-phase regression](../../test/t/cases/async_sleep_in_log.rb)
- [Current agent-proxy tests](../../test/t/cases/agent_proxy.rb) and
  [rate-limit guide](../guides/rate-limit.md)

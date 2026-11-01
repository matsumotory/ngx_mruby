# v3: a thin control layer for AI traffic

Status: design direction requested on 2026-11-01. This proposal records what v3
should enable, not completed features or a commitment to ship every recipe in
v3.0. The public [use-case guide](../guides/edge-control.md) and homepage distinguish
this direction from the tested agent-proxy mechanisms on `next`.
Next step: the first mock recipe, MCP tool authorization with two tenants and
read/write mock tools ("Tool authorization and tenant validation" below). It
starts after the core stabilization of Pillar B, beside step 7 of the plan, and
is the row [`mcp-tool-authorization`](#mcp-tool-authorization) of the ledger below.

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

## Use cases and the features they need

This table is the ledger of the AI uses of v3. Sessions choose the next work
from it: first the rows at `designing`, then the rows at `direction`, and a
feature of [the v3 plan](v3-plan.md) is taken up for the uses that need it
(the `serves:` notes on its rows). The queue of [docs/HANDOFF.md](../HANDOFF.md)
copies these rows; when the two disagree, this table holds.

Status, for the use case as a whole:

- `2.x`: a recipe for the use case runs in a test of `master`.
- `next`: a recipe runs in a test of `next`.
- `designing`: the first recipe and its acceptance test are written down, and
  no test runs it yet.
- `direction`: only the direction is written down.

The column "Features needed" names what exists on both branches today (with
the test that runs it, where one does) and the rows of the v3 plan that the
use case still needs. "Unverified" marks a fact that no test or source
reading of this repository has checked.

| Use case | Whose pain | What nginx does | What Ruby (ngx_mruby) decides | Features needed | Status | Recipe |
|---|---|---|---|---|---|---|
| [MCP tool authorization and tenant validation](#mcp-tool-authorization) | The operator of several MCP services: an agent can reach a write tool or another tenant's data by changing a header, a tool name or an argument, and each service repeats the checks. | TLS; the identity check through `auth_request` to the resource server's validation, or through a trusted front proxy; reading the body; `proxy_pass` to the allowlisted backend; relaying JSON and SSE responses. | From the validated principal and tenant: whether `tools/call` of the named tool is allowed, whether `Mcp-Method` and `Mcp-Name` agree with the JSON-RPC body and the tenant-bearing arguments with the tenant, which backend, and the protocol-correct rejection. | Today, on both branches: `mruby_enable_read_request_body` and `Nginx::Request#body` in an access handler (POST and PUT only; `nil` when nginx wrote the body to a temporary file; a Ruby String of at most 10 MiB, `MRB_STR_LENGTH_MAX`), `JSON.parse` of the bundled mattn/mruby-json, `headers_in`, and `proxy_pass` with a variable; on `next` the agent proxy test runs this routing (`test/t/cases/agent_proxy.rb`). A JSON error body comes from an `error_page` location, as the agent proxy's 401 does. No bundled gem validates a JWT or an OAuth token (`build_config.rb`); the bundled iij/mruby-digest has `Digest::HMAC`. v3: the JSON body read (`body_json`); the Pillar B rows of the execution-context type and of a Ruby-built body with any status. | `designing`: the first recipe and what it must show, in [Tool authorization and tenant validation](#tool-authorization-and-tenant-validation) | None |
| [Loop and burst protection for agents](#mcp-burst-control) | An MCP service whose agent clients repeat calls in bursts or hold many streams open, while legitimate repeated reads must still pass. | `limit_req` and `limit_conn` counters in shared memory, `client_max_body_size`, the rejection status through `limit_req_status`, `limit_conn_status` and `error_page`. | The nonempty key (tenant, principal) and the class of the call (tool, short call or stream) that selects a configured limit; truthful retry guidance in the rejection. | Today: a key from `mruby_set` for `limit_req` ([rate-limit guide](../guides/rate-limit.md), run on `next` by `test/t/cases/guides.rb`), and `limit_conn` per client key with a JSON 429 through `error_page` (`agent_proxy.rb` on `next`). `mruby_set` does not wait for the body, so a class taken from the JSON-RPC body needs the body read by an earlier handler that can wait ([`mruby_enable_read_request_body`](../directives/README.md#mruby_enable_read_request_body)). v3: the shared dictionary (Ruby globals count the requests of one worker only), `mruby_variable`. | `direction` | None |
| [Client-specific tool profiles](#mcp-tool-profiles) | The provider of one domain service whose clients expect different tool surfaces (granular tools, or `search` and `fetch`), without a second service for each client. | Separate configured routes (locations, `map`), the proxy to the adapter of each profile, the relay. | Which configured profile a verified request gets, the rejection of an unknown profile, the policy of the profile, and the key of the discovery cache (tenant, permission set, profile, version). | Today: routing by request data ([routing guide](../guides/routing.md), run on `next` by `guides.rb`). An mruby output body filter replaces only a response of known length, which it reads whole into memory; a response of unknown length (chunked, SSE) passes on unread (`ngx_http_mruby_body_filter` in `src/http/ngx_http_mruby_module.c`). The mapping of arguments and results belongs to a versioned adapter. Read from the source: in a location with an mruby body filter, the header of a response of unknown length goes on with the first call of the body filter, and the body then passes on as it arrives (`ngx_http_mruby_header_filter` and `ngx_http_mruby_body_filter`, the same on `master`); no test runs a stream through such a location. v3: the shared dictionary for the discovery cache. | `designing`: the first recipe and what it must show, in [Client-specific tool profiles](#client-specific-tool-profiles) | None |
| [Progressive document retrieval](#mcp-progressive-retrieval) | The user of an AI client that gets whole documents larger than it can use, and the service whose tool responses are too large. | The relay, `client_max_body_size` and the proxy timeouts. | The retrieval profile of the request and its budgets per tenant. The backend owns passages, versions and continuation tokens; Ruby does not cut JSON or SSE. | Today: routing and `limit_req` keys as in the rows above. v3: the shared dictionary for budgets that all workers share. | `designing`: what the mock must show, in [Progressive document retrieval](#progressive-document-retrieval) | None |
| [Next-step guidance on empty results and errors](#mcp-next-step-guidance) | The AI client that gets an empty or failed tool result and cannot tell no match from denied access or an outage, so it stops or retries blindly. | The relay of the backend's typed results; `error_page` for the gateway's own rejections. | Truthful, protocol-correct guidance in the gateway's own rejections (identity, limits), and the adapter that exposes the backend's signals. Domain suggestions come from the service. | Today: JSON error bodies through `error_page` locations (the agent proxy's 401 and 429 on `next`). Changing a backend's JSON in nginx: the body filter of the row on profiles, with the same limits. v3: the Pillar B row of a Ruby-built body with any status. | `direction` | None |
| [Asynchronous logging of interaction trajectories](#mcp-trajectory-logging) | The operator who wants the sequence of tool calls per client, with outcomes and durations, without collecting raw queries or documents. | `access_log` with variables (`$request_id`, `$request_time`, `$upstream_status`). | Which metadata to record (method, tool, profile, outcome) and the correlation ID; no raw payload. | Today: a log handler reads `$upstream_status` (`agent_proxy.rb` on `next`), runs after nginx's log module, so what it sets does not reach the `access_log` line of the same request, and cannot wait: `Nginx::Async` raises there (`test/t/cases/async_sleep_in_log.rb`). A variable that `mruby_set` sets earlier reaches `access_log`. v3: log handlers before `access_log`, `mruby_variable`, worker timers and the non-blocking socket API behind a bounded queue. | `direction` | None |
| [LLM API fallback](#llm-api-fallback) | The application operator whose provider answers 429, 529 or a 5xx, and who wants endpoint selection and provider keys out of each application. | `proxy_next_upstream` (`http_429`, selected 5xx, `non_idempotent` for a POST), `proxy_next_upstream_tries` and `_timeout`, `error_page 529 = @name` with `proxy_intercept_errors on`, and per location the credential, `Host` and TLS SNI (`proxy_set_header`, `proxy_ssl_server_name`, `proxy_ssl_name`). | The allowlisted endpoints compatible with the request's model, the credential that replaces the client's, whether the request is safe to replay, and the cooldown of a provider after a 429. | Today: routing by the `model` of the body with the credential replaced, and an upstream 529 passed to the client unchanged (`agent_proxy.rb` on `next`). The fallback through `error_page 529` is a test that section 8 of the v3 plan plans; the suite does not run it. v3: the shared dictionary (cooldown), the upstream peer hook, the first-byte deadline, and the Ruby balancer API (another credential on each attempt inside one location). | `designing`: section 8 of the v3 plan | None; [model routing](../../examples/start/README.md#model-routing) of `examples/start/` chooses an upstream by model, with no fallback |
| [Dynamic control of AI crawlers and bots](#ai-crawler-and-bot-control) | The site or API operator whose expensive endpoints AI crawlers load, and who keeps a lighter public representation available under a policy that changes often. | `limit_req` and `limit_conn` classes, `map`, `set_real_ip_from` for trusted proxies, routing to a lightweight endpoint. | The class of a request from its properties (verified client, heuristic bot, ordinary client), the limit class or endpoint for it, and an optional isolated honeypot route. | Today: a key from `mruby_set` for `limit_req` (rate-limit guide), and a deny list read from a file ([access-control guide](../guides/access-control.md)), both run on `next` by `guides.rb`. v3: the shared dictionary for adaptive counters that all workers share, and the non-blocking socket API for a lookup of a client's identity in an external service. | `direction` | None |
| [Semantic cache](#semantic-cache) | The operator who pays for repeated similar LLM requests and wants an external cache to answer them without changing the application. | The relay to the original upstream on a miss, a timeout or an uncertain match. | Whether a request may be cached (never a modifying tool call), the partition key (tenant, authorization scope, model, prompt and policy versions), and the lookup before the upstream. | Today: `Nginx::Async::HTTP.sub_request` takes a location and query arguments, not a method or a body. Whether the location of the subrequest can send the lookup as a POST with nginx's `proxy_method` and `proxy_set_body`: unverified, as no test does it. How a response is stored in the cache is not designed yet, and no row of the v3 plan covers it (the SSE event filter only reads). v3: the JSON body read, `sub_request` with a method, a body and headers, and the non-blocking socket API. | `direction` | None |
| [Telemetry from the log handler](#log-handler-telemetry) | The team that wants status, latency, routing decisions and token usage in a collector, without sending prompts or credentials and without stalling a worker. | `access_log` and its variables; traces through `ngx_otel_module` by configuration. | Which fields to record, the sampling, and the events queued per worker. | Today: the log handler of the trajectory row, with the same limits. A blocking client in an operator's script (mruby-socket of the default build) stalls its worker (AGENTS.md, "Design principles"). v3: log handlers before `access_log`, `mruby_variable`, the SSE event filter (usage from a stream), worker timers and the non-blocking socket API. | `direction` | None |

Each use below has a heading, which the links of the plan, the queue and the guides point at, and names the section with its design.

### MCP tool authorization

MCP tool authorization and tenant validation: status `designing`; the design is in [Tool authorization and tenant validation](#tool-authorization-and-tenant-validation).

### MCP burst control

Loop and burst protection for agents: status `direction`; the design is in [Loop and burst protection](#loop-and-burst-protection).

### MCP tool profiles

Client-specific tool profiles: status `designing`; the design is in [Client-specific tool profiles](#client-specific-tool-profiles).

### MCP progressive retrieval

Progressive document retrieval: status `designing`; the design is in [Progressive document retrieval](#progressive-document-retrieval).

### MCP next-step guidance

Next-step guidance on empty results and errors: status `direction`; the design is in [Recovery guidance](#recovery-guidance).

### MCP trajectory logging

Asynchronous logging of interaction trajectories: status `direction`; the design is in [Interaction trajectories](#interaction-trajectories).

### LLM API fallback

LLM API fallback: status `designing`; the design is in [LLM fallback, bot policy and semantic cache](#llm-fallback-bot-policy-and-semantic-cache).

### AI crawler and bot control

Dynamic control of AI crawlers and bots: status `direction`; the design is in [LLM fallback, bot policy and semantic cache](#llm-fallback-bot-policy-and-semantic-cache).

### Semantic cache

Semantic cache: status `direction`; the design is in [LLM fallback, bot policy and semantic cache](#llm-fallback-bot-policy-and-semantic-cache).

### Log handler telemetry

Telemetry from the log handler: status `direction`; the design is in [Interaction trajectories](#interaction-trajectories).

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

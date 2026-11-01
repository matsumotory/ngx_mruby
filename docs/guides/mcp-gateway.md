# Routing a document service behind one MCP URL

**Use-case design, not a verified MCP integration.** This page targets ngx_mruby
3.x on `next`. Its HTTP routing and streamed relay are tested; an MCP-specific
recipe and interoperability suite have not been implemented. MCP protocol
requirements below target revision **2026-07-28**. They are requirements for the
service you build, not capabilities supplied automatically by ngx_mruby.

## Who this helps

A service offers document search, text retrieval and expensive source processing.
AI applications should keep one MCP endpoint while the operator separates those workloads.
An MCP gateway would select a configured backend using service-specific rules and an
allowlist. Ruby is useful when several conditions or service rules determine the
choice; a fixed header-to-backend mapping may only need nginx `map`.

The proposed path is **AI application → one `/mcp` endpoint → nginx with Ruby rules →
search, text or source-processing backend → original response**. Separate workers
can keep source processing from consuming the search workers, but this arrangement
is not itself a latency or capacity guarantee. Measure the deployed workload.

Keep the protocols separate: model API traffic uses formats such as Messages
or Responses; MCP traffic connects AI applications to servers offering MCP
tools and resources. An AI gateway can host both locations without
translating either protocol. This is not a stdio-to-HTTP converter, an MCP server,
an MCP tool-discovery aggregator or an OAuth implementation.

## Responsibilities before deploying

Use the [Streamable HTTP specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
and [versioning rules](https://modelcontextprotocol.io/specification/versioning)
as the contract. Declare which versions your endpoint accepts; older clients need
an explicit compatibility strategy. The 2026-07-28 revision removed protocol
sessions and the GET stream endpoint; an SSE disconnect now signals cancellation.

Routing metadata (`Mcp-Method`, `Mcp-Name`, `MCP-Protocol-Version`) must agree with
the JSON-RPC body after the specified decoding. The destination MCP service must
validate that agreement before executing an MCP tool. Headers alone do not establish
permission. Keep a service responsible for discovery and the complete MCP tool list;
refuse unknown MCP tools and unsupported versions without selecting an arbitrary
backend. Preserve JSON and SSE responses and required error headers.

Validate Origin and apply the [MCP authorization contract](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).
A lookup of a Bearer string in a Ruby hash is not OAuth. The resource server must
validate the issuer, intended audience and granted scope; never repurpose a token
for another service. Avoid logging bodies or secret identifiers. Do not enable
unconditional retries for `tools/call`: repeating a modifying MCP tool can repeat its
side effects.

## What can be reused today

- [HTTP routing](routing.md): request data selects a configured upstream.
- [Model API relay recipes](agent-proxy.md): nginx connection limits, credential
  replacement and byte-preserving streaming, tested with mock model APIs.
- [Request phases](../concepts/request-phases.md): where Ruby runs within nginx.

These tests establish those mechanisms, not MCP compatibility. Connection limits
are concurrent-work controls, not monthly quotas or token billing. A long-lived
subscription should not silently consume the same allowance as a short MCP tool call.
Shared usage accounting, event-level processing and first-byte deadlines remain
planned v3 work; see the implementation-status table in the model API relay guide.

## Acceptance test for the first executable recipe

A follow-up recipe should use two localhost mock MCP backends and one endpoint,
with no provider account or real credentials. Its test must cover:

1. Discovery and a complete MCP tool list, known and unknown MCP tool names, supported and
   unknown protocol versions, and header/body disagreements.
2. Search versus source-processing routing, with the original request body and
   response bytes preserved. Editing the Ruby rule must change the destination.
3. Origin rejection, authorization failures and their response headers, JSON and
   SSE, cancellation on disconnect, and a modifying call sent only once.
4. Any supported older client version in a separate case, rather than applying
   the new cancellation/session rules to it.

Until that recipe runs, use this page to design the boundary and the HTTP recipe
to learn routing. Do not advertise an MCP-conformance result from the model API relay tests.

## Wider v3 direction

[AI gateway use cases](edge-control.md#mcp-access-policy) expands this routing design
into MCP tool authorization and user data-access checks, AI application-specific
profiles, progressive retrieval, recovery guidance and privacy-conscious observation. These remain planned uses;
the domain backend and the agent in the user’s AI application retain their own
responsibilities.

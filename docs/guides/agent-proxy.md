# Agent proxy

**Development version.** This page describes ngx_mruby 3.x on the branch
`next`, which is not released: the current release is 2.7. The recipes
below run on `next` today, and CI checks them. The diagrams show the agent
proxy that the v3 plan builds for v3.0.0, and say for each step whether it
runs today or which step of
[the plan](../proposals/v3-plan.md#agent-proxy-the-v30-use-case) adds it.

An agent proxy is nginx in front of the API of an LLM provider, between
coding agents and the provider. Ruby decides per request: whether the
client key is known, which upstream and which provider credential the
request gets, and whether the key may start another stream. nginx moves
the bytes: it reads the request, relays the response of the provider as it
arrives, and enforces the limits of its own modules. The proxy passes the
Anthropic Messages API (`/v1/messages`) and the OpenAI Responses API
(`/v1/responses`) through, with their streamed responses (server-sent
events); it does not translate between them.

## Recipes that run today

The configuration below serves both APIs with the same recipes. In front
of a mock of the two APIs, which the test client starts on ports 12372 and
12373 (`test/soak/mock_llm.rb`):

- `agent_proxy_auth.rb`, a server rewrite handler, looks up the client key
  in `Authorization` (`Bearer`) or `x-api-key`. An unknown key gets 401,
  and `error_page 401 @agent_proxy_401` gives it a JSON body in the error
  format of the API; the request does not reach the upstream.
- `limit_conn` per client key allows one request at a time. A second
  request of the key while the first streams gets 429 with a JSON body and
  `retry-after`, through the status 460, which no upstream sends, so that
  an upstream's own 429 passes unchanged.
- `agent_proxy_route.rb`, an access handler, reads the `model` of the JSON
  body, chooses the upstream block, and sets the credential that the
  upstream gets in place of the client's. A model without an upstream gets
  403.
- `proxy_pass` relays the response as it arrives (`proxy_buffering off`).
  An error of the upstream, such as 529, reaches the client with its body.
- `agent_proxy_log.rb`, a log handler, writes one line per request with
  the key id and `$upstream_status`.

```sample
label: development
case: test/t/cases/agent_proxy.rb
conf: test/conf/conf.d/60-agent-proxy.conf
script: test/html/agent_proxy_auth.rb
script: test/html/agent_proxy_route.rb
script: test/html/agent_proxy_log.rb
compared: test/html/agent_proxy_auth.expected
compared: test/html/agent_proxy_route.expected
compared: test/html/agent_proxy_limit.expected
compared: test/html/agent_proxy_log.expected
```

The client of the test (`test/t/cases/_agent_proxy_client.rb`) sends the
requests of each recipe to `/v1/messages` and prints one value per line;
the files above are the values that the case compares for the Messages
API. The case compares the same recipes for `/v1/responses`, and that a
stream of 50 deltas of each API arrives byte for byte.

## The request in v3.0

```diagram
agent-proxy-request
label: development
caption: The steps of a request through the agent proxy of v3.0, each with whether it runs today or which step of the v3 plan adds it.
source: docs/proposals/v3-plan.md 407-447 558-576
source: test/conf/conf.d/60-agent-proxy.conf 14-111
at: 8d1500bf0 2026-10-29
leg-now: Today: on `next`, checked by `agent_proxy.rb`
leg-next: Step 4: the next step of the v3 plan
leg-later: Steps 7a to 7e: later steps of the v3 plan
key: Today: the server rewrite handler checks the client key; an unknown key gets 401 with a JSON body
limit: Today: `limit_conn` per client key; a second stream of the key gets 429
route: Today: the access handler routes by the `model` of the body and swaps the credential; 403 for an unknown model
budget: Steps 7a and 7b: the model allowlist and the budgets of the key in a shared dictionary; `body_json` reads the `model` in C
upstream: Today: `proxy_pass` relays the request to the chosen upstream with the provider's credential
overloaded: Today: an upstream 529 reaches the client with its body
fallback: Step 7e: the reference proxy sets Host and SNI per provider, and sends a 529 to another provider with `error_page 529 = @name`
```

## The streamed response in v3.0

```diagram
agent-proxy-stream
label: development
caption: How the agent proxy of v3.0 relays a streamed response and charges its usage, each step with whether it runs today or which step of the v3 plan adds it.
source: docs/proposals/v3-plan.md 407-447 558-576
source: test/conf/conf.d/60-agent-proxy.conf 44-55
at: 8d1500bf0 2026-10-29
leg-now: Today: on `next`, checked by `agent_proxy.rb`
leg-next: Step 4: the next step of the v3 plan
leg-later: Steps 7a to 7e: later steps of the v3 plan
relay: Today: nginx relays the events of the provider byte for byte as they arrive
frame: Step 7b: the event filter frames the events in C and calls Ruby once per listed event
usage: Step 7b: Ruby reads the usage from `message_start` and `message_delta`, or from the terminal `response.*` event
charge: Step 7a: the counters of the shared dictionary are charged when the response ends or is cut
log: Step 4: the log handlers run before `access_log`, which then logs the cost and the tokens
deadline: Step 7c: a first-byte deadline; `proxy_read_timeout` stays the idle timeout of the stream
```

## The endpoints in v3.0

```diagram
agent-proxy-endpoints
label: development
caption: What the agent proxy of v3.0 answers itself, what it passes through and what it refuses, each with whether it runs today or which step of the v3 plan adds it.
source: docs/proposals/v3-plan.md 424-447
source: test/conf/conf.d/60-agent-proxy.conf 93-110
at: 8d1500bf0 2026-10-29
leg-now: Today: on `next`, checked by `agent_proxy.rb`
leg-next: Step 4: the next step of the v3 plan
leg-later: Steps 7a to 7e: later steps of the v3 plan
own-errors: Today: the proxy answers 401, 403 and 429 itself, with JSON bodies
models: Steps 7c and 7e: `GET /v1/models` from the client's model allowlist, and 504 after the first-byte deadline
pass: Today: `POST /v1/messages` and `POST /v1/responses` with their streams pass through unchanged
upstream-errors: Today: an error of the upstream reaches the client with its body
upgrade: Step 7e: the reference proxy refuses `Upgrade`, the WebSocket transport of the Responses API
```

The plan of the agent proxy, its protocol scope and the order of its steps
are in
[Agent proxy: the v3.0 use case](../proposals/v3-plan.md#agent-proxy-the-v30-use-case)
of the v3 plan. A sample of a planned feature appears on this page when
the feature and its test merge.

## Cost per request

The perf lane counts the instructions that nginx runs per request with
callgrind (`test/perf/compare.sh`). On 2026-10-14, with `PERF_N=20000`,
nginx 1.31.6 and the bundled mruby 4.0.0, in an Ubuntu 22.04 container on
aarch64, the tree of `next` at `bc2488a` with mruby 4.0.0 (#561) measured:

| What | Instructions per request (without GC) |
|---|---|
| The authentication check of the server rewrite handler, over proxying a 2 KB POST without Ruby | 25,276 (23,305) |
| Routing by `model` with `JSON.parse` of a 2 KB body, over the same proxying | 85,228 (82,097) |

[Agent proxy scenarios in the comparison](../test/README.md#agent-proxy-scenarios-in-the-comparison)
describes the scenarios.

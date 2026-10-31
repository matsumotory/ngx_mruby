# Documents

<a id="documents"></a>

Build request policies in Ruby inside nginx. These pages describe the
**v3 development branch `next`**: implemented behavior and planned work are
kept separate. For the released 2.7 line, use the [stable documentation](https://ngx.mruby.org/v2/).

## Try a working example

- [Model routing with local mocks](../examples/start/README.md#model-routing):
  choose an upstream by model, verify credential replacement, then edit the
  Ruby mapping and send the same request again. No provider key is needed.
- [Install](install/README.md): build the module for your own nginx, with the
  requirements, build options and upgrade checks.

## Add a policy to your application

- [LLM proxy](guides/agent-proxy.md): client-key checks, model routing,
  concurrency limits and streamed relay. Each planned extension is marked.
- [HTTP routing](guides/routing.md): select a backend from request data.
- [Access control](guides/access-control.md): refuse clients on a local denylist.
- [Rate limits](guides/rate-limit.md): apply a limit per API key.
- [Response filters](guides/body-filter.md): modify a response body.
- [TCP connections](guides/tcp.md): check the client before relaying a connection.
- [MCP gateway design](guides/mcp-gateway.md): an unverified architecture,
  with its missing evidence and boundaries stated explicitly.

## Look up an API or build option

- [Directives](directives/README.md): where nginx calls Ruby and how to configure it.
- [Ruby classes and methods](class_and_method/README.md): the API available to handlers.
- [Build reference](reference/build.md): compile options and bundled gems.

## Understand the request lifecycle

- [Request phases](concepts/request-phases.md): the order of handlers.
- [Filters](concepts/filters.md): headers, body chunks and their constraints.
- [Waiting without blocking](concepts/async.md): yielding work to nginx.
- [Lifetimes](concepts/lifetimes.md): request-owned and shared worker state.

## Operate and upgrade

- [Release notes](releases/README.md): read behavior changes before upgrading.
- [Migration from 2.x](migration/README.md): changes required for v3.
- [Trust boundary](security/trust-boundary.md): what the module and each script must validate.
- [Security policy](../SECURITY.md): supported releases and private vulnerability reporting.

## Contribute or follow development

- [Contributing](../CONTRIBUTING.md): scope, review and contribution steps.
- [Testing](test/README.md): the test suites and how to run them.
- [Development procedure](DEVELOPMENT.md): branch workflow and shared handoffs.
- [Current work](HANDOFF.md): the dated queue and public checkpoints.
- [Branch strategy](../README.md#branch-strategy): maintenance and development lines.
- [Other use cases](use_case/README.md): additional examples, with their context.

## License

ngx_mruby is distributed under the [MIT License](../MITL).

# Documentation

This is the documentation of ngx_mruby 3.x, developed on the branch
`next`. It has four kinds of page: a start page that runs ngx_mruby,
guides for tasks, the reference, and the concepts behind them.

## Documents

- Start: [Get started](../examples/start/README.md): run nginx with a Ruby handler in Docker, then change the script
- Guides: [Install](./install/README.md), [Route requests to a backend](./guides/routing.md), [Deny clients listed in a file](./guides/access-control.md), [Limit the rate per API key](./guides/rate-limit.md), [Change a response body](./guides/body-filter.md), [Allow TCP connections in Ruby](./guides/tcp.md), [Agent proxy](./guides/agent-proxy.md) (development version), and the [use cases](./use_case/README.md)
- Reference: [Directives](./directives/README.md), [Ruby classes and methods](./class_and_method/README.md), [Build](./reference/build.md)
- Concepts: [Request phases](./concepts/request-phases.md), [Filters](./concepts/filters.md), [Waiting without blocking](./concepts/async.md), [Lifetimes](./concepts/lifetimes.md)
- Releases: [Release notes](./releases/README.md), which start with the behavior changes to read before upgrading, and [Migrating from ngx_mruby 2.x to 3.0.0](./migration/README.md)
- Security: [Security policy](../SECURITY.md) and [Trust boundary](./security/trust-boundary.md): what ngx_mruby trusts, what it treats as client input, and what a script is responsible for
- Contributing: [Contributing](../CONTRIBUTING.md), [Testing](./test/README.md), [Developing ngx_mruby](./DEVELOPMENT.md) and the [state of the work](./HANDOFF.md)

## Branches and releases

- [Branch strategy](../README.md#branch-strategy): what `master`, `next` and `v2.x` hold, and what to pin to stay on 2.x
- [Promoting v3 to master](./DEVELOPMENT.md#promoting-v3-to-master): the procedure, for maintainers

## License

ngx_mruby is under the [MIT License](../MITL).

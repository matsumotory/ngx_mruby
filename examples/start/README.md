# Get started

Run a local model-routing proxy, send the same request to two mock APIs, then
change the destination by editing Ruby. No provider account or API key is
needed. The mocks report which route and credential nginx selected; they do
not generate text or contact an LLM.

This is a trial of the **v3 development branch `next`**, not a released v3
image or a production configuration. The example also retains `/hello` for
trying a basic Ruby content handler.

## Before you start

You need Docker with the Compose plugin (`docker compose`), git, curl and a
network connection. The first run builds nginx and mruby from this checkout;
it downloads nginx from nginx.org and the gems pinned by `build_config.rb.lock`
from GitHub. Later runs reuse the image. No verified prebuilt v3 image is supplied.

[`compose.yaml`](compose.yaml) publishes port 8080 only on `127.0.0.1`. The two
mock APIs listen on loopback inside the same container; they are not published
to the host. All keys in this example are public demonstration values. Do not
expose this configuration as a public service.

## Start the local proxy

```console
$ git clone --branch next https://github.com/matsumotory/ngx_mruby.git
$ cd ngx_mruby/examples/start
$ docker compose up --build --wait
```

`--wait` returns when `/hello`, the container health check, answers. The requests
below then verify routing separately. Keep the example directory as your
working directory for every command on this page.

## Model routing

Send model A with the local client key. nginx checks the key, looks up the
model in `route.rb`, replaces the client credential and forwards the body.
The mock response identifies the destination and confirms that it received
its own upstream credential, not the client key.

`client.conf` supplies the same local URL and demonstration headers for each
request, so the commands below focus on the model. Its complete contents are
shown with the other files below.

```console
$ curl -K client.conf -d '{"model": "mock-model-a"}'
{
  "upstream":"a",
  "model":"mock-model-a",
  "credential_replaced":true
}
```

Change only `model` to choose API B. The URL and the client key stay the same.

```console
$ curl -K client.conf -d '{"model": "mock-model-b"}'
{
  "upstream":"b",
  "model":"mock-model-b",
  "credential_replaced":true
}
```

This demonstrates model routing and credential replacement. It does not
convert API formats, test real providers or implement LLM inference. For
streamed relay, concurrency limits and the separate integration-test recipe,
read the [agent proxy guide](../../docs/guides/agent-proxy.md).

## Change the route without changing the request

Replace model A's destination **and** upstream credential in the mapping. The
command saves the original as `route.rb.orig`. The mounted Ruby handler has
no `cache` parameter, so the next request reads the edited file without a reload.

```console
$ sed -i.orig 's/local_api_a/local_api_b/;s/upstream-a/upstream-b/' route.rb
$ curl -K client.conf -d '{"model": "mock-model-a"}'
{
  "upstream":"b",
  "model":"mock-model-a",
  "credential_replaced":true
}
```

The request still says `mock-model-a`; the response now says `upstream: b`.
Restore the original mapping and confirm that the same request returns to A.

```console
$ mv route.rb.orig route.rb
$ curl -K client.conf -d '{"model": "mock-model-a"}'
{
  "upstream":"a",
  "model":"mock-model-a",
  "credential_replaced":true
}
```

## Check rejected requests

A missing or unknown client key gets 401. An unmapped model gets 403.
Malformed JSON gets 400. These requests stop at the proxy instead of reaching
a mock API.

```console
$ curl -sS localhost:8080/v1/responses -d '{}' -o /dev/null -w '%{http_code}\n'
401
$ curl -K client.conf -o /dev/null -w '%{http_code}\n' -d '{"model": "unknown"}'
403
$ curl -K client.conf -o /dev/null -w '%{http_code}\n' -d '{'
400
```

## The files that run

`nginx.conf` connects the access handler, named upstreams and mock endpoints.
It also keeps the basic `/hello` handler. The folder is mounted read-only
inside the container; edit its files on the host.

```text title="client.conf"
# Local demonstration credentials, not for a public service.
url = "http://localhost:8080/v1/responses"
header = "Content-Type: application/json"
header = "Authorization: Bearer local-client"
silent
show-error
```

```nginx title="nginx.conf"
# Local examples: one proxy and two mock APIs inside the container.
user nobody nogroup;
worker_processes 1;
error_log /dev/stderr;

events {
    worker_connections 64;
}

http {
    access_log /dev/stdout;

    upstream local_api_a { server 127.0.0.1:8081; }
    upstream local_api_b { server 127.0.0.1:8082; }

    server {
        listen 8080;

        location /hello {
            mruby_content_handler /example/hello.rb;
        }

        location = /v1/responses {
            set $selected_backend "";
            set $upstream_credential "";
            mruby_enable_read_request_body on;
            mruby_access_handler /example/route.rb;
            proxy_http_version 1.1;
            proxy_set_header Connection close;
            proxy_set_header Authorization $upstream_credential;
            proxy_set_header x-api-key "";
            proxy_buffering off;
            proxy_pass http://$selected_backend;
        }
    }

    server {
        listen 127.0.0.1:8081;
        location = /v1/responses {
            mruby_enable_read_request_body on;
            mruby_content_handler /example/mock.rb;
        }
    }

    server {
        listen 127.0.0.1:8082;
        location = /v1/responses {
            mruby_enable_read_request_body on;
            mruby_content_handler /example/mock.rb;
        }
    }
}
```

`route.rb` checks the local key and selects both parts of the route. The
nginx variables pass those values to `proxy_pass` and `proxy_set_header`.

```ruby title="route.rb"
# Local demonstration credentials. Never use these values for a public service.
r = Nginx::Request.new
v = Nginx::Var.new

if r.headers_in["Authorization"] != "Bearer local-client"
  Nginx.return Nginx::HTTP_UNAUTHORIZED
else
  routes = {
    "mock-model-a" => ["local_api_a", "Bearer local-upstream-a"],
    "mock-model-b" => ["local_api_b", "Bearer local-upstream-b"]
  }
  begin
    body = JSON.parse(r.body)
    route = body.kind_of?(Hash) ? routes[body["model"]] : nil
    if route
      v.selected_backend = route[0]
      v.upstream_credential = route[1]
      Nginx.return Nginx::DECLINED
    else
      Nginx.return Nginx::HTTP_FORBIDDEN
    end
  rescue JSON::ParserError, ArgumentError
    Nginx.return Nginx::HTTP_BAD_REQUEST
  end
end
```

`mock.rb` reports the request received by API A or B. It returns a boolean
for the credential check, not the credential itself.

```ruby title="mock.rb"
# These local mocks report the selected route; they do not call an LLM.
r = Nginx::Request.new
v = Nginx::Var.new
name = v.server_port == "8081" ? "a" : "b"
body = JSON.parse(r.body)
r.headers_out["Content-Type"] = "application/json"
Nginx.rputs JSON.pretty_generate({
  "upstream" => name,
  "model" => body["model"],
  "credential_replaced" => r.headers_in["Authorization"] == "Bearer local-upstream-#{name}"
})
```

## Try a basic response handler

`hello.rb` runs Ruby inside the nginx worker and writes the response directly,
without an upstream. Change the greeting, send the request again, then restore it.

```ruby title="hello.rb"
# The content handler of the start page (examples/start/nginx.conf).
r = Nginx::Request.new
name = r.var.arg_name.to_s
name = "world" if name.empty?
r.content_type = "text/plain"
Nginx.rputs "Hello, #{name}! hello.rb answered #{r.method} #{r.uri}.\n"
```

```console
$ curl -sS 'http://localhost:8080/hello?name=Ruby'
Hello, Ruby! hello.rb answered GET /hello.
$ sed -i.orig 's/Hello/Good morning/' hello.rb
$ curl -sS 'http://localhost:8080/hello?name=Ruby'
Good morning, Ruby! hello.rb answered GET /hello.
$ mv hello.rb.orig hello.rb
```

## Reload a configuration change

An uncached Ruby handler reads its file on the next request. Changes to
`nginx.conf` or a Ruby handler compiled with `cache` instead need a configuration
check and reload. Use the paths of this image:

```console
$ docker compose exec -T nginx /usr/local/nginx/sbin/nginx -t -c /example/nginx.conf
$ docker compose exec -T nginx /usr/local/nginx/sbin/nginx -s reload -c /example/nginx.conf
$ curl -sS 'http://localhost:8080/hello?name=Ruby'
Hello, Ruby! hello.rb answered GET /hello.
$ curl -K client.conf -d '{"model": "mock-model-a"}'
{
  "upstream":"a",
  "model":"mock-model-a",
  "credential_replaced":true
}
```

For a production configuration, use [compiled-code caching](../../docs/directives/README.md#caching-compile-code)
to avoid reading a Ruby file on every request. Changes to mrbgems or build
options need an image rebuild, not only a reload.

## Stop the trial

```console
$ docker compose down
```

Use `docker compose logs nginx` if startup or the health check fails. A
base-image metadata/download failure is a registry or network failure before
nginx starts; it is not a response from this example.

## Continue with your own application

- [Agent proxy](../../docs/guides/agent-proxy.md): authentication, model routing,
  concurrency limits and streamed relay, with their integration tests and planned work.
- [Install](../../docs/install/README.md): build a static or dynamic module for
  an existing deployment, matching its nginx version and build options.
- [Directives](../../docs/directives/README.md): choose the phase where nginx runs Ruby.
- [Request phases](../../docs/concepts/request-phases.md): follow one request through its handlers.

Official nginx packages and images do not contain ngx_mruby. `--with-compat`
does not make a module compatible with arbitrary nginx versions. Running this
Linux container on a Mac is not a native macOS build test.

The `examples` workflow executes these commands and compares their outputs
for each relevant commit. Consult the run for the revision you use: a previous
run is not proof that a changed recipe works. The documented older Hello-only
trial took 170 seconds on GitHub's `ubuntu-24.04` runner on 2026-10-29
(Docker Engine 28.0.4, Compose 2.38.2); this is historical build evidence,
not a current duration guarantee, a routing test or an arm64 result.

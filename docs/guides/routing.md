# Route requests to a backend

nginx passes a request to a backend with `proxy_pass`. With
[`mruby_set`](../directives/README.md#mruby_set-and-mruby_set_code), a
Ruby script computes the backend for each request, and `proxy_pass` uses
the variable that the script sets. nginx then connects to the backend and
relays the response; the script runs once per request and returns a
string.

## The sample

The script picks the backend from the request header `X-Tenant`, with a
table of tenants and backend addresses, and backend `a` for a request
without the header or with an unknown tenant. The value of the last line of
the script is the value of `$backend`.

```sample
case: test/t/cases/guides.rb
conf: test/conf/conf.d/73-guide-routing.conf
script: test/html/guide_routing.rb
request: test/html/guide_routing.request
response: test/html/guide_routing.response
```

The case also sends a request without `X-Tenant` and expects the answer of
backend `a`, on port 18164.

## Run it independently

This complete loopback example uses the same routing table as the sample,
with separate ports and a cached Ruby script. It needs no existing nginx
configuration or backend service. The chosen fallback is backend `a`, not
an authentication decision: `X-Tenant` alone must not grant tenant access.

### Prerequisites and version

The recipe was executed with development commit
[`6d65a12ec`](https://github.com/matsumotory/ngx_mruby/commit/6d65a12ecf166e11a6ece40d56f0f2efb05ea112),
its default gem lock, nginx 1.31.8, and GCC 11.4.0 on Ubuntu 22.04 aarch64.
This is a next-branch example, not a released v3 feature claim. This exact
recipe has not been executed against the released v2.7.2 tag.

Use a standalone nginx built with ngx_mruby's HTTP module; see
[installation](../install/README.md). In the shell where that build was
installed, set `NGX_BIN` to its absolute executable path. For a source build
installed under `build/nginx` in the current checkout:

```sh
export NGX_BIN="$PWD/build/nginx/sbin/nginx"
"$NGX_BIN" -V
```

The shell also needs `curl`, `mktemp`, `cmp` and ordinary POSIX utilities.
Ports 19480, 19481 and 19482 must be free in the same network namespace as
nginx and curl. Run as an ordinary user, or inside an isolated test
container; no host port publication is needed. A distribution nginx
without the module cannot run this recipe. Dynamic-module loading and
non-Linux systems were not exercised here.

### Create, request, check and stop

Paste the whole block into that shell. It creates both files in a fresh
temporary directory, checks the configuration, starts its own nginx,
asserts status, media type and the complete response body for five inputs,
and stops only that instance. The logs and files remain in the printed
directory for inspection. The escaped nginx variables in the shell
heredoc must keep their backslashes; the shell expands only `RUN_DIR`.

```sh
(
set -eu
: "${NGX_BIN:?Set NGX_BIN to the absolute path of nginx with ngx_mruby}"
case "$NGX_BIN" in /*) ;; *) echo 'NGX_BIN must be absolute' >&2; exit 1 ;; esac
RUN_DIR="$(mktemp -d)"
mkdir -p "$RUN_DIR/logs"
printf 'Runtime and logs: %s\n' "$RUN_DIR"
started=0
cleanup() {
    result=$?
    trap - 0
    if [ "$started" = 1 ]; then
        "$NGX_BIN" -p "$RUN_DIR/" -c nginx.conf -s quit || result=1
        tries=0
        while [ -f "$RUN_DIR/logs/nginx.pid" ] && [ "$tries" -lt 50 ]; do
            sleep 0.1
            tries=$((tries + 1))
        done
        if [ -f "$RUN_DIR/logs/nginx.pid" ]; then
            echo 'Shutdown not confirmed; inspect the runtime logs' >&2
            result=1
        fi
    fi
    if [ "$result" != 0 ]; then
        tail -n 30 "$RUN_DIR/logs/error.log" >&2 || :
    fi
    exit "$result"
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' TERM
cat > "$RUN_DIR/route.rb" <<'RUBY'
backends = {
  "a" => "127.0.0.1:19481",
  "b" => "127.0.0.1:19482",
}
tenant = Nginx::Request.new.headers_in["X-Tenant"].to_s
backends.fetch(tenant, backends["a"])
RUBY
cat > "$RUN_DIR/nginx.conf" <<CONF
worker_processes 1;
pid logs/nginx.pid;
error_log logs/error.log notice;
events { worker_connections 64; }
http {
    access_log off;
    default_type text/plain;
    server {
        listen 127.0.0.1:19480;
        location / {
            mruby_set \$backend "$RUN_DIR/route.rb" cache;
            proxy_pass http://\$backend;
        }
    }
    server {
        listen 127.0.0.1:19481;
        return 200 "backend a: \$request_uri\n";
    }
    server {
        listen 127.0.0.1:19482;
        return 200 "backend b: \$request_uri\n";
    }
}
CONF
"$NGX_BIN" -p "$RUN_DIR/" -c nginx.conf -t
"$NGX_BIN" -p "$RUN_DIR/" -c nginx.conf
started=1
check() {
    label=$1
    backend=$2
    shift 2
    meta=$(curl --noproxy '*' --fail --silent --show-error --max-time 5 \
        -D "$RUN_DIR/headers" -o "$RUN_DIR/body" \
        -w '%{http_code} %{content_type}' "$@" \
        'http://127.0.0.1:19480/orders?limit=2')
    test "$meta" = '200 text/plain'
    printf 'backend %s: /orders?limit=2\n' "$backend" > "$RUN_DIR/expected"
    cmp "$RUN_DIR/expected" "$RUN_DIR/body"
    printf '%s -> %s; ' "$label" "$meta"
    cat "$RUN_DIR/body"
}
check tenant-a a -H 'X-Tenant: a'
check tenant-b b -H 'X-Tenant: b'
check absent a
check unknown a -H 'X-Tenant: other'
check address-input a -H 'X-Tenant: 127.0.0.1:1'
)
```

After the runtime-directory line and nginx configuration messages, the
five successful checks print these lines. Each body ends with one newline;
`cmp` checks it too. The path and query string reach the selected backend.

```text
tenant-a -> 200 text/plain; backend a: /orders?limit=2
tenant-b -> 200 text/plain; backend b: /orders?limit=2
absent -> 200 text/plain; backend a: /orders?limit=2
unknown -> 200 text/plain; backend a: /orders?limit=2
address-input -> 200 text/plain; backend a: /orders?limit=2
```

The address-shaped header is a table key, not a destination: it reaches
backend `a`. Requests are sequential, including a switch from `a` to `b`
and back to `a`; this is a correctness check, not a load or performance
measurement. The Ruby code only selects a string. nginx performs the
upstream connection and response relay.

### If a check fails

- `unknown directive "mruby_set"`: check `NGX_BIN` and its `-V` output;
  the executable needs ngx_mruby, not just a Ruby interpreter.
- `bind() ... address already in use`: leave the existing process alone.
  Free the three ports or change all corresponding addresses in both the
  configuration and Ruby table, plus the curl URL, before trying again.
- `502` or a curl connection error: inspect `logs/error.log` in the printed
  directory and the three loopback listeners. No DNS resolver is needed
  for these literal addresses.
- An assertion or `cmp` failure: inspect `headers`, `body` and `expected`
  in that directory. A `200` by itself does not establish correct routing.
- A Ruby path/load error: check the generated absolute script path and
  directory permissions. The script uses `cache`; after editing it,
  restart this example to compile the new contents.

A successful exit confirms the temporary instance removed its PID file.
On failure the trap still requests a graceful quit if startup succeeded;
if shutdown cannot be confirmed, inspect the recorded instance before
reusing the ports. Remove only this example's printed directory when its
logs are no longer needed. The existing integration fixture remains in
`test/t/cases/guides.rb`; the block above additionally checks explicit
unknown and address-shaped inputs without changing that fixture.

## What to keep in mind

- `mruby_set` runs in the rewrite phase of the location, before nginx
  connects to the backend ([Request phases](../concepts/request-phases.md)).
  The script reads the request through `Nginx::Request`; it does not see
  the response.
- `proxy_pass` with a variable takes an address as it is. A value that
  names an `upstream` block uses that block; any other host name needs
  nginx's `resolver` directive.
- The request header is client input: the script compares it with the
  keys of its table, so that a client can only reach the backends that the
  table lists ([Trust boundary](../security/trust-boundary.md)).
- Without `cache`, nginx reads the script file for every request. Add
  `cache` to the directive, or use `mruby_set_code`, in production
  ([Caching compile code](../directives/README.md#caching-compile-code)).

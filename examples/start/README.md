# Get started

This page runs nginx with ngx_mruby in Docker, sends a request that a Ruby
script answers, and then changes the script. The example is the folder
`examples/start` of the repository: [`compose.yaml`](compose.yaml) builds
nginx with ngx_mruby from the source in your checkout with the
[`Dockerfile`](Dockerfile), and starts it with the `nginx.conf` and
`hello.rb` of the folder.

## Before you start

- You need Docker with the Compose plugin (`docker compose`), git, curl
  and a network connection: the build downloads nginx from nginx.org and the
  mrbgems of `build_config.rb` from GitHub.
- No verified prebuilt image of this v3 development version is provided,
  so the first run compiles mruby and nginx. On 2026-10-29, on GitHub's `ubuntu-24.04` runner with Docker
  Engine 28.0.4 and Docker Compose 2.38.2, step 3 took 170 seconds. Later
  runs reuse the built image.
- These steps run in CI on every pull request that changes `examples/`
  (the workflow `.github/workflows/examples.yml`), which compares every
  output on this page with what the commands print.

## Run nginx with a Ruby handler

The site documents ngx_mruby 3.x, which is developed on the branch `next`.

1. Clone the branch `next` of the repository.

   ```console
   $ git clone --branch next https://github.com/matsumotory/ngx_mruby.git
   ```

2. Go to the folder of the example.

   ```console
   $ cd ngx_mruby/examples/start
   ```

3. Build the image and start nginx. With `--wait`, the command returns
   when nginx answers the health check of `compose.yaml`, and Compose
   reports the container `start-nginx-1` as healthy.

   ```console
   $ docker compose up --build --wait
   ```

4. Send a request to `/hello` with the argument `name`. The Ruby script
   writes the response.

   ```console
   $ curl -s 'http://localhost:8080/hello?name=Ruby'
   Hello, Ruby! hello.rb answered GET /hello.
   ```

## What answered the request

`nginx.conf` sends the requests for `/hello` to the script with
[`mruby_content_handler`](../../docs/directives/README.md#mruby_content_handler-and-mruby_content_handler_code):

```nginx title="nginx.conf"
# The nginx configuration of the start page. compose.yaml mounts this
# folder at /example, and the image starts nginx with this file.
user nobody nogroup;
worker_processes 1;
error_log /dev/stderr;

events {
    worker_connections 64;
}

http {
    access_log /dev/stdout;

    server {
        listen 8080;

        location /hello {
            mruby_content_handler /example/hello.rb;
        }
    }
}
```

`hello.rb` reads the argument through `Nginx::Request` and writes the body
with `Nginx.rputs`:

```ruby title="hello.rb"
# The content handler of the start page (examples/start/nginx.conf).
r = Nginx::Request.new
name = r.var.arg_name.to_s
name = "world" if name.empty?
r.content_type = "text/plain"
Nginx.rputs "Hello, #{name}! hello.rb answered #{r.method} #{r.uri}.\n"
```

nginx runs the script inside the worker process, with an mruby VM that
ngx_mruby embeds in nginx. No other process takes part. The
[Ruby reference](../../docs/class_and_method/README.md) lists the classes
and methods that a script can use.

## Change the script

`compose.yaml` mounts this folder into the container, and the directive
names the script without the parameter `cache`, so nginx reads the file
again for every request. A change to `hello.rb` takes effect with the next
request, without a reload.

1. Replace `Hello` with `Good morning` in `hello.rb`. The command keeps
   the original file as `hello.rb.orig`.

   ```console
   $ sed -i.orig 's/Hello/Good morning/' hello.rb
   ```

2. Send the request again. The response has the new greeting.

   ```console
   $ curl -s 'http://localhost:8080/hello?name=Ruby'
   Good morning, Ruby! hello.rb answered GET /hello.
   ```

3. Put the original script back.

   ```console
   $ mv hello.rb.orig hello.rb
   ```

4. Validate the mounted configuration and reload it. Use the binary and
   configuration paths of this image, rather than relying on `PATH`.

   ```console
   $ docker compose exec -T nginx /usr/local/nginx/sbin/nginx -t -c /example/nginx.conf
   $ docker compose exec -T nginx /usr/local/nginx/sbin/nginx -s reload -c /example/nginx.conf
   $ curl -s 'http://localhost:8080/hello?name=Ruby'
   Hello, Ruby! hello.rb answered GET /hello.
   ```

5. Stop and remove the container. Compose reports the container
   `start-nginx-1` as removed.

   ```console
   $ docker compose down
   ```

Reading the file for every request is convenient while you write a
script, and it reads the disk on the request path. In production, add
`cache` to the directive, as
[Caching compile code](../../docs/directives/README.md#caching-compile-code)
shows, so that nginx compiles the script once when it reads its
configuration.

## Choose how to customize it

| Change | Apply it | Why |
|---|---|---|
| Ruby without `cache` | Send the next request | The handler reads the mounted script each time |
| `nginx.conf`, or Ruby compiled with `cache` | Validate with `nginx -t`, then reload as above | nginx compiles configuration-time code when it reads the configuration |
| mrbgems or build options | Rebuild the image | These change the compiled module |

The mount is read-only inside the container; edit files on the host. The example
publishes port 8080 on host interfaces; for a local-only trial, change the Compose
mapping to `127.0.0.1:8080:8080` before starting it. Use `docker compose logs nginx`
to inspect a failed health check or configuration error. An image-metadata error
before compilation is a registry/network failure, not an nginx response.

Containers are one trial path. For Linux installation into an existing deployment,
follow [Install](../../docs/install/README.md), matching the nginx version and
module build options. Official nginx packages and images do not include ngx_mruby;
`--with-compat` is not compatibility with arbitrary nginx versions. Running this
Linux image on a Mac is not evidence of a native macOS build.

The recorded 170-second run above is historical CI evidence, not a current timing
guarantee or an arm64 result. A fresh linux/arm64 trial on 2026-10-30 stopped while
fetching the Ubuntu base-image metadata, before compilation. That attempt did not
validate startup, editing or reload. The examples workflow validates the commands
on its Linux runner; consult its run for the commit you use.

Primary references: [NGINX containers](https://docs.nginx.com/nginx/admin-guide/installing-nginx/installing-nginx-docker/),
[Linux packages](https://nginx.org/en/linux_packages.html),
[dynamic modules](https://blog.nginx.org/blog/nginx-dynamic-modules-how-they-work),
[reload](https://nginx.org/en/docs/control.html), and
[bind mounts](https://docs.docker.com/engine/storage/bind-mounts/).

## Next steps

- [Install](../../docs/install/README.md): build ngx_mruby into your own
  nginx, as a static or a dynamic module.
- [Directives](../../docs/directives/README.md): the phases where nginx
  runs Ruby, and the directive for each.
- [Request phases](../../docs/concepts/request-phases.md): the order in
  which nginx runs the handlers of one request.

- [Agent proxy](../../docs/guides/agent-proxy.md): extend the handler into tested model routing and streamed relay recipes.

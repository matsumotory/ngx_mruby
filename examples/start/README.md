# Get started

This page runs nginx with ngx_mruby in Docker, sends a request that a Ruby
script answers, and then changes the script. The example is the folder
[examples/start](.) of the repository: `compose.yaml` builds nginx with
ngx_mruby from the source in your checkout and starts it with the
`nginx.conf` and `hello.rb` of the folder.

## Before you start

- You need Docker with the Compose plugin (`docker compose`), git, and a
  network connection: the build downloads nginx from nginx.org and the
  mrbgems of `build_config.rb` from GitHub.
- No image of ngx_mruby is published yet, so the first run compiles mruby
  and nginx. In CI the first build takes BUILD_MINUTES minutes. Later runs
  reuse the built image.
- These steps run in CI on every pull request that changes `examples/`
  (the workflow `.github/workflows/examples.yml`), which compares every
  output on this page with what the commands print. CHECKED_ON.

## Run nginx with a Ruby handler

1. Clone the repository and go to the folder of the example. The site
   documents ngx_mruby 3.x, which is developed on the branch `next`.

   ```console
   $ git clone --branch next https://github.com/matsumotory/ngx_mruby.git
   $ cd ngx_mruby/examples/start
   ```

2. Build the image and start nginx. With `--wait`, the command returns
   when nginx answers the health check of `compose.yaml`, and Compose
   reports the container `start-nginx-1` as healthy.

   ```console
   $ docker compose up --build --wait
   ```

3. Send a request to `/hello` with the argument `name`. The Ruby script
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

3. Put the original script back, then stop and remove the container.
   Compose reports the container `start-nginx-1` as removed.

   ```console
   $ mv hello.rb.orig hello.rb
   $ docker compose down
   ```

Reading the file for every request is convenient while you write a
script, and it reads the disk on the request path. In production, add
`cache` to the directive, as
[Caching compile code](../../docs/directives/README.md#caching-compile-code)
shows, so that nginx compiles the script once when it reads its
configuration.

## Next steps

- [Install](../../docs/install/README.md): build ngx_mruby into your own
  nginx, as a static or a dynamic module.
- [Directives](../../docs/directives/README.md): the phases where nginx
  runs Ruby, and the directive for each.
- [Request phases](../../docs/concepts/request-phases.md): the order in
  which nginx runs the handlers of one request.

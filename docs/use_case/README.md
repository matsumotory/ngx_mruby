# Use cases

Each use case below has a sample that CI runs, on this page or on the
guide it links to, or is marked untested with the reason. A sample shows
the files of a test of this repository and the response that the test
compares on every CI run (3.5 of the site proposal).

## Hello world

A content handler writes the response.

```sample
case: test/t/cases/guides.rb
conf: test/conf/conf.d/72-guide-hello.conf
script: test/html/guide_hello.rb
request: test/html/guide_hello.request
response: test/html/guide_hello.response
```

[The start page](../../examples/start/README.md) runs a handler of the same
kind in Docker.

## Reverse proxy

A script chooses the backend of `proxy_pass` for each request. The sample
is on the guide [Route requests to a backend](../guides/routing.md).

## File based access list

An access handler answers 403 for clients that a file lists. The sample is
on the guide [Deny clients listed in a file](../guides/access-control.md).

## Output filter converting Markdown to HTML

A body filter converts the body of a `.md` file into HTML. The filter part
is the sample of the guide [Change a response body](../guides/body-filter.md),
which wraps a text file in an HTML page.

**Untested.** The conversion of Markdown needs the gem mruby-discount,
which `build_config.rb` leaves out (its line is commented out), and no CI
job builds it. To try it, uncomment the line of mruby-discount in
`build_config.rb` and build again.

```nginx
location ~ \.md$ {
    mruby_output_body_filter /path/to/filter.rb cache;
}
```

```ruby
# /path/to/filter.rb
f = Nginx::Filter.new

css = "/css/markdown.css"   # a stylesheet that your server serves
md = Discount.new css, "markdown"

f.body = md.md2html f.body
```

## Change to maintenance mode with Redis

An access handler reads a flag from Redis and answers 503 while the flag is
set; otherwise nginx proxies the request. After an article by takeswim
([in Japanese](https://takeswim.hateblo.jp/entry/2013/10/03/182748)).

**Untested.** The test job of CI runs no Redis server, so no sample runs
this use case. The default build includes the gem mruby-redis, whose
`Redis` class it uses.

```nginx
location / {
    mruby_access_handler_code '
        redis = Redis.new "127.0.0.1", 6379
        maintenance = redis.get("maintenance") == "on"
        redis.close
        Nginx.return Nginx::HTTP_SERVICE_UNAVAILABLE if maintenance
    ';
    proxy_pass http://127.0.0.1:8080;
}
```

mruby-redis waits for each answer of the Redis server in the worker, so the
worker serves no other request meanwhile.

## Markdown web page

A content handler renders a Markdown text as an HTML page.

**Untested.** It needs the gem mruby-discount, which `build_config.rb`
leaves out (its line is commented out), and no CI job builds it. To try it,
uncomment that line and build again.

```nginx
location ~ \.rb$ {
    mruby_add_handler on;
}
```

```ruby
# md.rb, under the root of the location
r = Nginx::Request.new
r.content_type = "text/html"

md = Discount.new "/css/markdown.css", "md test"

body = <<DATA
# Section

- item 1
- item 2
DATA

Nginx.echo md.header + body.to_html + md.footer
```

## File server like Dropbox link

A rewrite handler looks up the path of the request in Redis and redirects
to a file until the link expires.

**Untested.** The test job of CI runs no Redis server, so no sample runs
this use case. The default build includes the gem mruby-redis.

```nginx
location /dropbox {
    mruby_rewrite_handler /path/to/dropbox.rb;
}
```

```ruby
# /path/to/dropbox.rb
redis = Redis.new "127.0.0.1", 6379
r = Nginx::Request.new
file = redis.hget r.uri, "file"
expire = redis.hget r.uri, "expire"
redis.close

if file && expire.to_i >= Time.now.to_i
  Nginx.redirect file
else
  Nginx.return Nginx::DECLINED
end
```

The link is a hash in Redis, for example with `redis-cli`:

```text
HSET /dropbox/aaabbbcccddd file /files/hoge.html
HSET /dropbox/aaabbbcccddd expire 1900000000
```

## Articles and other examples

- [Dynamic Image Provider (in Japanese)](https://techhey.hatenablog.com/entry/2014/04/19/162323)
- [Research ngx_mruby and use output filter (in Russian)](https://habr.com/ru/articles/225313/)
- [ACME auto ssl using Let's Encrypt](https://github.com/matsumotory/ngx_mruby/blob/v2.7.2/test/conf/auto-ssl/nginx.conf.client_example)
  (ngx_mruby 2.x): needs the auto-ssl mrbgem, which ngx_mruby 3.0.0 does not
  have (see
  [The auto-ssl mrbgem and the classes that came with it](../install/README.md#the-auto-ssl-mrbgem-and-the-classes-that-came-with-it)),
  and a running Redis server. Its ACME client speaks ACMEv1, which Let's
  Encrypt no longer serves.

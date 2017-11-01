# Use Case
- [Hello World](https://github.com/matsumotory/ngx_mruby/tree/master/docs/use_case#hello-world)
- [Reverse Proxy](https://github.com/matsumotory/ngx_mruby/tree/master/docs/use_case#reverse-proxy)
- [Change to maintenance mode with Redis](https://github.com/matsumotory/ngx_mruby/tree/master/docs/use_case#change-to-maintenance-mode-with-redis)
- [Markdown Web Page](https://github.com/matsumotory/ngx_mruby/tree/master/docs/use_case#markdown-web-page)
- [Output Filter Converting Markdown to HTML](https://github.com/matsumotory/ngx_mruby/tree/master/docs/use_case#output-filter-convering-markdown-to-html)
- [File Based Access List](https://github.com/matsumotory/ngx_mruby/tree/master/docs/use_case#file-based-access-list)
- [File Server like Dropbox Link](https://github.com/matsumotory/ngx_mruby/tree/master/docs/use_case#file-server-like-dropbox-link)
- [Dynamic Image Providor (in Japanese)](http://techhey.hatenablog.com/entry/2014/04/19/162323)
- [Dynamic reverse proxy using access information (in Japanese)](http://blog.cloudpack.jp/2014/07/08/ngx-mruby-nginx-script/)
- [Research ngx_mruby and use output filter (in Russian)](http://habrahabr.ru/post/225313/)
- [ACME auto ssl using Let's Encrypt](https://github.com/matsumotory/ngx_mruby/blob/master/test/conf/auto-ssl/nginx.conf.client_example)

## Hello world
#### /path/to/hello.rb
```ruby
Nginx.echo "Hello World"
```

#### nginx.conf
```nginx
server {
  location /hello {
    mruby_content_handler /path/to/hello.rb;
  }
}
```

#### Access
```bash
$ curl http://127.0.0.1/hello
Hello World
```

## Reverse Proxy
#### /path/to/proxy.rb
```ruby
backends = [
  "127.0.0.1:8001",
  "127.0.0.1:8002",
  "127.0.0.1:8003",
]
# write algorithm for selecting backend
backends[rand(backends.length)]
```
#### nginx.conf
```nginx
server {
  location /proxy {
    mruby_set $backend /path/to/proxy.rb;
    proxy_pass  http://$backend;
  }
}
```

## Change to maintenance mode with Redis
refs: http://takeswim.hateblo.jp/entry/2013/10/03/182748
#### nginx.conf
```nginx
worker_processes  1;

daemon off;
master_process off;

events {
    worker_connections  1024;
}

http {
    # Create redis connection object at startup,
    # and set it into user-data object
    mruby_init_code '
        userdata = Userdata.new "redis_data_key"
        userdata.redis = Redis.new "127.0.0.1", 6379
    ';

    server {
        listen       7777;
        location / {
          echo "port 7777 contents";
        }
    }

    server {
        listen       57777;

        location /mruby {
          mruby_set_code $maint '
              userdata = Userdata.new "redis_data_key"
              redis = userdata.redis
              redis.get "ngx_maint"
          ';
          if ($maint = "TRUE") {
            mruby_set_code $res_maint '
              JSON::stringify({"result"=>"ERR", "time"=>Time.now.to_i})
          ';
            echo $res_maint;
          }
          if ($maint != "TRUE") {
             proxy_pass   http://127.0.0.1:7777;
          }
        }
    }
}
```
## Markdown Web Page
##### Activate mruby-discount when build ngx_mruby
```ruby
  # use markdown on mod_mruby
  conf.gem :git => 'git://github.com/matsumotory/mruby-discount.git'
```
##### nginx.conf
```nginx
location ~ \.rb$ {
    mruby_add_handler on;
}
```
##### md.rb
```ruby
r = Nginx::Request.new
r.content_type = "text/html"

# setup markdown engine
title = "md test"
css = "https://gist.github.com/andyferra/2554919/raw/2e66cabdafe1c9a7f354aa2ebf5bc38265e638e5/github.css"
md = Discount.new css, title

# create markdown data
body = <<DATA

# Section
## aaa

- hoge
- foo

## bbb

__code__

    a = 1
    b = a + 1

DATA

# create html
html = md.header
html << body.to_html
html << md.footer

# create reponse
Nginx.echo html
```
##### Response (images)
Access to http://example.com/md.rb

***
![response](https://dl.dropboxusercontent.com/s/fkzsuv94tr541zg/md_test.png)
***

## Output Filter Convering Markdown to HTML
``.md`` markdown file convert to html using output filter
#### Activate mruby-discount when build ngx_mruby
```ruby
  # use markdown on ngx_mruby
  conf.gem :git => 'git://github.com/matsumotory/mruby-discount.git'
```
#### nginx.conf
```nginx
location ~ \.md$ {
    mruby_output_filter /path/to/filter.rb cache;
}
```
#### /path/to/filter.rb
```ruby
f = Nginx::Filter.new

# setup markdown convert engine
css = "https://gist.github.com/andyferra/2554919/raw/2e66cabdafe1c9a7f354aa2ebf5bc38265e638e5/github.css"
title = "markdown"
md = Discount.new css, title

# convert markdown to html,
# and add output filter
f.body = md.md2html f.body
```
#### test.md
```markdown
# Section
## aaa

- hoge
- foo

## bbb

__code__

    a = 1
    b = a + 1

```
#### Access markdown file  
http://example.com/test.md image

***
![response](https://dl.dropboxusercontent.com/s/fkzsuv94tr541zg/md_test.png)
***

## File Based Access List
##### nginx.conf
```nginx
location / {
    mruby_access_handler /path/to/access_check.rb;
}
```
##### /path/to/access_check.rb
```ruby
r = Nginx::Request.new

filename = File.join r.var.document_root, ".access_list"
if File.exists? filename
  deny_list = Array.new
  File.open(filename) do |file|
    while line = file.gets
      deny_list << line.chomp
    end
  end
  if deny_list.include? r.var.remote_addr
    Nginx.errlogger Nginx::LOG_ERR, "ACL: FORBIDDEN Client Matched in #{filename}"
    Nginx.return Nginx::HTTP_FORBIDDEN
  else
    Nginx.errlogger Nginx::LOG_ERR, "ACL: OK Client Unmatched in #{filename}"
    Nginx.return Nginx::HTTP_OK
  end
else
  Nginx.return Nginx::HTTP_OK
end
```
##### /path/to/.access_list
```
192.168.12.9
192.168.12.10
```
##### Access to nginx(run with 192.168.12.9 listening 0.0.0.0:80)
```bash
$ curl http://127.0.0.1/
hello world

$ curl http://192.168.12.9/
<html>
<head><title>403 Forbidden</title></head>
<body bgcolor="white">
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.4.4</center>
</body>
</html>
```
##### error.log
```
2014/03/10 17:14:20 [error] 11376#0: *4 ACL: OK Client Unmatched in /usr/local/nginx-1.4.4/html/.access_list, client: 127.0.0.1, server: localhost, request: "GET / HTTP/1.1", host: "127.0.0.1"

2014/03/10 17:15:09 [error] 11376#0: *7 ACL: FORBIDDEN Client Matched in /usr/local/nginx-1.4.4/html/.access_list, client: 192.168.12.9, server: localhost, request: "GET / HTTP/1.1", host: "192.168.12.9"
```

## File Server like Dropbox Link
##### nginx.conf
```nginx
location /dropbox {
    mruby_rewrite_handler /path/to/dropbox.rb;
}
```
##### /path/to/dropbox.rb
```ruby
redis = Redis.new "127.0.0.1", 6379
reqst = Nginx::Request.new

file = redis.hget reqst.uri, "file"
expr = redis.hget reqst.uri, "expire"

Nginx.errlogger Nginx::LOG_ERR, "dropbox: uri=#{reqst.uri} file=#{file} expire=#{Time.at expr.to_i}"

redis.close

if expr.to_i >= Time.now.to_i
  Nginx.redirect file
else
  Nginx.return Nginx::DECLINED
end
```
##### Input data by redis-cli
```redis
HSET /dropbox/aaabbbcccddd file /files/hoge.html
HSET /dropbox/aaabbbcccddd expire 1400000000
```
##### /files/hoge.html
```html
hoge
```
##### access to http://127.0.0.1/dropbox/aaabbbcccddd
```curl
$ curl http://127.0.0.1/dropbox/aaabbbcccddd
hoge
```
##### error.log
```
2014/03/11 00:02:30 [error] 12245#0: *109 dropbox: uri=/dropbox/aaabbbcccddd file=/files/hoge.html expire=Wed May 14 01:53:20 2014, client: 127.0.0.1, server: localhost, request: "GET /dropbox/aaabbbcccddd HTTP/1.1", host: "127.0.0.1"
```

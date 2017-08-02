ngx_mruby test use mruby test.
ngx_mruby test is very earlier and experimental version. 

Welcome pull-request!
## Add test
##### Add location config to ``test/conf/nginx.conf``
```nginx
# Nginx.hello test
location /mruby {
    mruby_content_handler build/nginx/html/unified_hello.rb cache;
}
```
##### Add hook script into ``test/html/`` if you need the script for location config
```ruby
# test/htdocs/unified_hello.rb
if server_name == "NGINX"
  Server = Nginx
elsif server_name == "Apache"
  Server = Apache
end

Server::rputs "Hello #{Server::module_name}/#{Server::module_version} world!"
```
##### Add test code to ``test/t/ngx_mruby.rb``
```ruby
assert('ngx_mruby', 'location /mruby') do
  res = HttpRequest.new.get base + '/mruby'
  assert_equal 'Hello ngx_mruby/0.0.1 world!', res["body"]
end
```
## Testing
##### build nginx into ``./build/nginx`` and test on ``./build/nginx``
```
sh test.sh
```


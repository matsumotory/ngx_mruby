# Deny clients listed in a file

An access handler runs in nginx's access phase, before the content of the
location. A Ruby script there can end the request with a status, for
example 403, or let it go on by returning without a status
([`mruby_access_handler`](../directives/README.md#mruby_access_handler-and-mruby_access_handler_code)).

## The sample

The access handler reads the file that the variable `$deny_list` names and
answers 403 when the client's address is one of its lines. The location
`/listed/` names a list that holds `127.0.0.1`, the address of the test
client, so the request gets 403; `error_page 403 @denied` gives that 403
its body. The location `/open/` names a list without that address.

```sample
case: test/t/cases/guides.rb
conf: test/conf/conf.d/74-guide-access.conf
script: test/html/guide_access.rb
request: test/html/guide_access.request
response: test/html/guide_access.response
```

The case also sends `GET /open/report` and expects 200 with the body
`welcome`.

## What to keep in mind

- The script reads the list file for every request, which blocks the
  worker while the disk answers. To read it once per worker, load the list
  in `mruby_init_worker_code` into a constant, and reload nginx after a
  change of the file ([What a worker keeps between requests](../concepts/lifetimes.md#what-a-worker-keeps-between-requests)).
- `r.var.remote_addr` is the address of the TCP peer. Behind a load
  balancer, that is the load balancer, unless nginx's realip module sets
  it from a header that the load balancer sends.
- `Nginx.return Nginx::HTTP_FORBIDDEN` ends the request with 403. A script
  that returns without `Nginx.return` lets nginx go on with the next
  handler of the access phase and then the content.

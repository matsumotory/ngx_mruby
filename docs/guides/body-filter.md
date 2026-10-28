# Change a response body

A body filter runs while nginx sends a response, whichever handler or
upstream produced it. With
[`mruby_output_body_filter`](../directives/README.md#mruby_output_body_filter-mruby_output_body_filter_code-mruby_output_header_filter-and-mruby_output_header_filter_code),
a Ruby script reads the body through `Nginx::Filter#body` and replaces it
with `Nginx::Filter#body=`. A header filter
(`mruby_output_header_filter`) runs before it and can change the response
headers.

## The sample

The location sends a text file from disk. The header filter sets the
content type to `text/html`, and the body filter escapes `&`, `<` and `>`
and wraps the text in an HTML page.

```sample
case: test/t/cases/guides.rb
conf: test/conf/conf.d/76-guide-body-filter.conf
script: test/html/guide_body_filter.rb
request: test/html/guide_body_filter.request
response: test/html/guide_body_filter.response
```

## What to keep in mind

- The body filter reads a response of known length, such as a file from
  disk, as one buffer. nginx passes a response without `Content-Length`
  on without the filter reading it
  ([Nginx::Filter](../class_and_method/README.md#nginxfilter-class)).
- ngx_mruby sends the length of the new body in `Content-Length`.
- The use case "Output filter converting Markdown to HTML" of
  [Use cases](../use_case/README.md) converts Markdown in the same place,
  with the gem mruby-discount.

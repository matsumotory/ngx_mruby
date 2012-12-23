#ifndef NGX_HTTP_MRUBY_H
#define NGX_HTTP_MRUBY_H

#include <ngx_http.h>

ngx_int_t ngx_mrb_run_file(ngx_http_request_t *r, char *code_file);
ngx_int_t ngx_mrb_run_string(ngx_http_request_t *r, char *code);

#endif // NGX_HTTP_MRUBY_H

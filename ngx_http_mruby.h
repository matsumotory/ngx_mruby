#ifndef NGX_HTTP_MRUBY_H
#define NGX_HTTP_MRUBY_H

#include <ngx_http.h>

ngx_int_t ngx_mrb_run(ngx_http_request_t *r, char *code_file);

#endif // NGX_HTTP_MRUBY_H

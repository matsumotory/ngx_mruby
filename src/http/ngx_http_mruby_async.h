/*
// ngx_http_mruby_async.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_HTTP_MRUBY_ASYNC_H
#define NGX_HTTP_MRUBY_ASYNC_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <mruby.h>

#include "ngx_http_mruby_core.h"
#include "../common/ngx_mruby_fiber.h"

typedef struct ngx_http_mrb_fiber_s ngx_http_mrb_fiber_t;

/*
// Starts the code of a handler in a new fiber, and returns whether it waits,
// returned (its value in *result) or raised (the exception is logged, and
// mrb->exc is cleared). *record is the record of the run, or NULL when it
// raised before the fiber ran.
*/
ngx_mrb_fiber_outcome_t ngx_mrb_start_fiber(ngx_http_request_t *r, mrb_state *mrb, struct RProc *proc,
                                            mrb_value *result, ngx_http_mruby_handler_kind_t kind,
                                            ngx_http_mrb_fiber_t **record);

/*
// The second call of a handler that waits (section 4.4 of
// docs/proposals/core-stabilization.md). Returns NGX_DECLINED when no record
// of this handler waits, so the code starts; NGX_DONE when the record still
// waits, so the handler returns NGX_DONE again; NGX_ERROR when its request
// ended (CANCELLED); and NGX_OK when the record was READY and its fiber was
// resumed, with the outcome in *outcome and the record in *record.
*/
ngx_int_t ngx_http_mrb_fiber_call_again(ngx_http_request_t *r, ngx_http_mruby_ctx_t *ctx,
                                        ngx_http_mruby_handler_kind_t kind, mrb_value *result,
                                        ngx_http_mrb_fiber_t **record, ngx_mrb_fiber_outcome_t *outcome);

// The fiber of record yielded to the timer of Nginx::Async.sleep in a call of
// its handler from nginx: the handler returns NGX_DONE, and nginx calls it
// again when the timer fires.
void ngx_http_mrb_fiber_wait_on_nginx(ngx_http_request_t *r, ngx_http_mruby_ctx_t *ctx, ngx_http_mrb_fiber_t *record);

// The result that the code of the run set (Nginx.return, Nginx.send_header,
// Nginx.status_code=, Nginx.redirect with a URL): 1 and *result when it set
// one, 0 when it set none.
ngx_flag_t ngx_http_mrb_fiber_result(ngx_http_mrb_fiber_t *record, ngx_int_t *result);

// Stores the result of the handler whose fiber runs now for request r.
void ngx_http_mrb_fiber_set_result(ngx_http_request_t *r, ngx_int_t result);

/*
// Nginx.redirect with a local URI in a post_read, server rewrite, rewrite,
// access or content handler: the URI is kept in the record of the handler
// whose fiber runs now, and the internal redirect is made when the handler
// ends (Q2 of section 9 of docs/proposals/core-stabilization.md). Returns
// NGX_OK when it is kept, NGX_DECLINED when the handler that runs is of
// another kind (the redirect is made at once, as before), and NGX_ERROR
// when the allocation failed.
*/
ngx_int_t ngx_http_mrb_fiber_defer_redirect(ngx_http_request_t *r, ngx_str_t *uri);
// Output or a status after Nginx.redirect, which are not sent
void ngx_http_mrb_fiber_after_redirect(ngx_http_request_t *r);
// The URI of the redirect that the run of record keeps, or NULL; *after tells
// whether the code wrote output or set a status after the call
ngx_str_t *ngx_http_mrb_fiber_redirect(ngx_http_mrb_fiber_t *record, ngx_flag_t *after);

void ngx_mrb_async_class_init(mrb_state *mrb, struct RClass *class);

#endif // NGX_HTTP_MRUBY_ASYNC_H

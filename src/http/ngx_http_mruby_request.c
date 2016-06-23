/*
// ngx_http_mruby_request.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_request.h"

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/compile.h>
#include <mruby/data.h>
#include <mruby/proc.h>
#include <mruby/string.h>

#define NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_MEMBER_STR(method_suffix, member)                                      \
  static mrb_value ngx_mrb_get_##method_suffix(mrb_state *mrb, mrb_value self);                                        \
  static mrb_value ngx_mrb_get_##method_suffix(mrb_state *mrb, mrb_value self)                                         \
  {                                                                                                                    \
    ngx_http_request_t *r = ngx_mrb_get_request();                                                                     \
    return mrb_str_new(mrb, (const char *)member.data, member.len);                                                    \
  }

#define NGX_MRUBY_DEFINE_METHOD_NGX_SET_REQUEST_MEMBER_STR(method_suffix, member)                                      \
  static mrb_value ngx_mrb_set_##method_suffix(mrb_state *mrb, mrb_value self);                                        \
  static mrb_value ngx_mrb_set_##method_suffix(mrb_state *mrb, mrb_value self)                                         \
  {                                                                                                                    \
    mrb_value arg;                                                                                                     \
    size_t len;                                                                                                        \
    ngx_http_request_t *r = ngx_mrb_get_request();                                                                     \
    mrb_get_args(mrb, "o", &arg);                                                                                      \
    if (mrb_nil_p(arg)) {                                                                                              \
      return self;                                                                                                     \
    }                                                                                                                  \
    len = RSTRING_LEN(arg);                                                                                            \
    member.len = len;                                                                                                  \
    member.data = (u_char *)ngx_palloc(r->pool, len);                                                                  \
    ngx_memcpy(member.data, RSTRING_PTR(arg), len);                                                                    \
    return self;                                                                                                       \
  }

#define NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_HEADERS_HASH(direction)                                                \
  static mrb_value ngx_mrb_get_request_headers_##direction##_hash(mrb_state *mrb, mrb_value self);                     \
  static mrb_value ngx_mrb_get_request_headers_##direction##_hash(mrb_state *mrb, mrb_value self)                      \
  {                                                                                                                    \
    ngx_list_part_t *part;                                                                                             \
    ngx_table_elt_t *header;                                                                                           \
    ngx_http_request_t *r;                                                                                             \
    ngx_uint_t i;                                                                                                      \
    mrb_value hash;                                                                                                    \
    mrb_value key;                                                                                                     \
    mrb_value value;                                                                                                   \
    r = ngx_mrb_get_request();                                                                                         \
    hash = mrb_hash_new(mrb);                                                                                          \
    part = &(r->headers_##direction.headers.part);                                                                     \
    header = part->elts;                                                                                               \
    for (i = 0; /* void */; i++) {                                                                                     \
      if (i >= part->nelts) {                                                                                          \
        if (part->next == NULL) {                                                                                      \
          break;                                                                                                       \
        }                                                                                                              \
        part = part->next;                                                                                             \
        header = part->elts;                                                                                           \
        i = 0;                                                                                                         \
      }                                                                                                                \
      key = mrb_str_new(mrb, (const char *)header[i].key.data, header[i].key.len);                                     \
      value = mrb_str_new(mrb, (const char *)header[i].value.data, header[i].value.len);                               \
      mrb_hash_set(mrb, hash, key, value);                                                                             \
    }                                                                                                                  \
    return hash;                                                                                                       \
  }

ngx_http_request_t *ngx_mruby_request = NULL;

static mrb_value ngx_mrb_get_request_header(mrb_state *mrb, ngx_list_t *headers, char *mkey, mrb_int mlen);
static mrb_value ngx_mrb_get_request_headers_in(mrb_state *mrb, mrb_value self);
static mrb_value ngx_mrb_get_request_headers_out(mrb_state *mrb, mrb_value self);
static ngx_int_t ngx_mrb_set_request_header(mrb_state *mrb, ngx_list_t *headers, ngx_pool_t *pool, mrb_value k,
                                            mrb_value v, mrb_int update);
static mrb_value ngx_mrb_set_request_headers_in(mrb_state *mrb, mrb_value self);
static mrb_value ngx_mrb_set_request_headers_out(mrb_state *mrb, mrb_value self);
static ngx_int_t ngx_mrb_del_request_header(mrb_state *mrb, ngx_list_t *headers, char *mkey, mrb_int mlen);

ngx_int_t ngx_mrb_push_request(ngx_http_request_t *r)
{
  ngx_mruby_request = r;
  return NGX_OK;
}

ngx_http_request_t *ngx_mrb_get_request(void)
{
  return ngx_mruby_request;
}

// request member getter
NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_MEMBER_STR(request_request_line, r->request_line);
NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_MEMBER_STR(request_uri, r->uri);
NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_MEMBER_STR(request_unparsed_uri, r->unparsed_uri);
NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_MEMBER_STR(request_method, r->method_name);
NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_MEMBER_STR(request_protocol, r->http_protocol);
NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_MEMBER_STR(request_args, r->args);

// request member setter
NGX_MRUBY_DEFINE_METHOD_NGX_SET_REQUEST_MEMBER_STR(request_request_line, r->request_line);
NGX_MRUBY_DEFINE_METHOD_NGX_SET_REQUEST_MEMBER_STR(request_uri, r->uri);
NGX_MRUBY_DEFINE_METHOD_NGX_SET_REQUEST_MEMBER_STR(request_unparsed_uri, r->unparsed_uri);
NGX_MRUBY_DEFINE_METHOD_NGX_SET_REQUEST_MEMBER_STR(request_method, r->method_name);
NGX_MRUBY_DEFINE_METHOD_NGX_SET_REQUEST_MEMBER_STR(request_protocol, r->http_protocol);
NGX_MRUBY_DEFINE_METHOD_NGX_SET_REQUEST_MEMBER_STR(request_args, r->args);

NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_HEADERS_HASH(in);
NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_HEADERS_HASH(out);

// TODO:this declation should be moved to headers_(in|out)
NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_MEMBER_STR(content_type, r->headers_out.content_type);
NGX_MRUBY_DEFINE_METHOD_NGX_SET_REQUEST_MEMBER_STR(content_type, r->headers_out.content_type);

static void read_request_body_cb(ngx_http_request_t *r)
{
  ngx_chain_t *cl;
  size_t len;
  u_char *p;
  u_char *buf;
  ngx_http_mruby_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);

  if (r->request_body == NULL || r->request_body->bufs == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "This pahse don't have request_body");
    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    return;
  }

  cl = r->request_body->bufs;

  if (cl->next == NULL) {
    len = cl->buf->last - cl->buf->pos;
    if (len == 0) {
      return;
    }

    ctx->request_body_ctx.data = cl->buf->pos;
    ctx->request_body_ctx.len = len;
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "request_body(%d): %V", len, &ctx->request_body_ctx);
    if (ctx->request_body_more) {
      ctx->request_body_more = 0;
      ngx_http_core_run_phases(r);
    } else {
      ngx_http_finalize_request(r, NGX_DONE);
    }
    return;
  }

  len = 0;

  for (; cl; cl = cl->next) {
    len += cl->buf->last - cl->buf->pos;
  }

  if (len == 0) {
    return;
  }

  buf = ngx_palloc(r->pool, len);

  p = buf;
  for (cl = r->request_body->bufs; cl; cl = cl->next) {
    p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
  }

  ctx->request_body_ctx.data = buf;
  ctx->request_body_ctx.len = len;
  ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "multi request_body(%d): %V", len, &ctx->request_body_ctx);
  if (ctx->request_body_more) {
    ctx->request_body_more = 0;
    ngx_http_core_run_phases(r);
  } else {
    ngx_http_finalize_request(r, NGX_DONE);
  }
  return;
}

static mrb_value ngx_mrb_read_request_body(mrb_state *mrb, mrb_value self)
{
  ngx_http_request_t *r = ngx_mrb_get_request();
  ngx_int_t rc;
  ngx_http_mruby_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);

  if (r->method != NGX_HTTP_POST && r->method != NGX_HTTP_PUT) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_mrb_read_request_body can't read"
                                    " when r->method is neither POST nor PUT");
  }

  rc = ngx_http_read_client_request_body(r, read_request_body_cb);
  if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "ngx_http_read_client_request_body failed");
  }
  if (rc == NGX_AGAIN) {
    ctx->request_body_more = 1;
  }

  return mrb_fixnum_value(rc);
}

static mrb_value ngx_mrb_get_request_body(mrb_state *mrb, mrb_value self)
{
  ngx_http_request_t *r = ngx_mrb_get_request();
  ngx_http_mruby_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);

  if (ctx->request_body_ctx.len != 0) {
    return mrb_str_new(mrb, (const char *)ctx->request_body_ctx.data, ctx->request_body_ctx.len);
  } else {
    return mrb_nil_value();
  }
}

static mrb_value ngx_mrb_get_request_header(mrb_state *mrb, ngx_list_t *headers, char *mkey, mrb_int mlen)
{
  u_char *key;
  size_t key_len;
  ngx_uint_t i;
  ngx_list_part_t *part;
  ngx_table_elt_t *header;
  ngx_http_request_t *r = ngx_mrb_get_request();
  mrb_value ary = mrb_ary_new(mrb);

  key_len = (size_t)mlen;
  key = ngx_pnalloc(r->pool, key_len);
  ngx_memcpy(key, (u_char *)mkey, key_len);
  part = &headers->part;
  header = part->elts;

  /* TODO:optimize later(linear-search is slow) */
  for (i = 0; /* void */; i++) {
    if (i >= part->nelts) {
      if (part->next == NULL) {
        break;
      }
      part = part->next;
      header = part->elts;
      i = 0;
    }

    if (ngx_strncasecmp(header[i].key.data, key, key_len) == 0) {
      mrb_ary_push(mrb, ary, mrb_str_new(mrb, (const char *)header[i].value.data, header[i].value.len));
    }
  }

  switch (mrb_ary_ptr(ary)->len) {
  case 0:
    return mrb_nil_value();
  case 1:
    return mrb_funcall(mrb, ary, "first", 0);
  default:
    break;
  }

  return ary;
}

/* Inspired by h2o header lookup.  https://github.com/h2o/h2o */
/* Reference as nghttp2 header lookup.  https://github.com/tatsuhiro-t/nghttp2
 */
/* Reference as trusterd header lookup.  https://github.com/trusterd/mruby-http2
 */

static int memeq(const void *a, const void *b, size_t n)
{
  return memcmp(a, b, n) == 0;
}

#define streq(A, B, N) ((sizeof((A)) - 1) == (N) && memeq((A), (B), (N)))

typedef enum {
  NGX_MRUBY_BUILDIN_HEADER_SERVER,
  NGX_MRUBY_BUILDIN_HEADER_DATE,
} ngx_mruby_header_token;

static int ngx_mruby_builtin_header_lookup_token(u_char *name, size_t namelen)
{
  // TODO: Add other built-in headers
  switch (namelen) {
  case 4:
    switch (name[namelen - 1]) {
    case 'e':
      if (streq("Dat", name, 3)) {
        return NGX_MRUBY_BUILDIN_HEADER_DATE;
      }
      break;
    }
    break;
  case 6:
    switch (name[namelen - 1]) {
    case 'r':
      if (streq("Serve", name, 5)) {
        return NGX_MRUBY_BUILDIN_HEADER_SERVER;
      }
      break;
    }
    break;
  }
  return -1;
}

static ngx_int_t ngx_mrb_set_request_header(mrb_state *mrb, ngx_list_t *headers, ngx_pool_t *pool, mrb_value mrb_key,
                                            mrb_value mrb_val, mrb_int update)
{
  u_char *key, *val;
  size_t key_len, val_len;
  ngx_table_elt_t *new_header;
  ngx_http_request_t *r = ngx_mrb_get_request();

  key_len = (size_t)RSTRING_LEN(mrb_key);
  val_len = (size_t)RSTRING_LEN(mrb_val);

  key = ngx_pnalloc(pool, key_len);
  if (key == NULL) {
    return NGX_ERROR;
  }
  val = ngx_pnalloc(pool, val_len);
  if (val == NULL) {
    return NGX_ERROR;
  }

  ngx_memcpy(key, (u_char *)RSTRING_PTR(mrb_key), key_len);
  ngx_memcpy(val, (u_char *)RSTRING_PTR(mrb_val), val_len);

  switch (ngx_mruby_builtin_header_lookup_token(key, key_len)) {
  case NGX_MRUBY_BUILDIN_HEADER_SERVER:
    r->headers_out.server = ngx_pnalloc(r->pool, sizeof(ngx_table_elt_t));
    if (r->headers_out.server == NULL) {
      return NGX_ERROR;
    }
    r->headers_out.server->hash = 1;
    r->headers_out.server->key.data = key;
    r->headers_out.server->key.len = key_len;
    r->headers_out.server->value.data = val;
    r->headers_out.server->value.len = val_len;
    break;

  // TODO: Add other built-in headers

  default:
    break;
  }

  /* TODO:optimize later(linear-search is slow) */
  if (update) {
    while (!mrb_nil_p(ngx_mrb_get_request_header(mrb, headers, (char *)key, key_len))) {
      ngx_mrb_del_request_header(mrb, headers, (char *)key, key_len);
    }
  }

  new_header = ngx_list_push(headers);
  if (new_header == NULL) {
    return NGX_ERROR;
  }
  new_header->hash = 1;
  new_header->key.data = key;
  new_header->key.len = key_len;
  new_header->value.data = val;
  new_header->value.len = val_len;

  return NGX_OK;
}

static ngx_int_t ngx_mrb_del_request_header(mrb_state *mrb, ngx_list_t *headers, char *mkey, mrb_int mlen)
{
  u_char *key;
  size_t key_len;
  ngx_uint_t i;
  ngx_list_part_t *part, *new;
  ngx_table_elt_t *header;
  ngx_http_request_t *r = ngx_mrb_get_request();

  key_len = (size_t)mlen;
  key = ngx_pnalloc(r->pool, key_len);
  ngx_memcpy(key, (u_char *)mkey, key_len);

  part = &headers->part;
  header = part->elts;

  for (i = 0; /* void */; i++) {
    if (i >= part->nelts) {
      if (part->next == NULL) {
        break;
      }
      part = part->next;
      header = part->elts;
      i = 0;
    }

    if (ngx_strncasecmp(header[i].key.data, key, key_len) == 0) {
      if (i == 0) {
        // part->elts now points to the next element in the current part
        part->elts = (char *)part->elts + headers->size;
        // Decrement the amount of elements in the current part
        part->nelts--;

        // If this part doesn't have any more elements
        if (part->nelts == 0) {
          // Try to find the previous part
          new = &headers->part;

          // If our part is the first part
          if (new == part) {
            // If we don't have a next part
            if (part->next == NULL) {
              // Our element pointer is not valid, point it back where
              // it is valid again
              part->elts = (char *)part->elts - headers->size;
            } else {
              // The new first part is the next part
              headers->part = *(part->next);
            }

            return NGX_OK;
          }

          // Find the previous part by iterating the linked list until
          // we find our part or exit
          while (new->next != part) {
            if (new->next == NULL) {
              return NGX_ERROR;
            }
            new = new->next;
          }

          // If our part is the last part
          if (headers->last == part) {
            // Set the last part to be the previous part
            headers->last = new;
          }

          // Remove our part from the list
          new->next = part->next;
        }

        return NGX_OK;

      } else if (i == part->nelts - 1) {
        // The last element in the part

        // Decrement the element count;
        part->nelts--;
        // If this is the last part in the headers list
        if (part == headers->last) {
          // Decrement the header element count
          headers->nalloc--;
        }

        return NGX_OK;
      }

      // Allocate some memory for our new part
      new = ngx_palloc(r->pool, sizeof(ngx_list_part_t));
      if (new == NULL) {
        return NGX_ERROR;
      }

      // Insert a new part that contains everything after
      // the header we want to get rid of
      new->elts = &header[i + 1];
      new->nelts = part->nelts - i - 1;

      // Link the new part to the next part
      new->next = part->next;

      // The previous part only contains elements before the
      // removed header
      part->nelts = i;

      // The next part to the previous part is the new part
      part->next = new;

      // If the previous part was the last one
      if (part == headers->last) {
        // Update the header list with the last part to be
        // the new part
        headers->last = new;

        return NGX_OK;
      }
      return NGX_OK;
    }
  }

  return NGX_OK;
}

static mrb_value ngx_mrb_get_request_headers_in(mrb_state *mrb, mrb_value self)
{
  char *mkey;
  mrb_int mlen;
  ngx_http_request_t *r;
  r = ngx_mrb_get_request();

  mrb_get_args(mrb, "s", &mkey, &mlen);
  return ngx_mrb_get_request_header(mrb, &r->headers_in.headers, mkey, mlen);
}

static mrb_value ngx_mrb_get_request_headers_out(mrb_state *mrb, mrb_value self)
{
  char *mkey;
  mrb_int mlen;
  ngx_http_request_t *r;
  r = ngx_mrb_get_request();

  mrb_get_args(mrb, "s", &mkey, &mlen);
  return ngx_mrb_get_request_header(mrb, &r->headers_out.headers, mkey, mlen);
}

static mrb_value ngx_mrb_set_request_headers_in(mrb_state *mrb, mrb_value self)
{
  ngx_http_request_t *r;
  mrb_value key, val;
  r = ngx_mrb_get_request();

  mrb_get_args(mrb, "oo", &key, &val);

  if (mrb_type(val) == MRB_TT_ARRAY) {
    mrb_value v;
    mrb_int len, i;
    while (!mrb_nil_p(
        ngx_mrb_get_request_header(mrb, &r->headers_in.headers, (char *)RSTRING_PTR(key), RSTRING_LEN(key)))) {
      ngx_mrb_del_request_header(mrb, &r->headers_in.headers, (char *)RSTRING_PTR(key), RSTRING_LEN(key));
    }
    len = RARRAY_LEN(val);
    for (i = 0; i < len; ++i) {
      v = mrb_ary_ref(mrb, val, i);
      ngx_mrb_set_request_header(mrb, &r->headers_in.headers, r->pool, key, v, 0);
    }
  } else {
    ngx_mrb_set_request_header(mrb, &r->headers_in.headers, r->pool, key, val, 1);
  }
  return self;
}

static mrb_value ngx_mrb_set_request_headers_out(mrb_state *mrb, mrb_value self)
{
  ngx_http_request_t *r;
  mrb_value key, val;
  r = ngx_mrb_get_request();

  mrb_get_args(mrb, "oo", &key, &val);

  if (mrb_type(val) == MRB_TT_ARRAY) {
    mrb_value v;
    mrb_int len, i;
    while (!mrb_nil_p(
        ngx_mrb_get_request_header(mrb, &r->headers_out.headers, (char *)RSTRING_PTR(key), RSTRING_LEN(key)))) {
      ngx_mrb_del_request_header(mrb, &r->headers_out.headers, (char *)RSTRING_PTR(key), RSTRING_LEN(key));
    }
    len = RARRAY_LEN(val);
    for (i = 0; i < len; ++i) {
      v = mrb_ary_ref(mrb, val, i);
      ngx_mrb_set_request_header(mrb, &r->headers_out.headers, r->pool, key, v, 0);
    }
  } else {
    ngx_mrb_set_request_header(mrb, &r->headers_out.headers, r->pool, key, val, 1);
  }
  return self;
}

static mrb_value ngx_mrb_del_request_headers_in(mrb_state *mrb, mrb_value self)
{
  char *mkey;
  mrb_int mlen;
  ngx_http_request_t *r;
  r = ngx_mrb_get_request();

  mrb_get_args(mrb, "s", &mkey, &mlen);
  ngx_mrb_del_request_header(mrb, &r->headers_in.headers, mkey, mlen);
  return self;
}

static mrb_value ngx_mrb_del_request_headers_out(mrb_state *mrb, mrb_value self)
{
  char *mkey;
  mrb_int mlen;
  ngx_http_request_t *r;
  r = ngx_mrb_get_request();

  mrb_get_args(mrb, "s", &mkey, &mlen);
  ngx_mrb_del_request_header(mrb, &r->headers_out.headers, mkey, mlen);
  return self;
}

// using from ngx_http_mruby_connection.c and ngx_http_mruby_server.c
mrb_value ngx_mrb_get_request_var(mrb_state *mrb, mrb_value self)
{
  const char *iv_var_str = "@iv_var";
  mrb_value iv_var;
  struct RClass *class_var, *ngx_class;

  iv_var = mrb_iv_get(mrb, self, mrb_intern_cstr(mrb, iv_var_str));
  if (mrb_nil_p(iv_var)) {
    // get class from Nginx::Var
    ngx_class = mrb_class_get(mrb, "Nginx");
    class_var =
        (struct RClass *)mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(ngx_class), mrb_intern_cstr(mrb, "Var")));
    // initialize a Var instance
    iv_var = mrb_class_new_instance(mrb, 0, 0, class_var);
    // save Var, avoid multi initialize
    mrb_iv_set(mrb, self, mrb_intern_cstr(mrb, iv_var_str), iv_var);
  }

  return iv_var;
}

static mrb_value ngx_mrb_get_request_var_hostname(mrb_state *mrb, mrb_value self)
{
  mrb_value v = ngx_mrb_get_request_var(mrb, self);
  return mrb_funcall(mrb, v, "host", 0, NULL);
}

static mrb_value ngx_mrb_get_request_var_authority(mrb_state *mrb, mrb_value self)
{
  mrb_value v = ngx_mrb_get_request_var(mrb, self);
  return mrb_funcall(mrb, v, "http_host", 0, NULL);
}

static mrb_value ngx_mrb_get_request_var_filename(mrb_state *mrb, mrb_value self)
{
  mrb_value v = ngx_mrb_get_request_var(mrb, self);
  return mrb_funcall(mrb, v, "request_filename", 0, NULL);
}

static mrb_value ngx_mrb_get_request_var_user(mrb_state *mrb, mrb_value self)
{
  mrb_value v = ngx_mrb_get_request_var(mrb, self);
  return mrb_funcall(mrb, v, "remote_user", 0, NULL);
}

// TODO: combine ngx_mrb_get_request_var
static mrb_value ngx_mrb_get_class_obj(mrb_state *mrb, mrb_value self, char *obj_id, char *class_name)
{
  mrb_value obj;
  struct RClass *obj_class, *ngx_class;

  obj = mrb_iv_get(mrb, self, mrb_intern_cstr(mrb, obj_id));
  if (mrb_nil_p(obj)) {
    ngx_class = mrb_class_get(mrb, "Nginx");
    obj_class =
        (struct RClass *)mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(ngx_class), mrb_intern_cstr(mrb, class_name)));
    obj = mrb_obj_new(mrb, obj_class, 0, NULL);
    mrb_iv_set(mrb, self, mrb_intern_cstr(mrb, obj_id), obj);
  }
  return obj;
}

static mrb_value ngx_mrb_headers_in_obj(mrb_state *mrb, mrb_value self)
{
  return ngx_mrb_get_class_obj(mrb, self, "headers_in_obj", "Headers_in");
}

static mrb_value ngx_mrb_headers_out_obj(mrb_state *mrb, mrb_value self)
{
  return ngx_mrb_get_class_obj(mrb, self, "headers_out_obj", "Headers_out");
}

static mrb_value ngx_mrb_sub_request_check(mrb_state *mrb, mrb_value str)
{
  ngx_http_request_t *r = ngx_mrb_get_request();
  return (r != r->main) ? mrb_true_value() : mrb_false_value();
}

void ngx_mrb_request_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_request;
  struct RClass *class_headers_in;
  struct RClass *class_headers_out;

  class_request = mrb_define_class_under(mrb, class, "Request", mrb->object_class);
  mrb_define_method(mrb, class_request, "get_body", ngx_mrb_get_request_body, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_request, "read_body", ngx_mrb_read_request_body, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_request, "content_type=", ngx_mrb_set_content_type, MRB_ARGS_ANY());
  mrb_define_method(mrb, class_request, "content_type", ngx_mrb_get_content_type, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_request, "request_line", ngx_mrb_get_request_request_line, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_request, "request_line=", ngx_mrb_set_request_request_line, MRB_ARGS_ANY());
  mrb_define_method(mrb, class_request, "uri", ngx_mrb_get_request_uri, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_request, "uri=", ngx_mrb_set_request_uri, MRB_ARGS_ANY());
  mrb_define_method(mrb, class_request, "unparsed_uri", ngx_mrb_get_request_unparsed_uri, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_request, "unparsed_uri=", ngx_mrb_set_request_unparsed_uri, MRB_ARGS_ANY());
  mrb_define_method(mrb, class_request, "method", ngx_mrb_get_request_method, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_request, "method=", ngx_mrb_set_request_method, MRB_ARGS_ANY());
  mrb_define_method(mrb, class_request, "protocol", ngx_mrb_get_request_protocol, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_request, "protocol=", ngx_mrb_set_request_protocol, MRB_ARGS_ANY());
  mrb_define_method(mrb, class_request, "args", ngx_mrb_get_request_args, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_request, "args=", ngx_mrb_set_request_args, MRB_ARGS_ANY());
  mrb_define_method(mrb, class_request, "var", ngx_mrb_get_request_var, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_request, "headers_in", ngx_mrb_headers_in_obj, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_request, "headers_out", ngx_mrb_headers_out_obj, MRB_ARGS_NONE());

  mrb_define_method(mrb, class_request, "sub_request?", ngx_mrb_sub_request_check, MRB_ARGS_NONE());

  mrb_define_method(mrb, class_request, "hostname", ngx_mrb_get_request_var_hostname, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_request, "authority", ngx_mrb_get_request_var_authority, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_request, "filename", ngx_mrb_get_request_var_filename, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_request, "user", ngx_mrb_get_request_var_user, MRB_ARGS_NONE());

  class_headers_in = mrb_define_class_under(mrb, class, "Headers_in", mrb->object_class);
  mrb_define_method(mrb, class_headers_in, "[]", ngx_mrb_get_request_headers_in, MRB_ARGS_ANY());
  mrb_define_method(mrb, class_headers_in, "[]=", ngx_mrb_set_request_headers_in, MRB_ARGS_ANY());
  mrb_define_method(mrb, class_headers_in, "delete", ngx_mrb_del_request_headers_in, MRB_ARGS_ANY());
  mrb_define_method(mrb, class_headers_in, "all", ngx_mrb_get_request_headers_in_hash, MRB_ARGS_ANY());

  class_headers_out = mrb_define_class_under(mrb, class, "Headers_out", mrb->object_class);
  mrb_define_method(mrb, class_headers_out, "[]", ngx_mrb_get_request_headers_out, MRB_ARGS_ANY());
  mrb_define_method(mrb, class_headers_out, "[]=", ngx_mrb_set_request_headers_out, MRB_ARGS_ANY());
  mrb_define_method(mrb, class_headers_out, "delete", ngx_mrb_del_request_headers_out, MRB_ARGS_ANY());
  mrb_define_method(mrb, class_headers_out, "all", ngx_mrb_get_request_headers_out_hash, MRB_ARGS_ANY());
}

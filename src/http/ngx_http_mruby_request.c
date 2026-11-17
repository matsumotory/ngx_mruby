/*
// ngx_http_mruby_request.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_request.h"

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/hash.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#define NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_MEMBER_STR(method_suffix, member)                                      \
  static mrb_value ngx_mrb_get_##method_suffix(mrb_state *mrb, mrb_value self);                                        \
  static mrb_value ngx_mrb_get_##method_suffix(mrb_state *mrb, mrb_value self)                                         \
  {                                                                                                                    \
    ngx_http_request_t *r = ngx_mrb_get_request_or_raise(mrb);                                                         \
    return mrb_str_new(mrb, (const char *)member.data, member.len);                                                    \
  }

#define NGX_MRUBY_DEFINE_METHOD_NGX_SET_REQUEST_MEMBER_STR(method_suffix, member)                                      \
  static mrb_value ngx_mrb_set_##method_suffix(mrb_state *mrb, mrb_value self);                                        \
  static mrb_value ngx_mrb_set_##method_suffix(mrb_state *mrb, mrb_value self)                                         \
  {                                                                                                                    \
    mrb_value arg;                                                                                                     \
    size_t len;                                                                                                        \
    ngx_http_request_t *r = ngx_mrb_get_request_or_raise(mrb);                                                         \
    mrb_get_args(mrb, "o", &arg);                                                                                      \
    if (mrb_nil_p(arg)) {                                                                                              \
      return self;                                                                                                     \
    }                                                                                                                  \
    arg = mrb_ensure_string_type(mrb, arg);                                                                            \
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
    r = ngx_mrb_get_request_or_raise(mrb);                                                                             \
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

/*
 * The current request is set only while mruby code runs for that request
 * (see ngx_mrb_run() and the Async resume path). Request-scoped methods called
 * from other contexts, such as mruby_init_worker, mruby_exit_worker or
 * mruby_ssl_handshake_handler, raise instead of touching another request.
 */
ngx_http_request_t *ngx_mrb_get_request_or_raise(mrb_state *mrb)
{
  if (ngx_mruby_request == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "this method can only be used while processing a request");
  }
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

static mrb_value ngx_mrb_get_request_body(mrb_state *mrb, mrb_value self)
{
  mrb_value v = ngx_mrb_get_request_var(mrb, self);
  ngx_http_request_t *r = ngx_mrb_get_request_or_raise(mrb);

  if (r->method != NGX_HTTP_POST && r->method != NGX_HTTP_PUT) {
    mrb_raise(mrb, E_RUNTIME_ERROR,
              "ngx_mrb_read_request_body can't read"
              " when r->method is neither POST nor PUT");
  }

  return mrb_funcall(mrb, v, "request_body", 0, NULL);
}

static mrb_value ngx_mrb_get_request_header(mrb_state *mrb, ngx_list_t *headers, char *mkey, mrb_int mlen)
{
  u_char *key;
  size_t key_len;
  ngx_uint_t i;
  ngx_list_part_t *part;
  ngx_table_elt_t *header;
  ngx_http_request_t *r = ngx_mrb_get_request_or_raise(mrb);
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

    if (header[i].key.len == key_len &&
      ngx_strncasecmp(header[i].key.data, key, key_len) == 0) {
      mrb_ary_push(mrb, ary, mrb_str_new(mrb, (const char *)header[i].value.data, header[i].value.len));
    }
  }

  switch (RARRAY_LEN(ary)) {
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
  u_char *key, *val, *lowcase;
  size_t key_len, val_len;
  ngx_table_elt_t *new_header;
  ngx_http_request_t *r = ngx_mrb_get_request_or_raise(mrb);

  key_len = (size_t)RSTRING_LEN(mrb_key);
  key = ngx_pnalloc(pool, key_len);
  if (key == NULL) {
    return NGX_ERROR;
  }
  ngx_memcpy(key, (u_char *)RSTRING_PTR(mrb_key), key_len);

  /* TODO:optimize later(linear-search is slow) */
  if (update || mrb_nil_p(mrb_val)) {
    while (!mrb_nil_p(ngx_mrb_get_request_header(mrb, headers, (char *)key, key_len))) {
      ngx_mrb_del_request_header(mrb, headers, (char *)key, key_len);
    }
  }
  if (mrb_nil_p(mrb_val)) {
    /* If the value is nil, just remove the key from the headers. */
    return NGX_OK;
  }
  mrb_val = mrb_ensure_string_type(mrb, mrb_val);

  val_len = (size_t)RSTRING_LEN(mrb_val);
  val = ngx_pnalloc(pool, val_len);
  if (val == NULL) {
    return NGX_ERROR;
  }
  ngx_memcpy(val, (u_char *)RSTRING_PTR(mrb_val), val_len);

  switch (ngx_mruby_builtin_header_lookup_token(key, key_len)) {
  case NGX_MRUBY_BUILDIN_HEADER_SERVER:
    r->headers_out.server = ngx_pcalloc(r->pool, sizeof(ngx_table_elt_t));
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

  /* nginx's proxy and grpc modules pass the lowcase_key of every request
   * header to ngx_hash_find, so the added header has it, and next, set.
   * On the 2.x line a header that a script adds is not matched against the
   * names of the headers that those modules set (proxy_set_header and
   * their own ones): it is sent to the upstream next to them. lowcase_key
   * is therefore key_len zero bytes, which no name of a header matches,
   * and not the lowercase name. 3.0 sets the hash of the name and the
   * lowercase name instead, so that those modules match the header. */
  lowcase = ngx_pcalloc(pool, key_len);
  if (lowcase == NULL) {
    return NGX_ERROR;
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
  new_header->lowcase_key = lowcase;
#if (nginx_version >= 1023000)
  new_header->next = NULL;
#endif

  return NGX_OK;
}

static ngx_int_t ngx_mrb_del_request_header(mrb_state *mrb, ngx_list_t *headers, char *mkey, mrb_int mlen)
{
  u_char *key;
  size_t key_len;
  ngx_uint_t i;
  ngx_list_part_t *part, *prev, *new;
  ngx_table_elt_t *header;
  ngx_http_request_t *r = ngx_mrb_get_request_or_raise(mrb);

  key_len = (size_t)mlen;
  key = ngx_pnalloc(r->pool, key_len);
  if (key == NULL) {
    return NGX_ERROR;
  }
  ngx_memcpy(key, (u_char *)mkey, key_len);

  prev = NULL;
  part = &headers->part;
  header = part->elts;

  for (i = 0; /* void */; i++) {
    if (i >= part->nelts) {
      if (part->next == NULL) {
        break;
      }
      prev = part;
      part = part->next;
      header = part->elts;
      i = 0;
    }

    /* Compare the length before the bytes: neither the name to delete nor
     * the stored key is NUL-terminated, so ngx_strncasecmp alone could read
     * past a shorter key and could match a key that only shares its first
     * key_len bytes. */
    if (header[i].key.len != key_len || ngx_strncasecmp(header[i].key.data, key, key_len) != 0) {
      continue;
    }

    /* Remove element i without moving the other elements, so the pointers
     * nginx caches into this list stay valid: the ngx_table_elt_t * it keeps
     * for a well-known header (r->headers_in.user_agent and the like) and the
     * same-name "next" chains (for example Cookie or X-Forwarded-For). The
     * previous code split a full part and left headers->last pointing inside
     * its array, and the next ngx_list_push then wrote one element past the
     * end of that array. The list is only ever appended to with
     * ngx_list_push, which starts a new part once a part reaches
     * headers->nalloc, so keeping headers->nalloc at or below the free room
     * of the last part makes a later push allocate a new part instead of
     * writing past the last part's array. */
    if (i == 0) {
      /* Drop the first element by advancing the part's base; the rest keep
       * their addresses. */
      part->elts = (char *)part->elts + headers->size;
      part->nelts--;
      if (part->nelts != 0) {
        if (part == headers->last) {
          headers->nalloc--;
        }
      } else if (part != &headers->part) {
        /* A later part emptied: unlink it. */
        prev->next = part->next;
        if (headers->last == part) {
          headers->last = prev;
          headers->nalloc = prev->nelts;
        }
      } else if (part->next == NULL) {
        /* The embedded first part is the only part and is now empty; keep it
         * and restore its base. */
        part->elts = (char *)part->elts - headers->size;
      } else if (headers->last == part->next) {
        /* The first part empties and the next part is the last: adopt it. */
        headers->part = *(part->next);
        headers->last = &headers->part;
        headers->nalloc = headers->part.nelts;
      } else {
        headers->part = *(part->next);
      }
    } else if (i == part->nelts - 1) {
      /* Drop the last element of the part. */
      part->nelts--;
      if (part == headers->last) {
        headers->nalloc--;
      }
    } else {
      /* Split the part after i. The second part points into this part's
       * array, so no element moves. */
      new = ngx_palloc(r->pool, sizeof(ngx_list_part_t));
      if (new == NULL) {
        return NGX_ERROR;
      }
      new->elts = &header[i + 1];
      new->nelts = part->nelts - i - 1;
      new->next = part->next;
      part->nelts = i;
      part->next = new;
      if (part == headers->last) {
        headers->last = new;
        headers->nalloc = new->nelts;
      }
    }

    return NGX_OK;
  }

  return NGX_OK;
}

static mrb_value ngx_mrb_get_request_headers_in(mrb_state *mrb, mrb_value self)
{
  char *mkey;
  mrb_int mlen;
  ngx_http_request_t *r;
  r = ngx_mrb_get_request_or_raise(mrb);

  mrb_get_args(mrb, "s", &mkey, &mlen);
  return ngx_mrb_get_request_header(mrb, &r->headers_in.headers, mkey, mlen);
}

static mrb_value ngx_mrb_get_request_headers_out(mrb_state *mrb, mrb_value self)
{
  char *mkey;
  mrb_int mlen;
  ngx_http_request_t *r;
  r = ngx_mrb_get_request_or_raise(mrb);

  mrb_get_args(mrb, "s", &mkey, &mlen);
  return ngx_mrb_get_request_header(mrb, &r->headers_out.headers, mkey, mlen);
}

static mrb_value ngx_mrb_set_request_headers_in(mrb_state *mrb, mrb_value self)
{
  ngx_http_request_t *r;
  mrb_value key, val;
  r = ngx_mrb_get_request_or_raise(mrb);

  mrb_get_args(mrb, "oo", &key, &val);
  key = mrb_ensure_string_type(mrb, key);

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
  r = ngx_mrb_get_request_or_raise(mrb);

  mrb_get_args(mrb, "oo", &key, &val);
  key = mrb_ensure_string_type(mrb, key);

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
  r = ngx_mrb_get_request_or_raise(mrb);

  mrb_get_args(mrb, "s", &mkey, &mlen);
  ngx_mrb_del_request_header(mrb, &r->headers_in.headers, mkey, mlen);
  return self;
}

static mrb_value ngx_mrb_del_request_headers_out(mrb_state *mrb, mrb_value self)
{
  char *mkey;
  mrb_int mlen;
  ngx_http_request_t *r;
  r = ngx_mrb_get_request_or_raise(mrb);

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
  ngx_http_request_t *r = ngx_mrb_get_request_or_raise(mrb);
  return (r != r->main) ? mrb_true_value() : mrb_false_value();
}

void ngx_mrb_request_class_init(mrb_state *mrb, struct RClass *class)
{
  struct RClass *class_request;
  struct RClass *class_headers_in;
  struct RClass *class_headers_out;

  class_request = mrb_define_class_under(mrb, class, "Request", mrb->object_class);
  mrb_define_method(mrb, class_request, "get_body", ngx_mrb_get_request_body, MRB_ARGS_NONE());
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

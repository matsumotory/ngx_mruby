/*
// ngx_http_mruby_request.c - ngx_mruby mruby module
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#include "ngx_http_mruby_request.h"

#include "ngx_http_mruby_core.h"
#include "ngx_http_mruby_gc_roots.h"
#include "ngx_http_mruby_module.h"
#include "ngx_http_mruby_var.h"

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#define NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_MEMBER_STR(method_suffix, member)                                      \
  static mrb_value ngx_mrb_get_##method_suffix(mrb_state *mrb, mrb_value self);                                        \
  static mrb_value ngx_mrb_get_##method_suffix(mrb_state *mrb, mrb_value self)                                         \
  {                                                                                                                    \
    ngx_http_request_t *r = ngx_http_mrb_request(mrb, NGX_MRB_EXEC_HTTP_REQUEST, "Nginx::Request#");                   \
    return mrb_str_new(mrb, (const char *)member.data, member.len);                                                    \
  }

#define NGX_MRUBY_DEFINE_METHOD_NGX_SET_REQUEST_MEMBER_STR(method_suffix, member, lookup)                              \
  static mrb_value ngx_mrb_set_##method_suffix(mrb_state *mrb, mrb_value self);                                        \
  static mrb_value ngx_mrb_set_##method_suffix(mrb_state *mrb, mrb_value self)                                         \
  {                                                                                                                    \
    mrb_value arg;                                                                                                     \
    size_t len;                                                                                                        \
    ngx_http_request_t *r = lookup;                                                                                    \
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
    r = ngx_http_mrb_request(mrb, NGX_MRB_EXEC_HTTP_REQUEST, "Nginx::Headers_" #direction "#");                        \
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

/*
 * The methods find their request in the execution context
 * (src/common/ngx_mruby_exec.h), with the mask of the handlers where each
 * works (section 2.1 of docs/proposals/core-alpha1.md): reading the request
 * works in every handler and filter of the request; changing it in mruby_set
 * and the phase handlers; changing the head of the response in every handler
 * and filter but a log handler, before nginx has sent the response header.
 * Outside a request they raise "this method can only be used while processing
 * a request", as since 2.7.1.
 */
#define NGX_MRB_REQUEST_CHANGE(mrb) ngx_http_mrb_request((mrb), NGX_MRB_EXEC_HTTP_CHANGE_REQUEST, "Nginx::Request#")
#define NGX_MRB_REQUEST_ANY(mrb) ngx_http_mrb_request((mrb), NGX_MRB_EXEC_HTTP_REQUEST, "Nginx::Request#")

// request member getter
NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_MEMBER_STR(request_request_line, r->request_line);
NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_MEMBER_STR(request_uri, r->uri);
NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_MEMBER_STR(request_unparsed_uri, r->unparsed_uri);
NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_MEMBER_STR(request_method, r->method_name);
NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_MEMBER_STR(request_protocol, r->http_protocol);
NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_MEMBER_STR(request_args, r->args);

// request member setter
NGX_MRUBY_DEFINE_METHOD_NGX_SET_REQUEST_MEMBER_STR(request_request_line, r->request_line, NGX_MRB_REQUEST_CHANGE(mrb));
NGX_MRUBY_DEFINE_METHOD_NGX_SET_REQUEST_MEMBER_STR(request_uri, r->uri, NGX_MRB_REQUEST_CHANGE(mrb));
NGX_MRUBY_DEFINE_METHOD_NGX_SET_REQUEST_MEMBER_STR(request_unparsed_uri, r->unparsed_uri, NGX_MRB_REQUEST_ANY(mrb));
NGX_MRUBY_DEFINE_METHOD_NGX_SET_REQUEST_MEMBER_STR(request_method, r->method_name, NGX_MRB_REQUEST_CHANGE(mrb));
NGX_MRUBY_DEFINE_METHOD_NGX_SET_REQUEST_MEMBER_STR(request_protocol, r->http_protocol, NGX_MRB_REQUEST_ANY(mrb));
NGX_MRUBY_DEFINE_METHOD_NGX_SET_REQUEST_MEMBER_STR(request_args, r->args, NGX_MRB_REQUEST_CHANGE(mrb));

NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_HEADERS_HASH(in);
NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_HEADERS_HASH(out);

// TODO:this declation should be moved to headers_(in|out)
NGX_MRUBY_DEFINE_METHOD_NGX_GET_REQUEST_MEMBER_STR(content_type, r->headers_out.content_type);
NGX_MRUBY_DEFINE_METHOD_NGX_SET_REQUEST_MEMBER_STR(content_type, r->headers_out.content_type,
                                                   ngx_http_mrb_response_head(mrb, "Nginx::Request#"));

static mrb_value ngx_mrb_get_request_body(mrb_state *mrb, mrb_value self)
{
  ngx_http_request_t *r = NGX_MRB_REQUEST_ANY(mrb);

  if (r->method != NGX_HTTP_POST && r->method != NGX_HTTP_PUT) {
    mrb_raise(mrb, E_RUNTIME_ERROR,
              "ngx_mrb_read_request_body can't read"
              " when r->method is neither POST nor PUT");
  }

  return ngx_mrb_var_get_fixed(mrb, NGX_MRB_VAR_REQUEST_BODY);
}

/*
 * Nginx::Headers_in and Nginx::Headers_out (section 2.2 of
 * docs/proposals/core-alpha1.md).
 *
 * [], []= and delete find the headers whose name has the same length and the
 * same bytes in any case, and no other header. delete and []= remove every
 * such header. A name is a String or a Symbol. A value of []= is a String,
 * nil (delete), an Array (one header per element), or an object whose to_s
 * returns a String (ngx_mrb_var_to_string, as for Nginx::Var).
 *
 * Headers_out keeps Content-Type, Location, Date and Server where nginx
 * reads them: Content-Type in r->headers_out.content_type, without a list
 * entry; the others in a list entry that r->headers_out.location, .date or
 * .server points at, as nginx's own modules do. Content-Length stays a list
 * entry: Nginx.rputs adds the length of its output to content_length_n, so
 * the field is left to a later change (section 2.2 of the proposal).
 *
 * A header that []= adds has its lowcase_key (the lowercase name) and next
 * set, and a request header also the hash of its name, as nginx sets them
 * for the headers that it reads: nginx's proxy and grpc modules look every
 * request header up by hash and lowcase_key in the table of the headers
 * that they set themselves (proxy_set_header and their own ones), and so
 * leave out a header of such a name that a script added, as they leave out
 * the same header from a client. The 2.x line gives an added header the
 * hash 1 and a lowcase_key that matches no name, so that those modules do
 * not match it and send it next to their own (section 2.2 of the proposal
 * and the release notes of 3.0.0).
 */
typedef enum {
  NGX_MRB_HEADER_LIST = 0,
  NGX_MRB_HEADER_CONTENT_TYPE,
  NGX_MRB_HEADER_LOCATION,
  NGX_MRB_HEADER_DATE,
  NGX_MRB_HEADER_SERVER,
} ngx_mrb_header_field_t;

#define NGX_MRB_HEADER_NAME_IS(name, len, lit)                                                                         \
  ((len) == sizeof(lit) - 1 && ngx_strncasecmp((name), (u_char *)(lit), sizeof(lit) - 1) == 0)

/* Which field of r->headers_out holds the response header of this name. */
static ngx_mrb_header_field_t ngx_mrb_header_out_field(u_char *name, size_t len)
{
  switch (len) {
  case sizeof("Date") - 1:
    if (NGX_MRB_HEADER_NAME_IS(name, len, "Date")) {
      return NGX_MRB_HEADER_DATE;
    }
    break;
  case sizeof("Server") - 1:
    if (NGX_MRB_HEADER_NAME_IS(name, len, "Server")) {
      return NGX_MRB_HEADER_SERVER;
    }
    break;
  case sizeof("Location") - 1:
    if (NGX_MRB_HEADER_NAME_IS(name, len, "Location")) {
      return NGX_MRB_HEADER_LOCATION;
    }
    break;
  case sizeof("Content-Type") - 1:
    if (NGX_MRB_HEADER_NAME_IS(name, len, "Content-Type")) {
      return NGX_MRB_HEADER_CONTENT_TYPE;
    }
    break;
  }
  return NGX_MRB_HEADER_LIST;
}

/* The field that points at the list entry of Location, Date or Server. */
static ngx_table_elt_t **ngx_mrb_header_out_elt(ngx_http_request_t *r, ngx_mrb_header_field_t field)
{
  switch (field) {
  case NGX_MRB_HEADER_LOCATION:
    return &r->headers_out.location;
  case NGX_MRB_HEADER_DATE:
    return &r->headers_out.date;
  case NGX_MRB_HEADER_SERVER:
    return &r->headers_out.server;
  default:
    return NULL;
  }
}

/* The name of a header, a String or a Symbol, without a copy. */
static void ngx_mrb_header_name(mrb_state *mrb, mrb_value name, ngx_str_t *out)
{
  const char *p = NULL;
  mrb_int len = 0;

  if (mrb_symbol_p(name)) {
    p = mrb_sym_name_len(mrb, mrb_symbol(name), &len);
  } else if (mrb_string_p(name)) {
    p = RSTRING_PTR(name);
    len = RSTRING_LEN(name);
  } else {
    mrb_raisef(mrb, E_TYPE_ERROR, "%Y cannot be converted to String (a header name is a String or a Symbol)", name);
  }
  out->data = (u_char *)p;
  out->len = (size_t)len;
}

/*
 * A value of []= as a String copied into the pool. A value that is not a
 * String is converted with its to_s, and *ran tells the caller that Ruby code
 * ran; a to_s that fails raises its exception.
 */
static void ngx_mrb_header_value(mrb_state *mrb, ngx_pool_t *pool, mrb_value o, ngx_str_t *out, mrb_bool *ran)
{
  mrb_value s = o;

  if (!mrb_string_p(o)) {
    *ran = TRUE;
    if (!ngx_mrb_var_to_string(mrb, o, &s)) {
      mrb_exc_raise(mrb, s);
    }
  }
  out->len = (size_t)RSTRING_LEN(s);
  out->data = ngx_pnalloc(pool, out->len);
  if (out->data == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
  }
  ngx_memcpy(out->data, RSTRING_PTR(s), out->len);
}

/* The value of every header of the name: nil, a String, or an Array. */
static mrb_value ngx_mrb_header_list_get(mrb_state *mrb, ngx_list_t *headers, ngx_str_t *name)
{
  ngx_uint_t i, n;
  ngx_list_part_t *part;
  ngx_table_elt_t *header;
  mrb_value first, ary, v;

  first = mrb_nil_value();
  ary = mrb_nil_value();
  n = 0;
  part = &headers->part;
  header = part->elts;

  for (i = 0; /* void */; i++) {
    while (i >= part->nelts) {
      if (part->next == NULL) {
        return n > 1 ? ary : first;
      }
      part = part->next;
      header = part->elts;
      i = 0;
    }

    if (header[i].key.len != name->len || ngx_strncasecmp(header[i].key.data, name->data, name->len) != 0) {
      continue;
    }

    v = mrb_str_new(mrb, (const char *)header[i].value.data, header[i].value.len);
    if (n == 0) {
      first = v;
    } else {
      if (n == 1) {
        ary = mrb_ary_new(mrb);
        mrb_ary_push(mrb, ary, first);
      }
      mrb_ary_push(mrb, ary, v);
    }
    n++;
  }
}

/* Append a header to a request's header list without reusing a part that is
 * shared with another request. nginx shares a request's header list with its
 * subrequests: ngx_http_subrequest does sr->headers_in = r->headers_in, which
 * copies the ngx_list_t, so the embedded first part is a separate struct for
 * each request but the parts after it (reached through part->next) are the same
 * structs, while each request keeps its own last. Push into the embedded part
 * (each request's own) with ngx_list_push; for any later part, append a fresh
 * part at the true tail of the chain (another request may already have appended
 * one) and write the header there, so a push never lands in a part another
 * request may have changed, and no header that another request appended is
 * unchained. */
static void *ngx_mrb_push_request_header(ngx_list_t *l)
{
  ngx_list_part_t *last, *part;

  if (l->last == &l->part) {
    return ngx_list_push(l);
  }

  last = l->last;
  while (last->next != NULL) {
    last = last->next;
  }

  part = ngx_palloc(l->pool, sizeof(ngx_list_part_t));
  if (part == NULL) {
    return NULL;
  }
  part->elts = ngx_palloc(l->pool, l->nalloc * l->size);
  if (part->elts == NULL) {
    return NULL;
  }
  part->nelts = 1;
  part->next = NULL;

  last->next = part;
  l->last = part;

  return part->elts;
}

/* Give this request its own copies of the header-list parts after the embedded
 * first one, so a delete or an add here changes only this request's view, not
 * the parts it shares with a subrequest (or, for a subrequest, with its main
 * request). nginx makes a subrequest with sr->headers_in = r->headers_in, which
 * copies the embedded first part by value but leaves the parts after it (reached
 * through part->next, with headers->last) the same structs in both requests.
 * When one request deletes the first element of such a shared part,
 * ngx_mrb_header_list_remove advances the part's base and decrements its length
 * in the struct the other request still reads, so the other request would then
 * read and forward a list that no longer matches its own headers. Copying the
 * part structs (not their arrays) keeps the element addresses, and the pointers
 * nginx caches to them (r->headers_in.host and the like), unchanged. It runs
 * before every change to r->headers_in, not once: a subrequest made after an
 * earlier change (for example the background subrequest of the mirror directive,
 * made in the precontent phase after a rewrite-phase change and before a
 * content-phase one) shares the request's parts again, so copying before each
 * change leaves that subrequest's copy alone. The copy is cheap, only the part
 * structs after the embedded one, which a request of 20 headers or fewer does
 * not have. */
static ngx_int_t ngx_mrb_unshare_headers_in(ngx_http_request_t *r)
{
  ngx_list_t *l;
  ngx_list_part_t *orig, *prev, *copy;

  l = &r->headers_in.headers;
  prev = &l->part;
  orig = l->part.next;
  while (orig != NULL) {
    copy = ngx_palloc(l->pool, sizeof(ngx_list_part_t));
    if (copy == NULL) {
      return NGX_ERROR;
    }
    *copy = *orig;
    prev->next = copy;
    prev = copy;
    orig = copy->next;
  }
  /* headers->last is a pointer, so the subrequest copy (sr->headers_in =
   * r->headers_in) shares it with the main request: when the list is only the
   * embedded part, it points at the MAIN request's embedded part, and a push
   * here would add to the main request's list. Point it at this request's own
   * last part so an add changes only this request's list. */
  l->last = prev;
  return NGX_OK;
}

/*
 * Removes element i of part from the list; prev is the part before part, or
 * NULL for the first part.
 *
 * It does not move the other elements, so the pointers nginx caches into
 * this list stay valid: the ngx_table_elt_t * it keeps for a well-known
 * header (r->headers_in.user_agent and the like) and the same-name "next"
 * chains (for example Cookie or X-Forwarded-For). The list is only ever
 * appended to with ngx_list_push, which starts a new part once a part
 * reaches headers->nalloc, so keeping headers->nalloc at or below the free
 * room of the last part makes a later push allocate a new part instead of
 * writing past the last part's array. A part other than the first is never
 * left empty.
 */
static ngx_int_t ngx_mrb_header_list_remove(ngx_pool_t *pool, ngx_list_t *headers, ngx_list_part_t *part,
                                            ngx_list_part_t *prev, ngx_uint_t i)
{
  ngx_list_part_t *new;
  ngx_table_elt_t *header = part->elts;

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
    new = ngx_palloc(pool, sizeof(ngx_list_part_t));
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

/*
 * Removes every header of the name from the list, in one scan. A removal
 * moves no element, so the scan goes on with the element after the removed
 * one, wherever ngx_mrb_header_list_remove() left it:
 * - element 0 of the first part: the first part is the embedded
 *   headers->part, whose base advanced, which was restored when the list
 *   emptied, or which took the contents of the next part; the scan goes on
 *   at element 0 of headers->part;
 * - element 0 of a later part: the part's base advanced, and the scan goes
 *   on at its element 0; or the part emptied and was unlinked, and the scan
 *   goes on at element 0 of the part that followed it, after the same prev;
 * - the last element of a part: the part lost it, and the scan goes on with
 *   the next part;
 * - an element in the middle: the part now ends before it, and the new part
 *   after it starts with the next element, so the scan goes on there.
 */
static ngx_int_t ngx_mrb_header_list_delete(ngx_pool_t *pool, ngx_list_t *headers, ngx_str_t *name)
{
  ngx_uint_t i;
  ngx_list_part_t *part, *prev, *next;
  ngx_table_elt_t *header;

  prev = NULL;
  part = &headers->part;
  i = 0;

  for (;;) {
    while (i >= part->nelts) {
      if (part->next == NULL) {
        return NGX_OK;
      }
      prev = part;
      part = part->next;
      i = 0;
    }
    header = part->elts;

    /* Compare the length before the bytes: neither the name nor the stored
     * key is NUL-terminated, so ngx_strncasecmp alone could read past a
     * shorter key and could match a key that only shares its first bytes. */
    if (header[i].key.len != name->len || ngx_strncasecmp(header[i].key.data, name->data, name->len) != 0) {
      i++;
      continue;
    }

    next = part->next;
    if (ngx_mrb_header_list_remove(pool, headers, part, prev, i) != NGX_OK) {
      return NGX_ERROR;
    }

    if (i != 0) {
      /* the last or a middle element: the while above goes on with the next
       * part, which a split made the new part after the removed element */
      continue;
    }
    if (part == &headers->part) {
      continue;
    }
    if (part->nelts == 0) {
      /* the part was unlinked; prev stays the part before it */
      part = next;
      if (part == NULL) {
        return NGX_OK;
      }
    }
  }
}

/* Removes every header of the name, and for a response header that nginx
 * keeps in a field, clears that field as ngx_http_clear_location() and the
 * like do. */
static ngx_int_t ngx_mrb_headers_remove(ngx_http_request_t *r, ngx_list_t *headers, ngx_str_t *name,
                                        ngx_mrb_header_field_t field)
{
  ngx_table_elt_t **elt;

  /* Give this request its own copies of the shared header-list parts before any
   * change, so a change here does not reach a request it shares the list with
   * (a subrequest, or, for a subrequest, its main request). ngx_mrb_headers_set
   * removes before it adds and ngx_mrb_headers_delete removes, so both paths
   * reach this before they change headers_in. */
  if (headers == &r->headers_in.headers && ngx_mrb_unshare_headers_in(r) != NGX_OK) {
    return NGX_ERROR;
  }

  if (field == NGX_MRB_HEADER_CONTENT_TYPE) {
    ngx_str_null(&r->headers_out.content_type);
    r->headers_out.content_type_len = 0;
    r->headers_out.content_type_hash = 0;
    r->headers_out.content_type_lowcase = NULL;
    ngx_str_null(&r->headers_out.charset);
  } else if ((elt = ngx_mrb_header_out_elt(r, field)) != NULL && *elt != NULL) {
    (*elt)->hash = 0;
    *elt = NULL;
  }

  return ngx_mrb_header_list_delete(r->pool, headers, name);
}

/*
 * Sets nginx's type of the response, as ngx_http_upstream_copy_content_type()
 * does for the Content-Type of an upstream: content_type_len ends before a
 * "; charset=" parameter, whose value (without quotes) becomes the charset,
 * so that nginx's filters (gzip_types, charset_types, sub_filter_types and
 * the others) test the type without the parameter. Unlike nginx's function,
 * it stops at the end of the value, which is not NUL-terminated.
 */
static void ngx_mrb_header_set_content_type(ngx_http_request_t *r, ngx_str_t *value)
{
  u_char *p, *last, *end;

  r->headers_out.content_type = *value;
  r->headers_out.content_type_len = value->len;
  r->headers_out.content_type_hash = 0;
  r->headers_out.content_type_lowcase = NULL;
  ngx_str_null(&r->headers_out.charset);

  end = value->data + value->len;

  for (p = value->data; p < end; p++) {
    if (*p != ';') {
      continue;
    }

    last = p;

    do {
      p++;
    } while (p < end && *p == ' ');

    if (p == end) {
      return;
    }

    if (end - p < (ptrdiff_t)(sizeof("charset=") - 1) ||
        ngx_strncasecmp(p, (u_char *)"charset=", sizeof("charset=") - 1) != 0) {
      continue;
    }

    p += sizeof("charset=") - 1;

    r->headers_out.content_type_len = last - value->data;

    if (p < end && *p == '"') {
      p++;
    }

    last = end;

    if (last > p && *(last - 1) == '"') {
      last--;
    }

    r->headers_out.charset.len = last - p;
    r->headers_out.charset.data = p;

    return;
  }
}

/* The request whose headers the method reads or changes. */
static ngx_http_request_t *ngx_mrb_headers_request(mrb_state *mrb, ngx_uint_t out, ngx_uint_t change)
{
  if (!change) {
    return ngx_http_mrb_request(mrb, NGX_MRB_EXEC_HTTP_REQUEST, out ? "Nginx::Headers_out#" : "Nginx::Headers_in#");
  }
  if (out) {
    return ngx_http_mrb_response_head(mrb, "Nginx::Headers_out#");
  }
  return ngx_http_mrb_request(mrb, NGX_MRB_EXEC_HTTP_CHANGE_REQUEST, "Nginx::Headers_in#");
}

static mrb_value ngx_mrb_headers_get(mrb_state *mrb, ngx_uint_t out)
{
  ngx_http_request_t *r;
  ngx_table_elt_t **elt;
  ngx_mrb_header_field_t field;
  mrb_value name;
  ngx_str_t n;

  r = ngx_mrb_headers_request(mrb, out, 0);
  mrb_get_args(mrb, "o", &name);
  ngx_mrb_header_name(mrb, name, &n);

  if (!out) {
    return ngx_mrb_header_list_get(mrb, &r->headers_in.headers, &n);
  }

  field = ngx_mrb_header_out_field(n.data, n.len);
  if (field == NGX_MRB_HEADER_CONTENT_TYPE && r->headers_out.content_type.len) {
    return mrb_str_new(mrb, (const char *)r->headers_out.content_type.data, r->headers_out.content_type.len);
  }
  if ((elt = ngx_mrb_header_out_elt(r, field)) != NULL && *elt != NULL) {
    return mrb_str_new(mrb, (const char *)(*elt)->value.data, (*elt)->value.len);
  }
  return ngx_mrb_header_list_get(mrb, &r->headers_out.headers, &n);
}

static mrb_value ngx_mrb_headers_set(mrb_state *mrb, mrb_value self, ngx_uint_t out)
{
  ngx_http_request_t *r;
  ngx_list_t *headers;
  ngx_table_elt_t *h, **elt;
  ngx_mrb_header_field_t field;
  ngx_array_t *values;
  ngx_str_t n, key, *v;
  ngx_uint_t i, hash;
  u_char *lowcase;
  mrb_value name, val;
  mrb_int k;
  mrb_bool ran;

  r = ngx_mrb_headers_request(mrb, out, 1);
  mrb_get_args(mrb, "oo", &name, &val);
  ngx_mrb_header_name(mrb, name, &n);

  /* Copy the name before a to_s of a value runs, which could change the
   * String of the name. */
  key.len = n.len;
  key.data = ngx_pnalloc(r->pool, n.len);
  lowcase = ngx_pnalloc(r->pool, n.len);
  if (key.data == NULL || lowcase == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
  }
  ngx_memcpy(key.data, n.data, n.len);
  hash = ngx_hash_strlow(lowcase, key.data, key.len);

  /* Convert every value before the headers change, so that a to_s that
   * raises leaves them as they were. */
  ran = FALSE;
  values = ngx_array_create(r->pool, mrb_array_p(val) && RARRAY_LEN(val) > 0 ? (ngx_uint_t)RARRAY_LEN(val) : 1,
                            sizeof(ngx_str_t));
  if (values == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
  }
  if (mrb_array_p(val)) {
    /* RARRAY_LEN is read on each turn: a to_s can change the Array. */
    for (k = 0; k < RARRAY_LEN(val); k++) {
      v = ngx_array_push(values);
      if (v == NULL) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
      }
      ngx_mrb_header_value(mrb, r->pool, mrb_ary_ref(mrb, val, k), v, &ran);
    }
  } else if (!mrb_nil_p(val)) {
    v = ngx_array_push(values);
    if (v == NULL) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
    }
    ngx_mrb_header_value(mrb, r->pool, val, v, &ran);
  }
  if (ran) {
    /* A to_s ran Ruby code: check again that the headers can change. */
    r = ngx_mrb_headers_request(mrb, out, 1);
  }

  if (out) {
    headers = &r->headers_out.headers;
    field = ngx_mrb_header_out_field(key.data, key.len);
    /* nginx sends the response headers whose hash is not 0, and marks the
     * ones that it adds itself with 1 */
    hash = 1;
  } else {
    headers = &r->headers_in.headers;
    field = NGX_MRB_HEADER_LIST;
  }

  if (ngx_mrb_headers_remove(r, headers, &key, field) != NGX_OK) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
  }

  v = values->elts;
  for (i = 0; i < values->nelts; i++) {
    if (field == NGX_MRB_HEADER_CONTENT_TYPE) {
      /* nginx's field, without a list entry; the last value wins */
      ngx_mrb_header_set_content_type(r, &v[i]);
      continue;
    }

    h = ngx_mrb_push_request_header(headers);
    if (h == NULL) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
    }
    h->hash = hash;
    h->key = key;
    h->lowcase_key = lowcase;
    h->value = v[i];
    h->next = NULL;

    if ((elt = ngx_mrb_header_out_elt(r, field)) != NULL) {
      /* the field points at the last entry; a delete of the name clears it */
      *elt = h;
    }
  }

  return self;
}

static mrb_value ngx_mrb_headers_delete(mrb_state *mrb, mrb_value self, ngx_uint_t out)
{
  ngx_http_request_t *r;
  ngx_mrb_header_field_t field;
  mrb_value name;
  ngx_str_t n;

  r = ngx_mrb_headers_request(mrb, out, 1);
  mrb_get_args(mrb, "o", &name);
  ngx_mrb_header_name(mrb, name, &n);

  field = out ? ngx_mrb_header_out_field(n.data, n.len) : NGX_MRB_HEADER_LIST;
  if (ngx_mrb_headers_remove(r, out ? &r->headers_out.headers : &r->headers_in.headers, &n, field) != NGX_OK) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
  }
  return self;
}

static mrb_value ngx_mrb_get_request_headers_in(mrb_state *mrb, mrb_value self)
{
  return ngx_mrb_headers_get(mrb, 0);
}

static mrb_value ngx_mrb_get_request_headers_out(mrb_state *mrb, mrb_value self)
{
  return ngx_mrb_headers_get(mrb, 1);
}

static mrb_value ngx_mrb_set_request_headers_in(mrb_state *mrb, mrb_value self)
{
  return ngx_mrb_headers_set(mrb, self, 0);
}

static mrb_value ngx_mrb_set_request_headers_out(mrb_state *mrb, mrb_value self)
{
  return ngx_mrb_headers_set(mrb, self, 1);
}

static mrb_value ngx_mrb_del_request_headers_in(mrb_state *mrb, mrb_value self)
{
  return ngx_mrb_headers_delete(mrb, self, 0);
}

static mrb_value ngx_mrb_del_request_headers_out(mrb_state *mrb, mrb_value self)
{
  return ngx_mrb_headers_delete(mrb, self, 1);
}

// Nginx::Request#var
mrb_value ngx_mrb_get_request_var(mrb_state *mrb, mrb_value self)
{
  mrb_sym iv_var_sym = NGX_HTTP_MRUBY_SYM(mrb, IV_VAR);
  mrb_value iv_var;
  struct RClass *class_var, *ngx_class;

  iv_var = mrb_iv_get(mrb, self, iv_var_sym);
  if (mrb_nil_p(iv_var)) {
    // get class from Nginx::Var
    ngx_class = mrb_class_get_id(mrb, NGX_HTTP_MRUBY_SYM(mrb, NGINX));
    class_var =
        (struct RClass *)mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(ngx_class), NGX_HTTP_MRUBY_SYM(mrb, VAR)));
    // initialize a Var instance
    iv_var = mrb_class_new_instance(mrb, 0, 0, class_var);
    // save Var, avoid multi initialize
    mrb_iv_set(mrb, self, iv_var_sym, iv_var);
  }

  return iv_var;
}

static mrb_value ngx_mrb_get_request_var_hostname(mrb_state *mrb, mrb_value self)
{
  return ngx_mrb_var_get_fixed(mrb, NGX_MRB_VAR_HOST);
}

static mrb_value ngx_mrb_get_request_var_authority(mrb_state *mrb, mrb_value self)
{
  return ngx_mrb_var_get_fixed(mrb, NGX_MRB_VAR_HTTP_HOST);
}

static mrb_value ngx_mrb_get_request_var_filename(mrb_state *mrb, mrb_value self)
{
  return ngx_mrb_var_get_fixed(mrb, NGX_MRB_VAR_REQUEST_FILENAME);
}

static mrb_value ngx_mrb_get_request_var_user(mrb_state *mrb, mrb_value self)
{
  return ngx_mrb_var_get_fixed(mrb, NGX_MRB_VAR_REMOTE_USER);
}

// TODO: combine ngx_mrb_get_request_var
static mrb_value ngx_mrb_get_class_obj(mrb_state *mrb, mrb_value self, mrb_sym obj_id, mrb_sym class_name)
{
  mrb_value obj;
  struct RClass *obj_class, *ngx_class;

  obj = mrb_iv_get(mrb, self, obj_id);
  if (mrb_nil_p(obj)) {
    ngx_class = mrb_class_get_id(mrb, NGX_HTTP_MRUBY_SYM(mrb, NGINX));
    obj_class = (struct RClass *)mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(ngx_class), class_name));
    obj = mrb_obj_new(mrb, obj_class, 0, NULL);
    mrb_iv_set(mrb, self, obj_id, obj);
  }
  return obj;
}

static mrb_value ngx_mrb_headers_in_obj(mrb_state *mrb, mrb_value self)
{
  return ngx_mrb_get_class_obj(mrb, self, NGX_HTTP_MRUBY_SYM(mrb, HEADERS_IN_OBJ), NGX_HTTP_MRUBY_SYM(mrb, HEADERS_IN));
}

static mrb_value ngx_mrb_headers_out_obj(mrb_state *mrb, mrb_value self)
{
  return ngx_mrb_get_class_obj(mrb, self, NGX_HTTP_MRUBY_SYM(mrb, HEADERS_OUT_OBJ),
                               NGX_HTTP_MRUBY_SYM(mrb, HEADERS_OUT));
}

static mrb_value ngx_mrb_sub_request_check(mrb_state *mrb, mrb_value str)
{
  ngx_http_request_t *r = NGX_MRB_REQUEST_ANY(mrb);
  return (r != r->main) ? mrb_true_value() : mrb_false_value();
}

/*
 * Nginx::Request#store (section 2.1 of docs/proposals/core-alpha1.md): the
 * Hash of a request, the same object in every handler and filter of the
 * request, created at the first call.
 *
 * The store belongs to the request, not to the module context, so that it
 * survives an internal redirect, which clears the module contexts (decision
 * 2 of the proposal). A cleanup of the request pool holds the record below:
 * the request, the Hash and its slot in the GC root holder
 * (ngx_http_mruby_gc_roots.h). nginx runs the cleanup when it destroys the
 * pool, after the log handlers, and the cleanup frees the slot. A
 * subrequest shares the pool of its main request, so the record names the
 * request it belongs to, and a subrequest gets a store of its own, which
 * lives until the main request ends. The module context caches the record;
 * after a redirect cleared the module context, the first call walks the
 * cleanups of the pool once to find it again. A request that never calls the
 * method allocates nothing.
 */
typedef struct ngx_http_mrb_store_s {
  ngx_http_request_t *r;
  mrb_state *mrb;
  mrb_value hash;
  mrb_int slot;
} ngx_http_mrb_store_t;

static void ngx_http_mrb_store_cleanup(void *data)
{
  ngx_http_mrb_store_t *store = data;

  ngx_mrb_gc_roots_remove(store->mrb, store->slot);
  store->slot = NGX_MRB_GC_ROOTS_NONE;
}

static ngx_http_mrb_store_t *ngx_http_mrb_store_find(mrb_state *mrb, ngx_http_request_t *r)
{
  ngx_pool_cleanup_t *cln;
  ngx_http_mrb_store_t *store;

  for (cln = r->pool->cleanup; cln != NULL; cln = cln->next) {
    if (cln->handler != ngx_http_mrb_store_cleanup) {
      continue;
    }
    store = cln->data;
    if (store->r == r && store->mrb == mrb) {
      return store;
    }
  }
  return NULL;
}

static mrb_value ngx_mrb_get_request_store(mrb_state *mrb, mrb_value self)
{
  ngx_http_request_t *r = NGX_MRB_REQUEST_ANY(mrb);
  ngx_http_mruby_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mruby_module);
  ngx_http_mrb_store_t *store;
  ngx_pool_cleanup_t *cln;
  mrb_value hash;

  if (ctx != NULL && ctx->store != NULL) {
    return ctx->store->hash;
  }

  store = ngx_http_mrb_store_find(mrb, r);
  if (store == NULL) {
    hash = mrb_hash_new(mrb);
    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_mrb_store_t));
    if (cln == NULL) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "failed to allocate memory");
    }
    store = cln->data;
    store->r = r;
    store->mrb = mrb;
    store->hash = hash;
    /* The handler is set once the Hash has its slot: until then the cleanup
       has no handler, so nginx skips it, and the walk above does not find
       it. ngx_mrb_gc_roots_add() raises NoMemoryError when the holder cannot
       grow. */
    store->slot = ngx_mrb_gc_roots_add(mrb, hash);
    if (store->slot == NGX_MRB_GC_ROOTS_NONE) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "failed to keep the store of the request");
    }
    cln->handler = ngx_http_mrb_store_cleanup;
  }

  if (ctx != NULL) {
    ctx->store = store;
  }
  return store->hash;
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
  mrb_define_method(mrb, class_request, "store", ngx_mrb_get_request_store, MRB_ARGS_NONE());

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

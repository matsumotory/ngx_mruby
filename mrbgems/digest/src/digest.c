/*
// digest.c - Digest and Digest::HMAC of ngx_mruby
//
// See Copyright Notice in src/http/ngx_http_mruby_module.c
//
// The hashes use the EVP API of OpenSSL 3 and HMAC uses EVP_MAC. No function
// that OpenSSL 3 deprecates is used: OPENSSL_API_COMPAT below hides their
// declarations, so a call to one of them does not compile.
//
// The classes keep the API that iij/mruby-digest gave to the default build of
// ngx_mruby 2.x (docs/class_and_method/README.md, "Digest").
*/

#define OPENSSL_API_COMPAT 30000

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/params.h>

#if OPENSSL_VERSION_MAJOR < 3
#error "the Digest gem of ngx_mruby needs OpenSSL 3.0 or later (EVP_MAC)"
#endif

#include <limits.h>
#include <string.h>

#include <mruby.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/string.h>
#include <mruby/variable.h>

/* The constant that names the algorithm of a class of Digest, as in
 * iij/mruby-digest. A subclass of Digest::SHA256 finds it through its
 * superclass. */
#define DIGEST_TYPE_CONST "__type__"
/* The instance variable of the module Digest that holds the algorithms of
 * this mrb_state. Its name has no "@", so instance_variables does not list
 * it. */
#define DIGEST_LIB_IV "__ngx_mruby_digest_lib__"

enum { DIGEST_MD5, DIGEST_RMD160, DIGEST_SHA1, DIGEST_SHA256, DIGEST_SHA384, DIGEST_SHA512, DIGEST_ALGS };

static const struct {
  const char *class_name;
  const char *openssl_name;
} digest_algs[DIGEST_ALGS] = {
    {"MD5", "MD5"},       {"RMD160", "RIPEMD160"}, {"SHA1", "SHA1"},
    {"SHA256", "SHA256"}, {"SHA384", "SHA384"},    {"SHA512", "SHA512"},
};

/* The algorithms, fetched once when the gem is initialized, so that an object
 * does not look them up again. A NULL entry is an algorithm that the OpenSSL
 * of the process does not provide (RIPEMD160 is in the legacy provider of
 * OpenSSL 3.0.0 to 3.0.6, and MD5 is not in the FIPS provider). */
typedef struct {
  EVP_MD *md[DIGEST_ALGS];
  EVP_MAC *hmac;
} digest_lib;

typedef struct {
  EVP_MD_CTX *ctx;
  const EVP_MD *md;
} digest_md;

typedef struct {
  EVP_MAC_CTX *ctx;
  const EVP_MD *md;
} digest_hmac;

static void digest_lib_free(mrb_state *mrb, void *p)
{
  digest_lib *lib = p;
  int i;

  if (lib == NULL) {
    return;
  }
  for (i = 0; i < DIGEST_ALGS; i++) {
    EVP_MD_free(lib->md[i]);
  }
  EVP_MAC_free(lib->hmac);
  mrb_free(mrb, lib);
}

static void digest_md_free(mrb_state *mrb, void *p)
{
  digest_md *d = p;

  if (d == NULL) {
    return;
  }
  EVP_MD_CTX_free(d->ctx);
  mrb_free(mrb, d);
}

static void digest_hmac_free(mrb_state *mrb, void *p)
{
  digest_hmac *h = p;

  if (h == NULL) {
    return;
  }
  EVP_MAC_CTX_free(h->ctx);
  mrb_free(mrb, h);
}

static const struct mrb_data_type digest_lib_type = {"Digest::lib", digest_lib_free};
static const struct mrb_data_type digest_md_type = {"Digest::Base", digest_md_free};
static const struct mrb_data_type digest_hmac_type = {"Digest::HMAC", digest_hmac_free};

static mrb_noreturn void digest_raise_openssl(mrb_state *mrb, const char *what)
{
  unsigned long e = ERR_get_error();
  char buf[256];

  ERR_clear_error();
  if (e == 0) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "Digest: %s failed", what);
  }
  ERR_error_string_n(e, buf, sizeof(buf));
  mrb_raisef(mrb, E_RUNTIME_ERROR, "Digest: %s failed: %s", what, buf);
}

static digest_lib *digest_get_lib(mrb_state *mrb)
{
  struct RClass *mod = mrb_module_get(mrb, "Digest");
  mrb_value v = mrb_iv_get(mrb, mrb_obj_value(mod), mrb_intern_lit(mrb, DIGEST_LIB_IV));

  return (digest_lib *)mrb_data_get_ptr(mrb, v, &digest_lib_type);
}

/* The algorithm of a class of Digest (Digest::SHA256 or a subclass of it), or
 * of the digest class that Digest::HMAC.new takes. Like iij/mruby-digest, a
 * class without the constant raises the NameError of the constant lookup. */
static mrb_int digest_type_of(mrb_state *mrb, mrb_value klass)
{
  mrb_value t = mrb_const_get(mrb, klass, mrb_intern_lit(mrb, DIGEST_TYPE_CONST));

  if (!mrb_integer_p(t) || mrb_integer(t) < 0 || mrb_integer(t) >= DIGEST_ALGS) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "not a digester");
  }
  return mrb_integer(t);
}

static const EVP_MD *digest_md_of_type(mrb_state *mrb, mrb_int type)
{
  const EVP_MD *md = digest_get_lib(mrb)->md[type];

  if (md == NULL) {
    mrb_raisef(mrb, E_NOTIMP_ERROR, "Digest::%s is not available in this OpenSSL", digest_algs[type].class_name);
  }
  return md;
}

static mrb_value digest_hex(mrb_state *mrb, const unsigned char *p, size_t len)
{
  static const char hex[] = "0123456789abcdef";
  mrb_value s = mrb_str_new(mrb, NULL, (mrb_int)(len * 2));
  char *out = RSTRING_PTR(s);
  size_t i;

  for (i = 0; i < len; i++) {
    out[i * 2] = hex[p[i] >> 4];
    out[i * 2 + 1] = hex[p[i] & 0x0f];
  }
  return s;
}

/* Digest::Base */

static digest_md *digest_md_get(mrb_state *mrb, mrb_value self)
{
  return (digest_md *)mrb_data_check_get_ptr(mrb, self, &digest_md_type);
}

static mrb_value digest_md_initialize(mrb_state *mrb, mrb_value self)
{
  struct RClass *c = mrb_obj_class(mrb, self);
  digest_md *d = (digest_md *)DATA_PTR(self);
  const EVP_MD *md;
  mrb_int type;

  if (d != NULL) {
    digest_md_free(mrb, d);
  }
  mrb_data_init(self, NULL, &digest_md_type);

  if (!mrb_const_defined(mrb, mrb_obj_value(c), mrb_intern_lit(mrb, DIGEST_TYPE_CONST))) {
    mrb_raise(mrb, E_NOTIMP_ERROR, "Digest::Base is an abstract class");
  }
  type = digest_type_of(mrb, mrb_obj_value(c));
  md = digest_md_of_type(mrb, type);

  d = (digest_md *)mrb_malloc(mrb, sizeof(*d));
  d->md = md;
  d->ctx = EVP_MD_CTX_new();
  mrb_data_init(self, d, &digest_md_type);
  if (d->ctx == NULL || !EVP_DigestInit_ex2(d->ctx, md, NULL)) {
    digest_raise_openssl(mrb, "EVP_DigestInit_ex2");
  }
  return self;
}

static mrb_value digest_md_initialize_copy(mrb_state *mrb, mrb_value copy)
{
  mrb_value src;
  digest_md *s, *d;

  mrb_get_args(mrb, "o", &src);
  if (mrb_obj_equal(mrb, copy, src)) {
    return copy;
  }
  if (!mrb_obj_is_instance_of(mrb, src, mrb_obj_class(mrb, copy))) {
    mrb_raise(mrb, E_TYPE_ERROR, "wrong argument class");
  }
  s = digest_md_get(mrb, src);
  if (s == NULL) {
    return copy;
  }
  d = (digest_md *)DATA_PTR(copy);
  if (d != NULL) {
    digest_md_free(mrb, d);
  }
  mrb_data_init(copy, NULL, &digest_md_type);
  d = (digest_md *)mrb_malloc(mrb, sizeof(*d));
  d->md = s->md;
  d->ctx = EVP_MD_CTX_new();
  mrb_data_init(copy, d, &digest_md_type);
  /* The copy goes on from the data that the source has taken, as in CRuby. */
  if (d->ctx == NULL || !EVP_MD_CTX_copy_ex(d->ctx, s->ctx)) {
    digest_raise_openssl(mrb, "EVP_MD_CTX_copy_ex");
  }
  return copy;
}

static mrb_value digest_md_update(mrb_state *mrb, mrb_value self)
{
  digest_md *d;
  char *p;
  mrb_int len;

  mrb_get_args(mrb, "s", &p, &len);
  d = digest_md_get(mrb, self);
  if (d == NULL) {
    return mrb_nil_value();
  }
  if (!EVP_DigestUpdate(d->ctx, p, (size_t)len)) {
    digest_raise_openssl(mrb, "EVP_DigestUpdate");
  }
  return self;
}

/* The digest of the data so far; the object can take more data afterwards. */
static mrb_value digest_md_finish(mrb_state *mrb, digest_md *d, int hex)
{
  unsigned char buf[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  EVP_MD_CTX *tmp = EVP_MD_CTX_new();

  if (tmp == NULL || !EVP_MD_CTX_copy_ex(tmp, d->ctx) || !EVP_DigestFinal_ex(tmp, buf, &len)) {
    EVP_MD_CTX_free(tmp);
    digest_raise_openssl(mrb, "EVP_DigestFinal_ex");
  }
  EVP_MD_CTX_free(tmp);
  return hex ? digest_hex(mrb, buf, len) : mrb_str_new(mrb, (const char *)buf, len);
}

static mrb_value digest_md_digest(mrb_state *mrb, mrb_value self)
{
  digest_md *d = digest_md_get(mrb, self);

  if (d == NULL) {
    return mrb_nil_value();
  }
  return digest_md_finish(mrb, d, 0);
}

static mrb_value digest_md_hexdigest(mrb_state *mrb, mrb_value self)
{
  digest_md *d = digest_md_get(mrb, self);

  if (d == NULL) {
    return mrb_nil_value();
  }
  return digest_md_finish(mrb, d, 1);
}

/* The digest of the data so far, then the object starts again empty. */
static mrb_value digest_md_digest_bang(mrb_state *mrb, mrb_value self)
{
  digest_md *d = digest_md_get(mrb, self);
  unsigned char buf[EVP_MAX_MD_SIZE];
  unsigned int len = 0;

  if (d == NULL) {
    return mrb_nil_value();
  }
  if (!EVP_DigestFinal_ex(d->ctx, buf, &len) || !EVP_DigestInit_ex2(d->ctx, d->md, NULL)) {
    digest_raise_openssl(mrb, "EVP_DigestFinal_ex");
  }
  return mrb_str_new(mrb, (const char *)buf, len);
}

static mrb_value digest_md_reset(mrb_state *mrb, mrb_value self)
{
  digest_md *d = digest_md_get(mrb, self);

  if (d == NULL) {
    return mrb_nil_value();
  }
  if (!EVP_DigestInit_ex2(d->ctx, d->md, NULL)) {
    digest_raise_openssl(mrb, "EVP_DigestInit_ex2");
  }
  return self;
}

static digest_md *digest_md_check(mrb_state *mrb, mrb_value self)
{
  digest_md *d = digest_md_get(mrb, self);

  if (d == NULL) {
    mrb_raise(mrb, E_NOTIMP_ERROR, "Digest::Base is an abstract class");
  }
  return d;
}

static mrb_value digest_md_block_length(mrb_state *mrb, mrb_value self)
{
  return mrb_int_value(mrb, EVP_MD_get_block_size(digest_md_check(mrb, self)->md));
}

static mrb_value digest_md_digest_length(mrb_state *mrb, mrb_value self)
{
  return mrb_int_value(mrb, EVP_MD_get_size(digest_md_check(mrb, self)->md));
}

/* Digest::HMAC */

static digest_hmac *digest_hmac_get(mrb_state *mrb, mrb_value self)
{
  return (digest_hmac *)mrb_data_check_get_ptr(mrb, self, &digest_hmac_type);
}

static mrb_value digest_hmac_initialize(mrb_state *mrb, mrb_value self)
{
  digest_hmac *h = (digest_hmac *)DATA_PTR(self);
  mrb_value klass;
  char *key;
  mrb_int keylen, type;
  const EVP_MD *md;
  digest_lib *lib;
  OSSL_PARAM params[2];

  mrb_get_args(mrb, "so", &key, &keylen, &klass);
  if (h != NULL) {
    digest_hmac_free(mrb, h);
  }
  mrb_data_init(self, NULL, &digest_hmac_type);

  type = digest_type_of(mrb, klass);
  md = digest_md_of_type(mrb, type);
  lib = digest_get_lib(mrb);
  if (lib->hmac == NULL) {
    mrb_raise(mrb, E_NOTIMP_ERROR, "Digest::HMAC is not available in this OpenSSL");
  }

  h = (digest_hmac *)mrb_malloc(mrb, sizeof(*h));
  h->md = md;
  h->ctx = EVP_MAC_CTX_new(lib->hmac);
  mrb_data_init(self, h, &digest_hmac_type);
  if (h->ctx == NULL) {
    digest_raise_openssl(mrb, "EVP_MAC_CTX_new");
  }
  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)EVP_MD_get0_name(md), 0);
  params[1] = OSSL_PARAM_construct_end();
  /* An empty key is a key of zero bytes, as HMAC defines it: the pointer of
   * an empty String is not NULL, and EVP_MAC_init with a NULL key would keep
   * the key of an earlier init instead. */
  if (!EVP_MAC_init(h->ctx, (const unsigned char *)key, (size_t)keylen, params)) {
    digest_raise_openssl(mrb, "EVP_MAC_init");
  }
  return self;
}

static mrb_value digest_hmac_initialize_copy(mrb_state *mrb, mrb_value copy)
{
  mrb_raise(mrb, E_RUNTIME_ERROR, "cannot duplicate HMAC");
  return copy;
}

static mrb_value digest_hmac_update(mrb_state *mrb, mrb_value self)
{
  digest_hmac *h;
  char *p;
  mrb_int len;

  mrb_get_args(mrb, "s", &p, &len);
  h = digest_hmac_get(mrb, self);
  if (h == NULL) {
    return mrb_nil_value();
  }
  if (!EVP_MAC_update(h->ctx, (const unsigned char *)p, (size_t)len)) {
    digest_raise_openssl(mrb, "EVP_MAC_update");
  }
  return self;
}

/* The HMAC of the data so far, from a copy of the context: the object keeps
 * its state and can take more data afterwards. */
static mrb_value digest_hmac_finish(mrb_state *mrb, mrb_value self, int hex)
{
  digest_hmac *h = digest_hmac_get(mrb, self);
  unsigned char buf[EVP_MAX_MD_SIZE];
  size_t len = 0;
  EVP_MAC_CTX *tmp;

  if (h == NULL) {
    return mrb_nil_value();
  }
  tmp = EVP_MAC_CTX_dup(h->ctx);
  if (tmp == NULL || !EVP_MAC_final(tmp, buf, &len, sizeof(buf))) {
    EVP_MAC_CTX_free(tmp);
    digest_raise_openssl(mrb, "EVP_MAC_final");
  }
  EVP_MAC_CTX_free(tmp);
  return hex ? digest_hex(mrb, buf, len) : mrb_str_new(mrb, (const char *)buf, (mrb_int)len);
}

static mrb_value digest_hmac_digest(mrb_state *mrb, mrb_value self)
{
  return digest_hmac_finish(mrb, self, 0);
}

static mrb_value digest_hmac_hexdigest(mrb_state *mrb, mrb_value self)
{
  return digest_hmac_finish(mrb, self, 1);
}

static mrb_value digest_hmac_block_length(mrb_state *mrb, mrb_value self)
{
  digest_hmac *h = digest_hmac_get(mrb, self);

  if (h == NULL) {
    return mrb_nil_value();
  }
  return mrb_int_value(mrb, EVP_MD_get_block_size(h->md));
}

static mrb_value digest_hmac_digest_length(mrb_state *mrb, mrb_value self)
{
  digest_hmac *h = digest_hmac_get(mrb, self);

  if (h == NULL) {
    return mrb_nil_value();
  }
  return mrb_int_value(mrb, EVP_MD_get_size(h->md));
}

void mrb_mruby_digest_gem_init(mrb_state *mrb)
{
  struct RClass *digest, *base, *hmac;
  digest_lib *lib;
  mrb_value v;
  int i;

  digest = mrb_define_module(mrb, "Digest");

  /* Fetched here, while nginx reads the configuration, not per request. */
  lib = (digest_lib *)mrb_malloc(mrb, sizeof(*lib));
  memset(lib, 0, sizeof(*lib));
  v = mrb_obj_value(mrb_data_object_alloc(mrb, mrb->object_class, lib, &digest_lib_type));
  mrb_iv_set(mrb, mrb_obj_value(digest), mrb_intern_lit(mrb, DIGEST_LIB_IV), v);
  for (i = 0; i < DIGEST_ALGS; i++) {
    lib->md[i] = EVP_MD_fetch(NULL, digest_algs[i].openssl_name, NULL);
  }
  lib->hmac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL);
  /* A failed fetch leaves its reason in the error queue of OpenSSL, which
   * nginx would log later as if its own call had failed. */
  ERR_clear_error();

  base = mrb_define_class_under(mrb, digest, "Base", mrb->object_class);
  MRB_SET_INSTANCE_TT(base, MRB_TT_CDATA);
  mrb_define_method(mrb, base, "block_length", digest_md_block_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, base, "digest", digest_md_digest, MRB_ARGS_NONE());
  mrb_define_method(mrb, base, "digest!", digest_md_digest_bang, MRB_ARGS_NONE());
  mrb_define_method(mrb, base, "digest_length", digest_md_digest_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, base, "hexdigest", digest_md_hexdigest, MRB_ARGS_NONE());
  mrb_define_method(mrb, base, "initialize", digest_md_initialize, MRB_ARGS_NONE());
  mrb_define_method(mrb, base, "initialize_copy", digest_md_initialize_copy, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, base, "reset", digest_md_reset, MRB_ARGS_NONE());
  mrb_define_method(mrb, base, "update", digest_md_update, MRB_ARGS_REQ(1));

  for (i = 0; i < DIGEST_ALGS; i++) {
    struct RClass *c = mrb_define_class_under(mrb, digest, digest_algs[i].class_name, base);
    MRB_SET_INSTANCE_TT(c, MRB_TT_CDATA);
    mrb_define_const(mrb, c, DIGEST_TYPE_CONST, mrb_int_value(mrb, i));
  }

  hmac = mrb_define_class_under(mrb, digest, "HMAC", mrb->object_class);
  MRB_SET_INSTANCE_TT(hmac, MRB_TT_CDATA);
  mrb_define_method(mrb, hmac, "block_length", digest_hmac_block_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, hmac, "digest", digest_hmac_digest, MRB_ARGS_NONE());
  mrb_define_method(mrb, hmac, "digest_length", digest_hmac_digest_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, hmac, "hexdigest", digest_hmac_hexdigest, MRB_ARGS_NONE());
  mrb_define_method(mrb, hmac, "initialize", digest_hmac_initialize, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, hmac, "initialize_copy", digest_hmac_initialize_copy, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, hmac, "update", digest_hmac_update, MRB_ARGS_REQ(1));
}

void mrb_mruby_digest_gem_final(mrb_state *mrb)
{
}

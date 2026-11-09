/*
// secure_random.c - SecureRandom.random_bytes of ngx_mruby
//
// See Copyright Notice in src/http/ngx_http_mruby_module.c
//
// The bytes come from RAND_bytes of OpenSSL: its generator is seeded from the
// operating system (getrandom(2) on Linux) and seeds itself again in a child
// process, so the workers that nginx forks get bytes of their own. A call
// opens no file. The other methods of SecureRandom are in mrblib/.
*/

#define OPENSSL_API_COMPAT 30000

#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>

#if OPENSSL_VERSION_MAJOR < 3
#error "the SecureRandom gem of ngx_mruby needs OpenSSL 3.0 or later"
#endif

#include <limits.h>

#include <mruby.h>
#include <mruby/string.h>

#define SECURE_RANDOM_DEFAULT_SIZE 16

/* SecureRandom.random_bytes(n = nil): n random bytes, 16 when n is nil. n is
 * converted with to_int, as in mruby-secure-random. */
static mrb_value secure_random_random_bytes(mrb_state *mrb, mrb_value self)
{
  mrb_value nv = mrb_nil_value();
  mrb_int n;
  mrb_value s;

  mrb_get_args(mrb, "|o", &nv);
  if (mrb_nil_p(nv)) {
    n = SECURE_RANDOM_DEFAULT_SIZE;
  } else {
    if (!mrb_integer_p(nv)) {
      nv = mrb_funcall_argv(mrb, nv, mrb_intern_lit(mrb, "to_int"), 0, NULL);
      if (!mrb_integer_p(nv)) {
        mrb_raise(mrb, E_TYPE_ERROR, "can't convert to Integer");
      }
    }
    n = mrb_integer(nv);
  }
  if (n < 0) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "negative string size: %i", n);
  }
  if (n > INT_MAX) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "string size too big: %i", n);
  }

  s = mrb_str_new(mrb, NULL, n);
  if (n > 0 && RAND_bytes((unsigned char *)RSTRING_PTR(s), (int)n) != 1) {
    unsigned long e = ERR_get_error();
    char buf[256];

    ERR_clear_error();
    ERR_error_string_n(e, buf, sizeof(buf));
    mrb_raisef(mrb, E_RUNTIME_ERROR, "SecureRandom: RAND_bytes failed: %s", buf);
  }
  return s;
}

void mrb_mruby_secure_random_gem_init(mrb_state *mrb)
{
  struct RClass *c = mrb_define_class(mrb, "SecureRandom", mrb->object_class);

  mrb_define_class_method(mrb, c, "random_bytes", secure_random_random_bytes, MRB_ARGS_OPT(1));
}

void mrb_mruby_secure_random_gem_final(mrb_state *mrb)
{
}

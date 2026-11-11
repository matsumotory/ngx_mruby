/*
// ngx_mruby_log.h - ngx_mruby mruby module header
//
// See Copyright Notice in ngx_http_mruby_module.c
*/

#ifndef NGX_MRUBY_LOG_H
#define NGX_MRUBY_LOG_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <mruby.h>

/*
// Writes exc, the exception of Ruby code, to the error log: one line at
// level with prefix followed by exc.inspect, and, in a build with
// --with-debug, one line at the error level for each String of
// exc.backtrace. The http and the stream modules call it for every kind of
// code; each caller passes the log, the level and the text that the line
// had before both modules shared this function (section 2.8 of
// docs/proposals/core-alpha1.md).
//
// cf is the parser state for the code that runs while nginx reads the
// configuration, and NULL otherwise. With cf, the line goes through
// ngx_conf_log_error, which adds the file and the line of the configuration,
// the backtrace goes to cf->log, and log is not used.
//
// The line is left out when exc.inspect does not return a String. A script
// can redefine #backtrace: an element of its result that is not a String is
// skipped, and a result that is not an Array is logged at the debug level
// instead of the frames.
*/
void ngx_mrb_log_exception(mrb_state *mrb, mrb_value exc, ngx_log_t *log, ngx_conf_t *cf, ngx_uint_t level,
                           const char *prefix);

/*
// The body of Nginx.log and Nginx.errlogger (http) and of Nginx::Stream.log
// and Nginx::Stream.errlogger (stream): reads the level and the message of
// the call and writes the message to log at that level. A negative level
// writes, at the error level, "<module_name> ERROR <func>: log level is not
// positive number" instead; each module passes its MODULE_NAME and the name
// of its C method (__func__), so that the line keeps its text. Returns self.
*/
mrb_value ngx_mrb_log_method(mrb_state *mrb, mrb_value self, ngx_log_t *log, const char *module_name, const char *func);

#endif /* NGX_MRUBY_LOG_H */

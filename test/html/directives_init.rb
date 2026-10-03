# mruby_init hook, file version, used by test/conf/nginx.conf.
# It replaces the former mruby_init_code line, because both directives
# share one slot and nginx rejects the second one as duplicated.
p "[#{Process.pid}] init master process"
$g3_init_order = ["init"]

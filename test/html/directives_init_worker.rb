# mruby_init_worker hook, file version, used by test/conf/nginx.conf.
# It replaces the former mruby_init_worker_code line and keeps what that
# inline code did, so the existing /iv_init_worker case still applies.
p "[#{Process.pid}] init worker process from file"
begin
  @iv_init_worker = true
rescue
end
$g3_init_order = ($g3_init_order || []) + ["init_worker"]

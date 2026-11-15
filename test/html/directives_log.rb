# Log phase hook, file version. Loaded by mruby_log_handler in
# test/conf/conf.d/30-directives.conf. The value it stores in Userdata is
# read back by a later request to /directives/log_read. The output at the
# end does not reach the client: since 3.0.0 it raises in a log handler, after
# the value is stored.
r = Nginx::Request.new
Userdata.new.phase_log = "file #{r.uri}?#{r.args} #{r.var.status}"
Nginx.rputs "file output"

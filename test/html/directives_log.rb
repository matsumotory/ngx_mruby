# Log phase hook, file version. Loaded by mruby_log_handler in
# test/conf/conf.d/30-directives.conf. The value it stores in Userdata is
# read back by a later request to /g3/log_read.
r = Nginx::Request.new
Userdata.new.g3_log = "file #{r.uri}?#{r.args} #{r.var.status}"

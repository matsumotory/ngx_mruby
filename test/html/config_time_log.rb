# Content handler file of test/conf/conf.d/63-config-time-log.conf. The reply
# shows that this file and the mruby_set_code of the same location ran.
Nginx.rputs "file handler ran, #{Nginx::Request.new.var.config_time_log_value}"

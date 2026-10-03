# Loaded by mruby_stream_init_worker in test/conf/nginx.stream.conf. The file
# directive comes after the inline mruby_stream_init_worker_code there and
# replaces it.
p "ngx_mruby: STREAM: mruby_stream_init_worker"
Userdata.new.g4_stream_trace = "#{Userdata.new.g4_stream_trace},init_worker_file"

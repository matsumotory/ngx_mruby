# Loaded by mruby_stream_init in test/conf/nginx.stream.conf. The file
# directive comes after the inline mruby_stream_init_code there, and the later
# directive replaces the earlier one, so this file also sets the upstream that
# the server on port 12346 reads.
p "ngx_mruby: STREAM: mruby_stream_init"
Userdata.new.new_upstream = "127.0.0.1:58081"

# The trace starts in mruby_stream_server_context_code of the server on port
# 12356 (test/conf/conf.d/stream/40-stream.conf), which runs while nginx reads
# the configuration. test/t/cases/stream.rb checks the whole trace.
Userdata.new.g4_stream_trace = "#{Userdata.new.g4_stream_trace},init_file"

# mruby_stream_init hook, file version. test/t/cases/stream.rb runs it with
# nginx -t, and test/t/cases/_second_instance.rb starts a second nginx that
# loads it. The trace starts in mruby_stream_server_context_code of that
# second nginx, which runs while nginx reads the configuration.
p "mruby_stream_init file"
Userdata.new.init_trace = "#{Userdata.new.init_trace},init_file"

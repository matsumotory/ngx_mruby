# mruby_stream_init_worker hook, file version. test/t/cases/_second_instance.rb
# starts a second nginx that loads it.
p "mruby_stream_init_worker file"
Userdata.new.init_trace = "#{Userdata.new.init_trace},init_worker_file"

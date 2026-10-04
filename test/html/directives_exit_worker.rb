# mruby_exit_worker hook, file version. test/t/cases/_second_instance.rb
# starts a second nginx that loads it, stops that nginx with SIGQUIT, and
# reads this p line from its stdout.
p "mruby_exit_worker file"

# mruby_init hook, file version. test/t/cases/directives.rb runs it with
# nginx -t, and test/t/cases/_second_instance.rb starts a second nginx that
# loads it. The p line shows that the file ran. directives_init_worker.rb and
# a request to the second nginx read the global variable.
p "mruby_init file"
$init_order = ["init"]

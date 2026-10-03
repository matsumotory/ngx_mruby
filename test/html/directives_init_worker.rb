# mruby_init_worker hook, file version. test/t/cases/directives.rb runs it
# with nginx -t, where it does not run, and test/t/cases/_second_instance.rb
# starts a second nginx that loads it.
p "mruby_init_worker file"
$init_order = ($init_order || []) + ["init_worker"]

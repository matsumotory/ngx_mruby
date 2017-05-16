class Foo
  def foo
    b = Bar.new
    b.bar
  end
end

class Bar
  def bar
    raise "Intentional Error for testing ngx_mrb_log_backtrace"
  end
end

Foo.new.foo

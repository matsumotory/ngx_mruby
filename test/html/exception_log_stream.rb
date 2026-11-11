# The code of the stream session of
# test/conf/conf.d/stream/49-exception-log.conf. It raises in
# ExceptionLogInner#call, which ExceptionLogOuter#call calls, so the backtrace
# of the exception has three frames in this file: the two methods and the top
# level. The message is computed, as in the other code of
# test/t/cases/exception_log.rb.
class ExceptionLogInner
  def call
    raise "exception log: stream session #{6 * 7}"
  end
end

class ExceptionLogOuter
  def call
    ExceptionLogInner.new.call
  end
end

ExceptionLogOuter.new.call

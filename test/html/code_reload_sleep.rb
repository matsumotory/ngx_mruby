# Content handler without cache (test/conf/conf.d/98-code-reload.conf).
# $code_reload_waiting counts the runs that wait at the same time: the second
# of two overlapping requests sees 2. After the wait, the code reads the
# literals and the method calls of its own proc, which another request
# replaced in the slot of the code meanwhile.
$code_reload_waiting = ($code_reload_waiting || 0) + 1
waiting = $code_reload_waiting
Nginx::Async.sleep 1000
$code_reload_waiting -= 1
Nginx.rputs "reloaded:#{[1, 2, 3].map { |i| i * 2 }.join(',')};waiting=#{waiting}"

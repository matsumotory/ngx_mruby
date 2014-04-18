r = Nginx::Request.new

Nginx.rputs "fuga => #{r.var.fuga} "
Nginx.rputs "hoge => #{r.var.hoge} "

r.var.set "hoge", r.var.hoge.to_i * 2
Nginx.rputs "hoge => #{r.var.hoge} "


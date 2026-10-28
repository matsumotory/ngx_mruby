# The body filter of test/conf/conf.d/76-guide-body-filter.conf: wraps the
# text of the response in an HTML page, with &, < and > escaped.
f = Nginx::Filter.new
text = f.body.gsub("&", "&amp;").gsub("<", "&lt;").gsub(">", "&gt;")
f.body = "<!doctype html>\n<title>notes</title>\n<pre>\n#{text}</pre>\n"

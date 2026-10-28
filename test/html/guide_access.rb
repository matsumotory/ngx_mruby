# The access handler of test/conf/conf.d/74-guide-access.conf: answers 403
# when the client's address is a line of the file that $deny_list names.
r = Nginx::Request.new
path = r.var.deny_list
listed = File.exist?(path) && File.read(path).split("\n").include?(r.var.remote_addr)
Nginx.return Nginx::HTTP_FORBIDDEN if listed

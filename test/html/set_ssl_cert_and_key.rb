ssl = Nginx::SSL.new
ssl.certificate = "__NGXDOCROOT__/#{ssl.servername}.crt"
ssl.certificate_key = "__NGXDOCROOT__/#{ssl.servername}.key"

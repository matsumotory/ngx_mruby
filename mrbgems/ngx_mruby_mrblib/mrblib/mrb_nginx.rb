class Nginx
  class Request
    def scheme
      self.var.scheme
    end

    def document_root
      Nginx::Server.new.document_root
    end

    def body
      self.read_body
      self.get_body
    end

    def get_uri_args
      Hash[*self.args.split("&").map{|arg| arg.split("=")}.flatten]
    end

    def set_uri_args(params)
      self.args = params.map{|k,v| "#{k}=#{v}"}.join("&")
    end

    def get_post_args
      Hash[*self.body.split("&").map{|arg| arg.split("=")}.flatten]
    end
  end

  class Headers_in
    def user_agent
      self["User-Agent"]
    end
  end

  def self.var
    Var.new
  end
end

module Kernel
  def get_server_class
    Nginx
  end
end

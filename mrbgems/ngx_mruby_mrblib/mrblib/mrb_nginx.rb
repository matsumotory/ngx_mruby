class Nginx
  class Request
    def document_root
      Nginx::Server.new.document_root
    end
    #def document_root=(path)
    #  Nginx::Var.new.set "document_root", path
    #end
  end
  class Headers_in
    def user_agent
      self["User-Agent"]
    end
  end
end

module Kernel
  def get_server_class
    Nginx
  end
end

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

    def uri_args
      args_to_hash(self.args)
    end

    def uri_args=(params)
      raise ArgumentError unless params.is_a?(Hash)
      self.args = params.map{|k,v| "#{k}=#{v}"}.join("&")
    end

    def post_args
      args_to_hash(self.body)
    end

    private

    def args_to_hash(args)
      Hash[*args.split("&").map{|arg| arg.split("=", 2)}.flatten]
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

  class Async
    class << self
      def sleep(*args)
        __sleep(*args)
        Fiber.yield
      end
    end

    class HTTP
      class << self
        def sub_request(*args)
          __sub_request(*args)
          Fiber.yield
        end
      end

      class Response
        attr_reader :body, :headers, :status
      end
    end
  end
end


module Kernel
  def get_server_class
    Nginx
  end

  def _ngx_mrb_prepare_fiber(nginx_handler)
    fiber_handler = Fiber.new { nginx_handler.call }

    lambda do
      # BUG?: return nginx_handler directly from fiber, not proc in any case.
      result = fiber_handler.resume
      [fiber_handler.alive?, result]
    end
  end
end

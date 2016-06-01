
# #
# # PoC code
# #
#
# r = Userdata.new.redis
# v = nil
#
# Nginx::Event.loop(100) do
#   r.get("hoge"){|val| v = val}
#   Nginx::Event.break unless v.nil?
#   Nginx::Event.next
# end
#
# Nginx.echo "a" + v

class Nginx
  class Event
    @@end = false
    @@f = nil
    @@t = nil
    @@b = nil
    def self.loop t, &b
      Nginx.log Nginx::LOG_CRIT, "event loop call"
      @@t = t
      @@b = b
      @@f = Fiber.new &@@b
      @@f.resume
      # implemented by C
      Nginx.log Nginx::LOG_CRIT, "event addtimer setup"
      self.add_timer(@@t) do
         Nginx.log Nginx::LOG_CRIT, "addtimer blk call"
        @@f.resume
      end
    end
    def self.next
      Nginx.log Nginx::LOG_CRIT, "event next call"
      Fiber.yield
    end
    def self.break
      @@end = true
      # implemented by C
      Nginx.log Nginx::LOG_CRIT, "event break call"
      self.del_timer
      Fiber.yield
    end
  end
end

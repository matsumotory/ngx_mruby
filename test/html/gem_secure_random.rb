# The handler of /gem_secure_random (test/conf/conf.d/62-gem-digest-secure-random.conf).
# One line per check; test/t/cases/gem_digest_secure_random.rb has the
# expected lines. The last lines are random values, which the case compares
# between two requests.

def check
  yield.to_s
rescue Exception => e
  e.class.to_s
end

# Whether every character of s is one of chars.
def only?(s, chars)
  s.each_char.all? { |c| chars.include?(c) }
end

hex_chars = '0123456789abcdef'
b64_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
urlsafe_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

lines = []

# random_bytes: 16 bytes without an argument, n bytes, n converted with
# to_int, and two calls give other bytes.
five = Object.new
def five.to_int
  5
end
lines << check { [SecureRandom.random_bytes.bytesize, SecureRandom.random_bytes(32).bytesize, SecureRandom.random_bytes(0), SecureRandom.random_bytes(five).bytesize].join(' ') }
lines << check { SecureRandom.random_bytes(16) != SecureRandom.random_bytes(16) }
lines << check { SecureRandom.random_bytes(-1) }

# hex: 2n lowercase hexadecimal digits.
lines << check { s = SecureRandom.hex; [s.size, SecureRandom.hex(8).size, only?(s, hex_chars), s != SecureRandom.hex].join(' ') }

# base64 and urlsafe_base64.
lines << check { s = SecureRandom.base64; [s.size, s.end_with?('=='), only?(s, b64_chars), SecureRandom.base64(3).size].join(' ') }
lines << check { s = SecureRandom.urlsafe_base64; [s.size, only?(s, urlsafe_chars), SecureRandom.urlsafe_base64(nil, true).size, SecureRandom.urlsafe_base64(3).size, SecureRandom.urlsafe_base64(32).size].join(' ') }

# random_number: an Integer of 0 or more and less than n.
lines << check { v = (1..200).map { SecureRandom.random_number(10) }; [v.all? { |x| x.kind_of?(Integer) && x >= 0 && x < 10 }, v.uniq.size > 1].join(' ') }
lines << check { [SecureRandom.random_number(1), SecureRandom.random_number(2**100) < 2**100, SecureRandom.random_number(2**100).kind_of?(Integer)].join(' ') }
lines << check { SecureRandom.random_number(0) }
lines << check { SecureRandom.random_number(-1) }
lines << check { SecureRandom.random_number(1.5) }

# uuid: version 4, the variant of RFC 9562, lowercase.
lines << check do
  u = SecureRandom.uuid
  [u.size, [u[8], u[13], u[18], u[23]].join, u[14], '89ab'.include?(u[19]), only?(u.gsub('-', ''), hex_chars), u != SecureRandom.uuid].join(' ')
end

# The methods call random_bytes through self, so a subclass that returns
# fixed bytes gives fixed values (the bytes and values of the tests of
# monochromegane/mruby-secure-random).
class GemSecureRandomFixed < SecureRandom
  def self.random_bytes(n = nil)
    n == 16 ? "t\353\227\311\030p\214\337DJ1\325[\016BQ" : "\334"
  end
end
lines << check { [GemSecureRandomFixed.hex(1), GemSecureRandomFixed.base64(1), GemSecureRandomFixed.urlsafe_base64(1), GemSecureRandomFixed.urlsafe_base64(1, true), GemSecureRandomFixed.uuid].join(' ') }
lines << check { SecureRandom.instance_of?(Class) && SecureRandom.superclass == Object }

# Random values, compared by the case between two requests.
lines << SecureRandom.hex
lines << SecureRandom.uuid

Nginx.rputs lines.join("\n")

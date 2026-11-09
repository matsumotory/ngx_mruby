# The methods of SecureRandom on top of SecureRandom.random_bytes
# (src/secure_random.c). They keep the API of monochromegane/mruby-secure-random,
# which the default build of ngx_mruby 2.x had, and call random_bytes through
# self, so that a subclass that redefines random_bytes changes them too.
class SecureRandom
  class << self
    # 2n lowercase hexadecimal digits (32 when n is nil).
    def hex(n = nil)
      random_bytes(n).unpack('H*')[0]
    end

    # The Base64 of n random bytes, with padding and without line breaks.
    def base64(n = nil)
      [random_bytes(n)].pack('m').gsub("\n", '')
    end

    # base64 with "-" and "_" in place of "+" and "/", and without "=" unless
    # padding is true.
    def urlsafe_base64(n = nil, padding = false)
      s = base64(n).gsub('+', '-').gsub('/', '_')
      padding ? s : s.gsub('=', '')
    end

    # An Integer of 0 or more and less than n, for an Integer n of 1 or more.
    # As in mruby-secure-random, n of 0 or less raises NotImplementedError,
    # where CRuby returns a Float.
    def random_number(n = 0)
      raise NotImplementedError, 'SecureRandom.random_number needs a positive Integer' unless 0 < n
      raise ArgumentError, "SecureRandom.random_number needs an Integer, not #{n.class}" unless n.kind_of?(Integer)

      bits = 0
      m = n - 1
      while m > 0
        bits += 1
        m >>= 1
      end
      return 0 if bits == 0

      mask = (1 << bits) - 1
      size = (bits + 7) / 8
      loop do
        v = random_bytes(size).unpack('H*')[0].to_i(16) & mask
        return v if v < n
      end
    end

    # A random UUID of version 4 (RFC 9562), in lowercase.
    def uuid
      b = random_bytes(16).unpack('C*')
      b[6] = (b[6] & 0x0f) | 0x40
      b[8] = (b[8] & 0x3f) | 0x80
      h = b.pack('C*').unpack('H*')[0]
      "#{h[0, 8]}-#{h[8, 4]}-#{h[12, 4]}-#{h[16, 4]}-#{h[20, 12]}"
    end
  end
end

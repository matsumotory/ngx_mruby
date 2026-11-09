# The handler of /gem_digest (test/conf/conf.d/62-gem-digest-secure-random.conf).
# One line per check; test/t/cases/gem_digest_secure_random.rb has the
# expected lines and where each value comes from.

def check
  yield.to_s
rescue Exception => e
  e.class.to_s
end

def gem_digest_hex(s)
  s.unpack('H*')[0]
end

lines = []

# The hashes of "abc" (FIPS 180-2 and RFC 1321) and of "".
lines << check { Digest::MD5.hexdigest('abc') }
lines << check { Digest::SHA1.hexdigest('abc') }
lines << check { Digest::SHA256.hexdigest('abc') }
lines << check { Digest::SHA384.hexdigest('abc') }
lines << check { Digest::SHA512.hexdigest('abc') }
lines << check { Digest::MD5.hexdigest('') }
# RIPEMD160 is in the default provider since OpenSSL 3.0.7; before that,
# Digest::RMD160.new raises NotImplementedError.
lines << check { Digest::RMD160.hexdigest('abc') }

# digest returns the bytes, hexdigest the same bytes in hexadecimal.
lines << check { d = Digest::SHA256.digest('abc'); "#{d.bytesize} #{gem_digest_hex(d)}" }
lines << check { d = Digest::SHA1.new.update('abc').digest; "#{d.bytesize} #{gem_digest_hex(d)}" }

# One million "a" in 1000 calls of update (FIPS 180-2, SHA-256).
lines << check { d = Digest::SHA256.new; 1000.times { d.update('a' * 1000) }; d.hexdigest }

# The aliases and the lengths.
lines << check { d = Digest::SHA256.new; d << 'abc'; [d.to_s, d.length, d.size, d.digest_length, d.block_length].join(' ') }
lines << check { [Digest::MD5.new.block_length, Digest::SHA512.new.block_length, Digest::SHA384.new.digest_length].join(' ') }

# hexdigest leaves the object as it was: more data can follow.
lines << check { d = Digest::SHA256.new.update('ab'); first = d.hexdigest; [first, d.hexdigest == first, d.update('c').hexdigest].join(' ') }

# digest! and hexdigest! return the digest, then start again empty.
lines << check { d = Digest::SHA256.new.update('abc'); [gem_digest_hex(d.digest!), d.hexdigest].join(' ') }
lines << check { d = Digest::SHA256.new.update('abc'); [d.hexdigest!, d.hexdigest].join(' ') }
lines << check { Digest::SHA256.new.update('abc').reset.hexdigest }

# dup copies the data so far.
lines << check { d = Digest::SHA256.new.update('ab'); e = d.dup; e.update('c'); [d.hexdigest, e.hexdigest].join(' ') }

# == with a String compares the hexdigest, with a digest the digests.
lines << check { d = Digest::SHA256.new.update('abc'); [d == Digest::SHA256.hexdigest('abc'), d == Digest::SHA256.new.update('abc'), d == 'abc'].join(' ') }

# A subclass of an algorithm class, and the abstract class.
lines << check { c = Class.new(Digest::SHA256); c.hexdigest('abc') }
lines << check { Digest::Base.new }
lines << check { Digest::SHA256.new.update(1) }

# Digest.file and Digest::Base#file read the file "abc\n".
path = Nginx::Request.new.var.gem_digest_file
lines << check { Digest::SHA256.file(path).hexdigest }
lines << check { Digest::SHA256.new.update('x').reset.file(path).hexdigest }

# HMAC: RFC 4231 test cases 1, 2 and 6, RFC 2202 test case 2, and an empty
# key with empty data.
key1 = "\x0b" * 20
lines << check { Digest::HMAC.hexdigest('Hi There', key1, Digest::SHA256) }
lines << check { Digest::HMAC.hexdigest('Hi There', key1, Digest::SHA384) }
lines << check { Digest::HMAC.hexdigest('Hi There', key1, Digest::SHA512) }
lines << check { Digest::HMAC.hexdigest('what do ya want for nothing?', 'Jefe', Digest::SHA256) }
lines << check { Digest::HMAC.hexdigest('Test Using Larger Than Block-Size Key - Hash Key First', "\xaa" * 131, Digest::SHA256) }
lines << check { Digest::HMAC.hexdigest('what do ya want for nothing?', 'Jefe', Digest::MD5) }
lines << check { Digest::HMAC.hexdigest('what do ya want for nothing?', 'Jefe', Digest::SHA1) }
lines << check { Digest::HMAC.hexdigest('', '', Digest::SHA256) }

# An HMAC object: update and <<, digest and hexdigest more than once, and the
# lengths.
lines << check do
  h = Digest::HMAC.new('Jefe', Digest::SHA256)
  h.update('what do ya want ')
  h << 'for nothing?'
  first = h.hexdigest
  [first, h.hexdigest == first, gem_digest_hex(h.digest) == first, h.digest.bytesize, h.digest_length, h.block_length].join(' ')
end
lines << check { gem_digest_hex(Digest::HMAC.digest('what do ya want for nothing?', 'Jefe', Digest::SHA256)) }
# update after digest goes on from the data so far.
lines << check { h = Digest::HMAC.new('Jefe', Digest::SHA256); h.update('what do ya want '); h.digest; h.update('for nothing?'); h.hexdigest }
lines << check { Digest::HMAC.new('k', Digest::SHA256).dup }
lines << check { Digest::HMAC.new('k', String) }
lines << check { Digest::HMAC.new('k', 'SHA256') }

Nginx.rputs lines.join("\n")

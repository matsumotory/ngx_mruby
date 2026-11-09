t = SimpleTest.new "ngx_mruby test: Digest, Digest::HMAC and SecureRandom of mrbgems/digest and mrbgems/secure-random (test/conf/conf.d/62-gem-digest-secure-random.conf)"

GEM_DIGEST_SECURE_RANDOM_PORT = 18195

def gem_digest_secure_random_lines(t, path)
  res = HttpRequest.new.get base(GEM_DIGEST_SECURE_RANDOM_PORT) + path
  t.assert_equal 200, res.code
  res["body"].split("\n")
end

# The digests of "abc", "ab", "abc\n" and "" (FIPS 180-2 and RFC 1321; the
# others computed with Python's hashlib).
MD5_ABC = '900150983cd24fb0d6963f7d28e17f72'
SHA1_ABC = 'a9993e364706816aba3e25717850c26c9cd0d89d'
SHA256_ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
SHA384_ABC = 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'
SHA512_ABC = 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'
RMD160_ABC = '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'
SHA256_AB = 'fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603'
SHA256_ABC_LF = 'edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb'
SHA256_EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
# HMAC-SHA256 of RFC 4231 test case 2 (key "Jefe").
HMAC_SHA256_JEFE = '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'

t.assert('mrbgems/digest', 'the hashes, the methods of Digest::Base and HMAC against known values') do
  lines = gem_digest_secure_random_lines(t, '/gem_digest')
  t.assert_equal 36, lines.size
  # RIPEMD160 is in the default provider of OpenSSL since 3.0.7: with 3.0.0
  # to 3.0.6, Digest::RMD160.new raises NotImplementedError.
  t.assert_true [RMD160_ABC, 'NotImplementedError'].include?(lines[6]), "Digest::RMD160: #{lines[6]}"
  lines[6] = 'RMD160'
  t.assert_equal [
    MD5_ABC,
    SHA1_ABC,
    SHA256_ABC,
    SHA384_ABC,
    SHA512_ABC,
    'd41d8cd98f00b204e9800998ecf8427e',       # MD5 of ""
    'RMD160',                                 # checked above
    "32 #{SHA256_ABC}",                       # SHA256.digest: 32 bytes
    "20 #{SHA1_ABC}",                         # SHA1#digest: 20 bytes
    'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0', # one million "a" (FIPS 180-2)
    "#{SHA256_ABC} 32 32 32 64",              # to_s, length, size, digest_length, block_length
    '64 128 48',                              # MD5 and SHA512 block_length, SHA384 digest_length
    "#{SHA256_AB} true #{SHA256_ABC}",        # hexdigest twice, then update goes on
    "#{SHA256_ABC} #{SHA256_EMPTY}",          # digest!, then empty
    "#{SHA256_ABC} #{SHA256_EMPTY}",          # hexdigest!, then empty
    SHA256_EMPTY,                             # reset
    "#{SHA256_AB} #{SHA256_ABC}",             # dup copies the data so far
    'true true false',                        # == with a hexdigest, a digest and another String
    SHA256_ABC,                               # a subclass of Digest::SHA256
    'NotImplementedError',                    # Digest::Base.new
    'TypeError',                              # update with an Integer
    SHA256_ABC_LF,                            # Digest::SHA256.file
    SHA256_ABC_LF,                            # Digest::Base#file after reset
    'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7', # RFC 4231 1, SHA-256
    'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6', # RFC 4231 1, SHA-384
    '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854', # RFC 4231 1, SHA-512
    HMAC_SHA256_JEFE,                         # RFC 4231 2, SHA-256
    '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54', # RFC 4231 6, a key of 131 bytes
    '750c783e6ab0b503eaa86e310a5db738',       # RFC 2202 2, HMAC-MD5
    'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79', # RFC 2202 2, HMAC-SHA1
    'b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad', # empty key, empty data (Python's hmac)
    "#{HMAC_SHA256_JEFE} true true 32 32 64", # an HMAC object: hexdigest twice, digest, lengths
    HMAC_SHA256_JEFE,                         # Digest::HMAC.digest
    'RuntimeError',                           # HMAC#dup: "cannot duplicate HMAC"
    'NameError',                              # HMAC.new with a class that is not a digest
    'TypeError',                              # HMAC.new with a String in place of the class
  ], lines
end

t.assert('mrbgems/secure-random', 'the lengths and characters of the values of SecureRandom') do
  lines = gem_digest_secure_random_lines(t, '/gem_secure_random')
  t.assert_equal 16, lines.size
  t.assert_equal [
    '16 32  5',                       # random_bytes: 16 by default, 32, 0 (empty), an object whose to_int is 5
    'true',                           # two calls give other bytes
    'ArgumentError',                  # random_bytes(-1)
    '32 16 true true',                # hex: 32 and 16 digits, lowercase hexadecimal, two calls differ
    '24 true true 4',                 # base64: 24 characters ending with "==", 3 bytes in 4
    '22 true 24 4 43',                # urlsafe_base64: 22 without padding, 24 with it, n bytes
    'true true',                      # random_number(10): Integers in 0...10, not all the same
    '0 true true',                    # random_number(1), and an Integer below 2**100
    'NotImplementedError',            # random_number(0)
    'NotImplementedError',            # random_number(-1)
    'ArgumentError',                  # random_number(1.5)
    '36 ---- 4 true true true',       # uuid: version 4, variant 10, hexadecimal, two calls differ
    'dc 3A== 3A 3A== 74eb97c9-1870-4cdf-844a-31d55b0e4251', # a subclass with fixed bytes
    'true',                           # SecureRandom is a class
  ], lines[0..-3]
  t.assert_equal 32, lines[-2].size
  t.assert_equal 36, lines[-1].size
end

t.assert('mrbgems/secure-random', 'two requests get other values') do
  first = gem_digest_secure_random_lines(t, '/gem_secure_random')
  second = gem_digest_secure_random_lines(t, '/gem_secure_random')
  t.assert_not_equal first[-2], second[-2]
  t.assert_not_equal first[-1], second[-1]
end

t.report

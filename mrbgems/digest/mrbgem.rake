# Digest (MD5, RMD160, SHA1, SHA256, SHA384, SHA512) and Digest::HMAC on the
# EVP and EVP_MAC APIs of OpenSSL 3, in place of iij/mruby-digest. The gem
# keeps that gem's name, so that a third-party gem that declares a
# dependency on mruby-digest uses this one; do not add iij/mruby-digest to
# the same build.
MRuby::Gem::Specification.new('mruby-digest') do |spec|
  spec.license = 'MIT'
  spec.authors = 'MATSUMOTO Ryosuke'
  spec.summary = 'Digest and Digest::HMAC on OpenSSL 3'
  spec.add_dependency('mruby-io', core: 'mruby-io')

  spec.linker.libraries << 'crypto'
end

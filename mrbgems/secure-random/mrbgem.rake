# SecureRandom on RAND_bytes of OpenSSL, in place of
# monochromegane/mruby-secure-random. The gem keeps that gem's name, so that
# a third-party gem that declares a dependency on mruby-secure-random uses
# this one; do not add monochromegane/mruby-secure-random to the same build.
MRuby::Gem::Specification.new('mruby-secure-random') do |spec|
  spec.license = 'MIT'
  spec.authors = 'MATSUMOTO Ryosuke'
  spec.summary = 'SecureRandom on RAND_bytes of OpenSSL 3'
  spec.add_dependency('mruby-pack', core: 'mruby-pack')

  spec.linker.libraries << 'crypto'
end

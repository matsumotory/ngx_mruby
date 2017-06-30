MRuby::Gem::Specification.new('auto-ssl') do |spec|
  spec.license = 'MIT'
  spec.authors = 'MATSUMOTO Ryosuke'
  spec.add_dependency('mruby-io', :github => 'iij/mruby-io')
  spec.add_dependency('mruby-acme-client', :github => 'pyama86/mruby-acme-client')
  spec.add_dependency('mruby-sleep', :github => 'matsumotory/mruby-sleep')
end

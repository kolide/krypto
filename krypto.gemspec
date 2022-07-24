# frozen_string_literal: true

Gem::Specification.new do |s|
  s.name = 'krypto'
  s.version     = '0.1.0'
  s.summary     = 'Cross Platform Crypto Tools'
  s.description = ''
  s.authors     = ['Kolide Inc.']
  s.email       = ['engineering@kolide.com']
  s.files       = Dir['{lib}/**/*'] + ['LICENSE', 'README.md']
  s.homepage    = 'https://github.com/kolide/krypto'
  s.license     = '???'

  s.required_ruby_version = '>= 3.1.2'

  s.add_runtime_dependency 'openssl'
  s.add_development_dependency 'msgpack', '~> 1.5'
  s.metadata['rubygems_mfa_required'] = 'true'
end

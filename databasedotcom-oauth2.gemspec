# -*- encoding: utf-8 -*-
require File.expand_path('../lib/databasedotcom-oauth2/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["Richard Vanhook"]
  gem.email         = ["rvanhook@salesforce.com"]
  gem.description   = %q{OAuth2 Rack Middleware for database.com/salesforce.com.}
  gem.summary       = %q{OAuth2 Rack Middleware for database.com/salesforce.com.}
  gem.homepage      = "https://github.com/richardvanhook/databasedotcom-oauth2"

  gem.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  gem.files         = `git ls-files`.split("\n")
  gem.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.name          = "databasedotcom-oauth2"
  gem.require_paths = ["lib"]
  gem.version       = Databasedotcom::OAuth2::VERSION

  gem.add_dependency 'addressable'
  gem.add_dependency 'hashie'
  gem.add_dependency 'databasedotcom'
  gem.add_dependency 'oauth2'

  gem.add_development_dependency 'rspec', '~> 2.7'
  gem.add_development_dependency 'rack-test'
  gem.add_development_dependency 'simplecov'
  gem.add_development_dependency 'webmock'
end

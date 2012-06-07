require 'oauth2'
require 'singleton'

module Databasedotcom
  module OAuth2
    class Configuration
      include Singleton
      attr_writer :on_failure
      attr_accessor :endpoints
    end

    def self.config
      Configuration.instance
    end

    def self.configure
      yield config
    end

  end
end

require_relative 'oauth2/web_server_flow'
require_relative 'oauth2/web_server_flow_demo_app'

module OAuth2
  class AccessToken
    def to_hash
      hsh = self.params.dup
      hsh[:access_token]  = self.token
      hsh[:refresh_token] = self.refresh_token
      hsh[:expires_in]    = self.expires_in
      hsh[:expires_at]    = self.expires_at
      hsh[:mode]          = self.options[:mode]
      hsh[:header_format] = self.options[:header_format]
      hsh[:param_name]    = self.options[:param_name]
      hsh
    end
  end
end

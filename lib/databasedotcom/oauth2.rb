require_relative "oauth2/web_server_flow"
require_relative "oauth2/web_server_flow_demo_app"

=begin
require "singleton"
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
=end


require "sinatra/base"
require "rack/ssl" unless ENV['RACK_ENV'] == "development"
require "base64"
require "databasedotcom"
require "haml"

module Databasedotcom
  module OAuth2
    
    class WebServerFlowDemoApp < Sinatra::Base

      configure do
        enable :logging
        set :app_file,        __FILE__
        set :root,            File.expand_path("../../../..",__FILE__)
        set :port,            ENV['PORT']
        set :raise_errors,    Proc.new { false }
        set :show_exceptions, true
      end

      # Defines endpoints available.
      endpoints = {
        "login.salesforce.com" => {
          :key      => ENV['SALESFORCE_KEY'], 
          :secret   => ENV['SALESFORCE_SECRET']}, 
        "test.salesforce.com" => {
          :key      => ENV['SALESFORCE_SANDBOX_KEY'],
          :secret   => ENV['SALESFORCE_SANDBOX_SECRET']}
      }
      endpoints.default = endpoints["login.salesforce.com"]

      # It's uber important that the below encrypted cookie secret
      #   is sufficiently strong.  Suggest running following to set appropriately:
      # $ ruby -ropenssl -rbase64 -e "puts Base64.strict_encode64(OpenSSL::Random.random_bytes(16).to_str)"
      token_encryption_key = Base64.strict_decode64(ENV['COOKIE_SECRET'])

      use Rack::SSL unless ENV['RACK_ENV'] == "development"
      use Rack::Session::Cookie
      use Databasedotcom::OAuth2::WebServerFlow, 
        :endpoints            => endpoints, 
        :token_encryption_key => token_encryption_key

      get '/authenticate' do
    	  if unauthenticated?
          haml :terms, :layout => :login, :locals => { :url => '/auth/salesforce', :state => params[:state] }
        else
          redirect to(sanitize_state(params[:state])) 
        end
      end

      get '/terms' do
        haml :terms
      end
      
      get '/*' do
        authenticate!
        haml :info, :locals => {:userinfo => userinfo}
      end
      
      helpers do
        def client
          env['databasedotcom.client']
        end

        def userinfo
          token = env['databasedotcom.credentials']
          userinfo = nil
          userinfo = token.post(token['id']).parsed unless token.nil?
          userinfo
        end

      	def unauthenticated?
      	  client.nil?
    	  end

      	def authenticate!
      	  if unauthenticated?
            uri = Addressable::URI.new
            uri.query_values = {:state => request.fullpath}
        	  redirect to("/authenticate?#{uri.query}") 
      	  end
      	end

        def sanitize_state(state = nil)
          state = "/" if state.nil? || state.strip.empty?
          state
        end

      end

    end
    
  end
end

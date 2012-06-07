require "oauth2"
require "addressable/uri"
require "databasedotcom"

module Databasedotcom
  
  class Client
    
    def self.from_token(token)
      client = nil
      unless token.nil?
        client = self.new({
          :client_id     => token.client.id, 
          :client_secret => token.client.secret, 
          :host          => token.client.site
        })
        m = token["id"].match(/\/id\/([^\/]+)\/([^\/]+)$/)
        org_id        = m[1] rescue nil
        user_id       = m[2] rescue nil
        client.set_org_and_user_id(org_id,user_id)
        client.version       = "23.0"
        client.instance_url  = token.client.site
        client.oauth_token   = token.token
        client.refresh_token = token.refresh_token
      end
      client
    end
    
    def set_org_and_user_id(orgid, userid)
      @org_id        = orgid
      @user_id       = userid
    end

  end

  module OAuth2
    
    class WebServerFlow

      SESSION_CREDS_KEY  = "databasedotcom.credentials"
      SESSION_CLIENT_KEY = "databasedotcom.client"
      
      def initialize(app, options = nil)
        @app = app       
        unless options.nil?
          @endpoints            = WebServerFlow.sanitize_endpoints(options[:endpoints])
          @token_encryption_key = options[:token_encryption_key]
        end

        fail "\n\ndatabasedotcom-oauth2 initialization error!  :endpoints parameter " \
          + "is invalid.  Do something like this:\n\nuse Databasedotcom::OAuth2::Web" \
          + "ServerFlow, :endpoints => {\"login.salesforce.com\" => { :key => CLIENT" \
          + "_ID_FROM_DATABASEDOTCOM, :secret => CLIENT_SECRET_FROM_DATABASEDOTCOM }" \
          + "}\n\n"                                                                   \
          if !@endpoints.is_a?(Hash) || @endpoints.empty?
            
        fail "\n\ndatabasedotcom-oauth2 initialization error!  :token_encryption_key " \
          + "is invalid.  Do something like this:\n\nuse Databasedotcom::OAuth2::WebS" \
          + "erverFlow, :token_encryption_key => YOUR_VERY_LONG_VERY_RANDOM_SECRET_KE" \
          + "Y_HERE\n\nTo generate a sufficiently long random key, use following comm" \
          + "and:\n\n$ ruby -ropenssl -rbase64 -e \"puts Base64.strict_encode64(OpenS" \
          + "SL::Random.random_bytes(16).to_str)\"\n\n"                                \
          if @token_encryption_key.nil? || @token_encryption_key.size < 16
      end                

      def call(env)
        dup.call!(env)
      end

      def call!(env)
        @env = env
        return authorize_call if on_authorize_path?
        return callback_call  if on_callback_path?
        parse_access_code_from_session_if_present
        @app.call(env)
      end

      private

      def on_authorize_path?
        on_path? "/auth/salesforce"
      end

      def authorize_call
        endpoint = request.params["endpoint"]
        keys = @endpoints[endpoint] #if endpoint not found, default will be used
        endpoint = @endpoints.invert[keys]
        mydomain = WebServerFlow.parse_domain(request.params["mydomain"])
        state = Addressable::URI.parse(request.params["state"] || "/")
        state.query_values={} unless state.query_values
        state.query_values= state.query_values.merge({:endpoint => endpoint, :mydomain => mydomain})
        auth_params = {
          :redirect_uri  => "#{ENV['ORIGIN']}/auth/salesforce/callback",
          :display       => "touch",
          :immediate     => false,
          :scope         => "id api refresh_token",
          :state         => state.to_s
        }
        redirect oauth2_client(mydomain.nil? ? endpoint : mydomain, 
          keys[:key], 
          keys[:secret] \
        ).auth_code.authorize_url(auth_params)
      end
      
      def on_callback_path?
        on_path? "/auth/salesforce/callback"
      end

      def callback_call
        state = Addressable::URI.parse(request.params["state"] || "/")
        #puts "state1: #{state}"
        state.query_values= {} if state.query_values.nil?
        state_params = state.query_values.dup
        endpoint = state_params.delete("endpoint")
        fail "endpoint param cannot blank" if endpoint.nil?
        keys = @endpoints[endpoint]
        fail "endpoint #{endpoint} not found" if keys.nil?
        code = request.params["code"]
        #puts "code: #{code}"
        mydomain = state_params.delete("mydomain")
        state.query_values= state_params
        #puts "endpoint: #{endpoint}"
        #puts "mydomain: #{mydomain}"
        #puts "state2: #{state}"
        #puts "state.query_values: #{state.query_values}"

        oauth2_client = ::OAuth2::Client.new(
           keys[:key], keys[:secret], :site => "https://#{mydomain.nil? || mydomain.empty? ? endpoint : mydomain}",
           :authorize_url => '/services/oauth2/authorize',
           :token_url     => '/services/oauth2/token'
        )
        access_token = oauth2_client.auth_code.get_token(code, :redirect_uri => "#{ENV['ORIGIN']}/auth/salesforce/callback")
        access_token.options[:mode] = :query
        access_token.options[:param_name] = :oauth_token
        @env["rack.session"] ||= {}
        @env["rack.session"][SESSION_CREDS_KEY] = access_token.to_hash.merge({:endpoint => endpoint})
        #puts "###callback rack.session #{@env["rack.session"]}"
        puts "redirecting to #{state.to_str}..."
        redirect state.to_str
      end

      def parse_access_code_from_session_if_present
        access_token_hash = (@env["rack.session"] || {})[SESSION_CREDS_KEY]
        puts "access_token_hash #{access_token_hash}"
        unless access_token_hash.nil?
          endpoint = access_token_hash[:endpoint]
          instance_url = access_token_hash["instance_url"]
          keys = @endpoints[endpoint]
          unless keys.nil?
            oauth2_client = ::OAuth2::Client.new(
               keys[:key], keys[:secret], :site => instance_url,
               :authorize_url => '/services/oauth2/authorize',
               :token_url     => '/services/oauth2/token'
            )
            @env[SESSION_CREDS_KEY]  = ::OAuth2::AccessToken.from_hash(oauth2_client,access_token_hash.dup)
            @env[SESSION_CLIENT_KEY] = ::Databasedotcom::Client.from_token(@env[SESSION_CREDS_KEY])
          end
        end
      end

      def parse_user_id_and_org_id_from_identity_url(identity_url)
      end

      def on_path?(path)
        current_path.casecmp(path) == 0
      end

      def current_path
        request.path_info.downcase.sub(/\/$/,'')
      end

      def query_string
        request.query_string.empty? ? "" : "?#{request.query_string}"
      end

      def request
        @request ||= Rack::Request.new(@env)
      end
      
      def oauth2_client(site_domain, client_id, client_secret)
        oauth2_client = ::OAuth2::Client.new(
           client_id, 
           client_secret, 
           :site          => "https://#{site_domain}",
           :authorize_url => '/services/oauth2/authorize',
           :token_url     => '/services/oauth2/token'
        )
      end
      
      def redirect(uri)
        r = Rack::Response.new
        r.write("Redirecting to #{uri}...")
        r.redirect(uri)
        r.finish
      end
      
      def self.sanitize_endpoints(endpoints = nil)
        endpoints = {} unless endpoints.is_a?(Hash)
        endpoints = endpoints.dup
        endpoints.keep_if do |key,value| 
          value.is_a?(Hash)       &&
          value.has_key?(:key)    && 
          value.has_key?(:secret) &&
          !value[:key].nil?       && 
          !value[:secret].nil?    && 
          !value[:key].empty?     && 
          !value[:secret].empty?
        end
        #set random default if default isn't already populated
        if !endpoints.empty? && endpoints.default.nil?
          endpoints.default = endpoints[endpoints.keys.first]
        end
        endpoints
      end

      def self.parse_domain(url = nil)
        unless url.nil?
          url = "https://" + url if (url =~ /http[s]?:\/\//).nil?
          begin
            url = Addressable::URI.parse(url)
          rescue Addressable::URI::InvalidURIError
            url = nil
          end
          url = url.host unless url.nil?
          url.strip! unless url.nil?
        end
        url = nil if url && url.strip.empty?
        url
      end

    end
    
  end
end

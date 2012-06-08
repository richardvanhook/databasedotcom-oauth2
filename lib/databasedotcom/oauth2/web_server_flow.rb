require "oauth2"
require "addressable/uri"
require "databasedotcom"
require "cgi"
require "base64"
require "openssl"

module Databasedotcom
  
  module OAuth2
    
    class WebServerFlow

      TOKEN_KEY  = "databasedotcom.token"
      CLIENT_KEY = "databasedotcom.client"
      
      def initialize(app, options = nil)
        @app = app       
        unless options.nil?
          @endpoints            = self.class.sanitize_endpoints(options[:endpoints])
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
        materialize_token_and_client_from_session_if_present
        @app.call(env)
      end

      private

      def on_authorize_path?
        on_path? "/auth/salesforce"
      end

      def authorize_call
        #determine endpoint via param; but if blank, use default
        endpoint = request.params["endpoint"] #get endpoint from http param
        keys     = @endpoints[endpoint]       #if endpoint not found, default will be used
        endpoint = @endpoints.invert[keys]    #re-lookup endpoint in case original param was bogus

        #check if my domain is present and add .my.salesforce.com
        mydomain = self.class.parse_domain(request.params["mydomain"])
        mydomain = nil unless mydomain.nil? || !mydomain.strip.empty?
        mydomain = mydomain.split(/\./).first + ".my.salesforce.com" unless mydomain.nil?

        #add endpoint to relay state so callback knows which keys to use
        state = Addressable::URI.parse(request.params["state"] || "/")
        state.query_values={} unless state.query_values
        state.query_values= state.query_values.merge({:endpoint => endpoint})
        
        #build params hash to be passed to ouath2 authorize redirect url
        auth_params = {
          :redirect_uri  => "#{full_host}/auth/salesforce/callback",
          :state         => state.to_s
        }
        scope = (self.class.param_repeated(request.url, :scope) || []).join(" ")
        auth_params[:scope]     = scope                       unless scope.nil? || scope.strip.empty?
        auth_params[:display]   = request.params["display"]   unless request.params["display"].nil?
        auth_params[:immediate] = request.params["immediate"] unless request.params["immediate"].nil?

        #do redirect
        redirect client(mydomain || endpoint, keys[:key], keys[:secret]).auth_code.authorize_url(auth_params)
      end
      
      def on_callback_path?
        on_path? "/auth/salesforce/callback"
      end

      def callback_call
        #grab authorization code
        code = request.params["code"]
        
        #grab and remove endpoint from relay state
        #upon successful retrieval of token, state is url where user will be redirected to
        state = Addressable::URI.parse(request.params["state"] || "/")
        state.query_values= {} if state.query_values.nil?
        state_params = state.query_values.dup
        endpoint = state_params.delete("endpoint")
        keys = @endpoints[endpoint]
        state.query_values= state_params

        #do callout to retrieve token
        access_token = client(endpoint, keys[:key], keys[:secret]).auth_code.get_token(code, 
          :redirect_uri => "#{full_host}/auth/salesforce/callback")
        access_token.options[:mode] = :query
        access_token.options[:param_name] = :oauth_token
        
        #populate session with serialized, encrypted token
        #will be used later to materialize actual token and databasedotcom client handle
        @env["rack.session"] ||= {} #in case session is nil
        @env["rack.session"][TOKEN_KEY] = self.class.encrypt(@token_encryption_key, access_token.to_hash.merge({:endpoint => endpoint}))
        redirect state.to_str
      end

      def materialize_token_and_client_from_session_if_present
        access_token_hash = nil
        begin
          access_token_hash = self.class.decrypt(@token_encryption_key, (@env["rack.session"] || {})[TOKEN_KEY])
        rescue
          return
        end
        unless access_token_hash.nil?
          endpoint = access_token_hash[:endpoint]
          instance_url = access_token_hash["instance_url"]
          keys = @endpoints[endpoint]
          unless keys.nil?
            @env[TOKEN_KEY]  = ::OAuth2::AccessToken.from_hash(client(instance_url, keys[:key], keys[:secret]),access_token_hash.dup)
            @env[CLIENT_KEY] = ::Databasedotcom::Client.from_token(@env[TOKEN_KEY])
          end
        end
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
      
      def full_host
        full_host = ENV['ORIGIN']
        if full_host.nil? || full_host.strip.empty?
          full_host = URI.parse(request.url.gsub(/\?.*$/,''))
          full_host.path = ''
          full_host.query = nil
          #sometimes the url is actually showing http inside rails because the other layers (like nginx) have handled the ssl termination.
          full_host.scheme = 'https' if(request.env['HTTP_X_FORWARDED_PROTO'] == 'https')          
          full_host = full_host.to_s
        end
        full_host
      end
      
      def client(site, client_id, client_secret)
        ::OAuth2::Client.new(
           client_id, 
           client_secret, 
           :site          => "https://#{self.class.parse_domain(site)}",
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
      
      def self.encrypt(secret, data)
        plain_text_before = [Marshal.dump(data)].pack("m*")
        plain_text_before = "#{plain_text_before}--#{OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, secret, plain_text_before)}"
        aes = OpenSSL::Cipher::Cipher.new('aes-128-cbc').encrypt
        aes.key = secret
        iv = OpenSSL::Random.random_bytes(aes.iv_len)
        aes.iv = iv
        cipher_text = [iv + (aes.update(plain_text_before) << aes.final)].pack('m0')
        cipher_text
      end

      def self.decrypt(secret, cipher_text)
        data = nil
        unless cipher_text.nil?
          plain_text_after = cipher_text.unpack('m0').first
          aes = OpenSSL::Cipher::Cipher.new('aes-128-cbc').decrypt
          aes.key = secret
          iv = plain_text_after[0, aes.iv_len]
          aes.iv = iv
          crypted_text = plain_text_after[aes.iv_len..-1]
          return nil if crypted_text.nil? || iv.nil?
          plain_text_after = aes.update(crypted_text) << aes.final
          data = plain_text_after.unpack("m*").first
          data = Marshal.load(data)
        end
        data
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

      def self.param_repeated(url = nil, param_name = nil)
        return_value = nil
        unless url.nil? || url.strip.empty? || param_name.nil?
          url = Addressable::URI.parse(url)
          param_name = param_name.to_s if param_name.is_a?(Symbol)
          query_values = url.query_values(:notation => :flat_array)
          unless query_values.nil? || query_values.empty?
            return_value = query_values.select{|param| param.is_a?(Array) && param.size >= 2 && param[0] == param_name}.collect{|param| param[1]}
          end
        end
        return_value
      end

    end
    
  end
end

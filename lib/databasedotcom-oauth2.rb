require "cgi"
require "base64"
require "openssl"
require "addressable/uri"
require "hashie"
require "gibberish"
require "databasedotcom"
require "oauth2"

module Databasedotcom
  
  class Client
    
    attr_accessor :org_id
    attr_accessor :user_id
    attr_accessor :endpoint
    attr_accessor :last_seen
    attr_accessor :logout_flag
    
    def logout
      @logout_flag = true
    end

  end

  module OAuth2
    CLIENT_KEY = "databasedotcom.client"
    
    module Helpers
      def client
        env[CLIENT_KEY]
      end

    	def unauthenticated?
    	  client.nil?
  	  end

    	def authenticated?
    	  !unauthenticated?
    	end
    	
    	def me
    	  @me ||= ::Hashie::Mash.new(Databasedotcom::Chatter::User.find(client, "me").raw_hash)
  	  end
    end

    class WebServerFlow

      def initialize(app, options = nil)
        @app = app       
        unless options.nil?
          @endpoints            = self.class.sanitize_endpoints(options[:endpoints])
          @token_encryption_key = options[:token_encryption_key]
          @path_prefix          = options[:path_prefix]
          @on_failure           = options[:on_failure]
          @display              = options[:display]
          @immediate            = options[:immediate]
          @prompt               = options[:prompt]
          @scope                = options[:scope]
          @display_override     = options[:display_override]   || false
          @immediate_override   = options[:immediate_override] || false
          @prompt_override      = options[:prompt_override]    || false
          @scope_override       = options[:scope_override]     || false
          @api_version          = options[:api_version]        || "25.0"
          @debugging            = options[:debugging]          || false
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
            
        @path_prefix = "/auth/salesforce" unless @path_prefix.is_a?(String) && !@path_prefix.strip.empty?
        @on_failure = nil unless @on_failure.is_a?(Proc)
      end                

      def call(env)
        dup.call!(env)
      end

      def call!(env)
        @env = env
        begin
          return authorize_call if on_authorize_path?
          return callback_call  if on_callback_path?
        rescue Exception => e
          self.class._log_exception(e)
          if @on_failure.nil?
            new_path = Addressable::URI.parse(@path_prefix + "/failure")
            new_path.query_values={:message => e.message, :state => request.params['state']}
            return [302, {'Location' => new_path.to_s, 'Content-Type'=> 'text/html'}, []]
          else
            return @on_failure.call(env,e)
          end
        end
        @env[CLIENT_KEY] = retrieve_client_from_session
        status, headers, body = @app.call(env)
        save_client_to_session(@env[CLIENT_KEY])
        [status, headers, body]
      end

      private

      def on_authorize_path?
        on_path?(@path_prefix)
      end

      def authorize_call
        puts "==================\nauthorize phase\n==================\n" if @debugging
        #determine endpoint via param; but if blank, use default
        endpoint = request.params["endpoint"] #get endpoint from http param
        keys     = @endpoints[endpoint]       #if endpoint not found, default will be used
        endpoint = @endpoints.invert[keys]    #re-lookup endpoint in case original param was bogus
        mydomain = self.class.sanitize_mydomain(request.params["mydomain"])

        #add endpoint to relay state so callback knows which keys to use
        request.params["state"] ||= "/"
        state = Addressable::URI.parse(request.params["state"])
        state.query_values={} unless state.query_values
        state.query_values= state.query_values.merge({:endpoint => endpoint})

        puts "(1) endpoint: #{endpoint}\n(2) mydomain: #{mydomain}\n(3) state: #{state.to_str}" if @debugging
        
        #build params hash to be passed to ouath2 authorize redirect url
        auth_params = {
          :redirect_uri  => "#{full_host}#{@path_prefix}/callback",
          :state         => state.to_str
        }
        auth_params[:display]   = @display   unless @display.nil?
        auth_params[:immediate] = @immediate unless @immediate.nil?
        auth_params[:prompt]    = @prompt    unless @prompt.nil?
        auth_params[:scope]     = @scope     unless @scope.nil? || @scope.strip.empty?

        #overrides
        overrides = {}
        overrides[:display]   = request.params["display"]   unless !@display_override   || request.params["display"].nil?
        overrides[:immediate] = request.params["immediate"] unless !@immediate_override || request.params["immediate"].nil?
        if @prompt_override
          prompt = (self.class.param_repeated(request.url, :prompt) || []).join(" ")
          overrides[:prompt] = prompt unless prompt.nil? || prompt.strip.empty?
        end
        if @scope_override
          scope = (self.class.param_repeated(request.url, :scope) || []).join(" ")
          overrides[:scope] = scope unless scope.nil? || scope.strip.empty?
        end
        auth_params.merge!(overrides)
        
        #do redirect
        redirect_url = client(mydomain || endpoint, keys[:key], keys[:secret]).auth_code.authorize_url(auth_params)
        puts "(4) redirecting to #{redirect_url}..." if @debugging
        redirect redirect_url
      end
      
      def on_callback_path?
        on_path?(@path_prefix + "/callback")
      end

      def callback_call
        puts "==================\ncallback phase\n==================\n" if @debugging
        #check for error
        callback_error         = request.params["error"]         
        callback_error_details = request.params["error_description"]
        fail "#{callback_error} #{callback_error_details}" unless callback_error.nil? || callback_error.strip.empty? 
                
        #grab authorization code
        code = request.params["code"]
        #grab and remove endpoint from relay state
        #upon successful retrieval of token, state is url where user will be redirected to
        request.params["state"] ||= "/"
        state = Addressable::URI.parse(request.params["state"])
        state.query_values= {} if state.query_values.nil?
        state_params = state.query_values.dup
        endpoint = state_params.delete("endpoint")
        keys = @endpoints[endpoint]
        puts "(1) endpoint #{endpoint}" if @debugging
        puts "(2) keys #{keys}" if @debugging
        state.query_values= state_params
        state = state.to_s
        state.sub!(/\?$/,"") unless state.nil?
        puts "(3) endpoint: #{endpoint}\nstate: #{state.to_str}\nretrieving token" if @debugging

        #do callout to retrieve token
        access_token = client(endpoint, keys[:key], keys[:secret]).auth_code.get_token(code, 
          :redirect_uri => "#{full_host}#{@path_prefix}/callback")
        puts "(4) access_token immediatly post get token call #{access_token.inspect}" if @debugging
        
        client = self.class.client_from_oauth_token(access_token)
        client.endpoint = endpoint
        puts "(5) client from token: #{client.inspect}" if @debugging
        save_client_to_session(client)
        puts "(6) session_client \n#{session_client}" if @debugging
        redirect state.to_str
      end

      def save_client_to_session(client)
        puts "==========================\nsave_client_to_session\n==========================\n" if @debugging
        puts "(1) client as stored in session \n#{session_client}" if @debugging
        puts "(2) client to save: #{client.inspect}" if @debugging
        unless client.nil?
          new_session_client = nil
          unless client.logout_flag
            # Zero out client id and secret; will re-populate later when client
            #   is reloaded.  Should be safe to store client id and secret inside
            #   encrypted client; however, out of an abundance of caution (and b/c
            #   it just makes sense), client id and secret will never be written
            #   to session but only stored via @endpoints variable server side.
            client.client_id     = nil
            client.client_secret = nil
            client.version       = nil
            client.debugging     = nil
            client.last_seen     = Time.now
            new_session_client = Gibberish::AES.new(@token_encryption_key).encrypt(Marshal.dump(client))
          end
          if new_session_client != session_client
            session_client_put(new_session_client)
          end
        end
        puts "(3) client as stored in session \n#{session_client}" if @debugging

      end

      def retrieve_client_from_session
        puts "==========================\nretrieve_client_from_session\n==========================\n" if @debugging
        puts "(1) session_client \n#{session_client}" if @debugging
        client = nil
        begin
          client = Marshal.load(Gibberish::AES.new(@token_encryption_key).decrypt(session_client)) unless session_client.nil?
        rescue Exception => e
          puts "Exception FYI"
          self.class._log_exception(e)
        end
        unless client.nil?
          keys = @endpoints[client.endpoint]
          if @debugging
            puts "(2) client #{client.inspect}" 
            puts "(3) client.endpoint #{client.endpoint}"
            puts "(4) keys #{keys}"
          end
          if keys.nil?
            client = nil
          else
            client.client_id     = keys[:key]
            client.client_secret = keys[:secret]
            client.version       = @api_version
            client.debugging     = @debugging
          end
          puts "(5) client #{client.inspect}" if @debugging
        end
        client
      end
      
      def request
        @request ||= Rack::Request.new(@env)
      end
      
      def session
        @env["rack.session"] ||= {} #in case session is nil
        @env["rack.session"]
      end

      def session_client
        session[CLIENT_KEY]
      end

      def session_client_put(value)
        session[CLIENT_KEY] = value
      end

      def on_path?(path)
        current_path.casecmp(path) == 0
      end

      def current_path
        request.path_info.downcase.sub(/\/$/,'')
      end

      def full_host
        full_host = ENV['ORIGIN']
        if full_host.nil? || full_host.strip.empty?
          full_host = URI.parse(request.url.gsub(/\?.*$/,''))
          full_host.path = ''
          full_host.query = nil
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
      
      class << self

        def parse_domain(url = nil)
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

        def client_from_oauth_token(token)
          c = nil
          unless token.nil?
            c = Databasedotcom::Client.new
            m = token["id"].match(/\/id\/([^\/]+)\/([^\/]+)$/)
            c.org_id        = m[1] rescue nil
            c.user_id       = m[2] rescue nil
            c.instance_url   = token.params["instance_url"]
            c.host           = parse_domain(c.instance_url)
            c.oauth_token    = token.token
            c.refresh_token  = token.refresh_token
          end
          c
        end

        def _log_exception(exception)
          STDERR.puts "\n\n#{exception.class} (#{exception.message}):\n    " +
            exception.backtrace.join("\n    ") +
            "\n\n"
        end

        def sanitize_mydomain(mydomain)
            mydomain = parse_domain(mydomain)
            mydomain = nil unless mydomain.nil? || !mydomain.strip.empty?
            mydomain = mydomain.split(/\.my\.salesforce\.com/).first + ".my.salesforce.com" unless mydomain.nil?
            mydomain
        end

        def sanitize_endpoints(endpoints = nil)
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

        def param_repeated(url = nil, param_name = nil)
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
end

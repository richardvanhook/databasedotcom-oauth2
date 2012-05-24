module Salesforce
  module OAuth2
    
    class WebServerFlow
      def initialize(app)
        @app = app       
      end                
      def call(env)
        @app.call(env)
      end
    end
    
  end
end

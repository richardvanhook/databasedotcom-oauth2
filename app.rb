module Salesforce
  module OAuth2
    class WebServerFlowDemoApp
      def call(env)
        [200, {"Content-Type" => "text/plain"}, ["Ola!"]]
      end
    end
  end
end

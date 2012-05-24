require "sinatra/base"

module Salesforce
  module OAuth2
    
    class WebServerFlowDemoApp < Sinatra::Base
      get '/*' do
        [200, {"Content-Type" => "text/plain"}, ["Ola!"]]
      end
    end
    
  end
end

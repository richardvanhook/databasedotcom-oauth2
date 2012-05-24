#\ -w -p 5000
require './lib/salesforce/oauth2'
use Rack::CommonLogger
use Salesforce::OAuth2::WebServerFlow
run Salesforce::OAuth2::WebServerFlowDemoApp.new
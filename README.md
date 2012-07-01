What is databasedotcom-oauth2?
------------------------------
* an extension of the [databasedotcom](https://rubygems.org/gems/databasedotcom) gem that simplifies authentication and authorization with [salesforce.com](http://salesforce.com/) for Ruby web apps via OAuth 2.0
* a Ruby gem intended to run as Rack Middleware
* an alternative to using [OmniAuth](http://www.omniauth.org/) and the corresponding [omniauth-salesforce](https://rubygems.org/gems/omniauth-salesforce) gem.

When and why should I use it instead of OmniAuth?
---------------------------------------------------------------
Many Ruby web apps integrated with [salesforce.com](http://salesforce.com/) need more than just identification, they also need to __interact__ with [salesforce.com](http://salesforce.com/) via the databasedotcom gem.  Both OmniAuth and databasedotcom-oauth2 provide identification; however, databasedotcom-oauth2 makes the interaction part easier. 

Specifically, databasedotcom-oauth2:

* allows multiple saleforce.com endpoints (production, sandbox, etc.)
* supports configuration of scope, display, and immediate OAuth 2.0 parameters
* supports My Domain
* maintains an encrypted OAuth 2.0 token in whatever session store you choose (Cookie, Pool, etc)
* materializes a databasedotcom client upon each request (using the token in session)
* provides a mixin for your app containing utility methods like unauthenticated?, client, etc.

Demos
-------

**<a href="https://db-oauth2-sinatra-basic.herokuapp.com" target="_blank">Simple example using Sinatra</a>**&nbsp;&nbsp;<a href="https://github.com/richardvanhook/databasedotcom-oauth2-sinatra-basic" target="_blank">view source on github</a>

**<a href="https://db-oauth2-sinatra-jqm.herokuapp.com" target="_blank">In-depth configuration with JQuery Mobile</a>**&nbsp;&nbsp;<a href="https://github.com/richardvanhook/databasedotcom-oauth2-sinatra-jqm" target="_blank">view source on github</a>

Usage
-------

### Required 

`:token_encryption_key` & `:endpoints` are required.  databasedotcom-oauth2 encrypts oauth2 token using `:token_encryption_key` and stores it in rack.session for further use.  `:endpoints` defines the server endpoints to be available; multiple can be specified but at least one is required.  

<pre class="brush: ruby">
  use Databasedotcom::OAuth2::WebServerFlow, 
    :token_encryption_key => TOKEN_ENCRYPTION_KEY,
    :endpoints            => {"login.salesforce.com" => {:key => CLIENT_ID, :secret => CLIENT_SECRET}}
</pre>  

```ruby
```

### Multiple Endpoints 

```ruby
use Databasedotcom::OAuth2::WebServerFlow, 
  :endpoints            => {"login.salesforce.com" => {:key => CLIENT_ID1, :secret => CLIENT_SECRET1},
                            "test.salesforce.com"  => {:key => CLIENT_ID2, :secret => CLIENT_SECRET2}}
```
### Authentication Options
```ruby
use Databasedotcom::OAuth2::WebServerFlow, 
  :scope                => "full",  #default is "id api refresh_token"
  :display              => "touch", #default is "page"
  :immediate            => true     #default is false
  :scope_override       => true,    #default is false
  :display_override     => true,    #default is false
  :immediate_override   => true,    #default is false
```

Required Configuration Parameters
-----------------------------------

* **`:endpoints`**

    Hash of remote access applications; at least one is required.  Values must be generated via salesforce at Setup > App Setup > Develop > Remote Access.  Only one remote access application is needed for production, sandbox, or pre-release; separate entries are not necessary for My Domain.

    Example:
    ```ruby
    :endpoints => {"login.salesforce.com" => {:key => "replace me", :secret => "replace me"}
                   "test.salesforce.com"  => {:key => "replace me", :secret => "replace me"}}
     ```

     *Default:* nil

* **`:token_encryption_key`**

    Encrypts OAuth 2.0 token prior to persistence in session store.  Any Rack session store can be used:  Rack:Session:Cookie, Rack:Session:Pool, etc.  A sufficiently strong key **must** be generated.  It's recommended you use the following command to generate a random key value.  

    ```
    ruby -ropenssl -rbase64 -e "puts Base64.strict_encode64(OpenSSL::Random.random_bytes(16).to_str)"
    ```

    It's also recommended you store the key value as an environment variable as opposed to a string literal in your code.  To both create the key value and store as an environment variable, use this command:
    
    ```
    export TOKEN=`ruby -ropenssl -rbase64 -e "puts Base64.strict_encode64(OpenSSL::Random.random_bytes(16).to_str)"`
    ```
    
    Then, in your code, decrypt prior to use:

    ```ruby
    require "base64"
    Base64.strict_decode64(ENV['TOKEN'])
    ```

    *Default:* nil
    
Optional Configuration Parameters
-----------------------------------

* **`:display`, `:immediate`, `:scope`**

    Values passed directly to salesforce which control salesforce authentication behavior.  See [OAuth 2.0 Web Server Authentication Flow](http://na12.salesforce.com/help/doc/en/remoteaccess_oauth_web_server_flow.htm#heading_2_1) for detailed explanation as well as valid and default values.

    *Default:* see [OAuth 2.0 Web Server Authentication Flow](http://na12.salesforce.com/help/doc/en/remoteaccess_oauth_web_server_flow.htm#heading_2_1)
    
* **`:display_override`,`:immediate_override`,`:scope_override`**

    Allow correspondingly named parameter to be overridden at runtime via http parameter of same name.  For example, if your app is capable of detecting the client device type, set **`:display_override`** to true and pass a display http parameter to `/auth/salesforce`.  

    *Default:* false

* **`:api_version`**

    For explanation of api versions, see [What's New in Version XX.X](http://www.salesforce.com/us/developer/docs/api/Content/whats_new.htm)

    *Default:* 25.0

* **`:debugging`**

    Will enable debug output for both this gem and `databasedotcom`.

    *Default:* false

* **`:on_failure`**

    A lambda block to be executed upon authentication failure.

    *Default:* redirect to `/auth/salesforce/failure` with error message passed via message http parameter.

* **`:path_prefix`**

    The path that signals databasedotcom-oauth2 to initiate authentication with [salesforce.com](http://salesforce.com/).

    *Default:* /auth/salesforce
  
## Resources
* [OAuth 2.0 Web Server Authentication Flow](http://na12.salesforce.com/help/doc/en/remoteaccess_oauth_web_server_flow.htm)
* [Article: Digging Deeper into OAuth 2.0 on Force.com](http://wiki.developerforce.com/index.php/Digging_Deeper_into_OAuth_2.0_on_Force.com)
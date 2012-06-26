# databasedotcom-oauth2

Rack Middleware for OAuth2 authentication against, and interaction with salesforce.com via the databasedotcom gem.  

### Who's it for?

RubyDevelopers of 
Whereas OmniAuth only provides authentication, this Rack Middleware assumes you lso instantiates a Databasedotcom::Client while providing an 

 authentication and  you need to query or manipulate salesforce.com data in addition to authentication.

### Benefits:

* Hides OAuth2 hand-shake complexity against multiple salesforce.com endpoints (prod vs sandbox) including support for My Domain.
* Configurable/override-able options for scope, display, immediate
* OAuth2 Token encrypted and stored in session, supports any Rack:Session type - Cookie, Pool, etc.
* Materializes Databasedotcom::Client from token upon each request
* Databasedotcom::OAuth2::Helpers mixin provides convenience methods client, me, etc.

## Demos

<a href="https://db-oauth2-sinatra-basic.herokuapp.com" target="_blank">Sinatra Basic</a><a href="https://github.com/richardvanhook/databasedotcom-oauth2-sinatra-basic" target="_blank">(source)</a>

<a href="https://db-oauth2-sinatra-jqm.herokuapp.com" target="_blank">Sinatra showing authentication options along with JQuery Mobile</a><a href="https://github.com/richardvanhook/databasedotcom-oauth2-sinatra-jqm" target="_blank">(source)</a>

## Usage

### Required 

`:token_encryption_key` & `:endpoints` are required.  databasedotcom-oauth2 encrypts oauth2 token using `:token_encryption_key` and stores it in rack.session for further use.  `:endpoints` defines the server endpoints to be available; multiple can be specified but at least one is required.  

```ruby
use Databasedotcom::OAuth2::WebServerFlow, 
  :token_encryption_key => TOKEN_ENCRYPTION_KEY,
  :endpoints            => {"login.salesforce.com" => {:keys => CLIENT_ID, :secret => CLIENT_SECRET}}
```

### Multiple Endpoints 

```ruby
use Databasedotcom::OAuth2::WebServerFlow, 
  :endpoints            => {"login.salesforce.com" => {:keys => CLIENT_ID1, :secret => CLIENT_SECRET1},
                            "test.salesforce.com"  => {:keys => CLIENT_ID2, :secret => CLIENT_SECRET2}}
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

## Parameters

### `:endpoints`



### `:token_encryption_key`

It's uber important that `:token_encryption_key` is sufficiently strong.  To generate a sufficiently strong key, run following:

    $ ruby -ropenssl -rbase64 -e "puts Base64.strict_encode64(OpenSSL::Random.random_bytes(16).to_str)"

Then, in your code, decrypt prior using:

```ruby
Base64.strict_decode64(TOKEN_ENCRYPTION_KEY)
```

## Resources

* [Article: Digging Deeper into OAuth 2.0 on Force.com](http://wiki.developerforce.com/index.php/Digging_Deeper_into_OAuth_2.0_on_Force.com)
# databasedotcom-oauth2

Rack Middleware for OAuth2 authentication against database.com or salesforce.com, and interaction via the databasedotcom gem.

## Demos

[Sinatra Basic](http://databasedotcom-oauth2-sinatra-basic.herokuapp.com) [(source)](https://github.com/richardvanhook/databasedotcom-oauth2-sinatra-basic)

[Sinatra using JQuery Mobile](http://databasedotcom-oauth2-sinatra-jqm.herokuapp.com) [(source)](https://github.com/richardvanhook/databasedotcom-oauth2-sinatra-jqm)


## Basic Usage

```ruby
use Databasedotcom::OAuth2::WebServerFlow, 
  :endpoints            => settings.endpoints, 
  :token_encryption_key => Base64.strict_decode64(ENV['TOKEN_ENCRYPTION_KEY'])
```

## Parameters

### :endpoints



### :token_encryption_key

It's uber important that the below encrypted cookie secret
is sufficiently strong.  Suggest running following to set appropriately:
$ ruby -ropenssl -rbase64 -e "puts Base64.strict_encode64(OpenSSL::Random.random_bytes(16).to_str)"

## Resources

* [Article: Digging Deeper into OAuth 2.0 on Force.com](http://wiki.developerforce.com/index.php/Digging_Deeper_into_OAuth_2.0_on_Force.com)
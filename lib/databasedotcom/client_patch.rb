require "databasedotcom"

Databasedotcom::Client.class_eval do

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

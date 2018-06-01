local BasePlugin = require "kong.plugins.base_plugin"
local access = require "kong.plugins.kong-oidc-auth.access"

local KongOidcAuth = BasePlugin:extend()

function KongOidcAuth:new()
	KongOidcAuth.super.new(self, "kong-oidc-auth")
end

function KongOidcAuth:access(conf)
	KongOidcAuth.super.access(self)
	access.run(conf)
end

return KongOidcAuth

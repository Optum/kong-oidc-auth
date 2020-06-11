local access = require "kong.plugins.kong-oidc-auth.access"

local KongOidcAuth = {}

function KongOidcAuth:access(conf)
	access.run(conf)
end

return KongOidcAuth

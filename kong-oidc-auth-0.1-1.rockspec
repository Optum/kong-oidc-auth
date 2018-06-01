package = "kong-oidc-auth"
version = "0.1-1"
source = {
   url = "git+https://github.com/Optum/kong-oidc-auth.git"
}
description = {
   summary = "OpenID Connect authentication with Kong gateway",
   detailed = [[Please refer to the documentation associated here: https://github.com/Optum/kong-oidc-auth ]],
   homepage = "https://github.com/Optum/kong-oidc-auth",
   license = "Apache 2.0"
}
dependencies = {}
build = {
   type = "builtin",
   modules = {
      ["kong.plugins.kong-oidc-auth.access"] = "src/access.lua",
      ["kong.plugins.kong-oidc-auth.handler"]  = "src/handler.lua",
      ["kong.plugins.kong-oidc-auth.schema"]= "src/schema.lua"
   }
}

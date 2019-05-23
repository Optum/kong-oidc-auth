local url = require "socket.url"

--Added a app_login_redirect_url for Single Page Apps that need redirection to their dashboard after auth prior to transacting against backend API services
--Added a new pf_idp_adapter_id tag as optional since we uses ping federate for OIDC
--Added a cookie_domain for valid domain the cookie can be used across

local function validate_url(value)
  local parsed_url = url.parse(value)
  if parsed_url.scheme and parsed_url.host then
    parsed_url.scheme = parsed_url.scheme:lower()
    if not (parsed_url.scheme == "http" or parsed_url.scheme == "https") then
      return false, "Supported protocols are HTTP and HTTPS"
    end
  end

  return true
end

return {
  fields = {
    authorize_url = {type = "url", required = true, func = validate_url},
    service_logout_url = {type = "string", required = false, default = ""},
    app_login_redirect_url = {type = "string", required = false, default = ""},
    token_url = {type = "url", required = true, func = validate_url},
    user_url  = {type = "url", required = true, func = validate_url},
    client_id = {type = "string", required = true},
    client_secret = {type = "string", required = true},
    scope = {type = "string", default = ""},
    salt = {required = true, type = "string", default = "b3253141ce67204b"},
    pf_idp_adapter_id = {type = "string", default = ""},
    user_keys = {type = "array", default = {"username", "email"}},
    cookie_domain = {type = "string", default = ".company.com"},
    user_info_periodic_check = {type = "number", required = true, default = 60},
    hosted_domain = {type = "string", default = ""},
    realm = {type = "string", default = ""},
    allowed_roles = {type = "array", default = {}},
    email_key = {type = "string", default = ""},
    user_info_cache_enabled = {type = "boolean", default = false}
  }
}

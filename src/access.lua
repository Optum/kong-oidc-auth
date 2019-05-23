local _M = {}
local cjson = require "cjson.safe"
local pl_stringx = require "pl.stringx"
local singletons = require "kong.singletons"
local http = require "resty.http"
local str = require "resty.string"
local openssl_digest = require "openssl.digest"
local cipher = require "openssl.cipher"
local aes = cipher.new("AES-128-CBC")
local oidc_error = nil
local salt = nil --16 char alphanumeric
local cookieDomain = nil

local function dump(o)
   if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s .. '['..k..'] = ' .. dump(v) .. ','
      end
      return s .. '} '
   else
      return tostring(o)
   end
end

local function getUserInfo(access_token, callback_url, conf)
    local httpc = http:new()
    local res, err = httpc:request_uri(conf.user_url, {
        method = "GET",
        ssl_verify = false,
        headers = {
          ["Authorization"] = "Bearer " .. access_token,
        }
    })

  -- redirect to auth if user result is invalid not 200
  if res.status ~= 200 then
     return redirect_to_auth(conf, callback_url)
  end

  local userJson = cjson.decode(res.body)
  return userJson
end

local function getKongKey(eoauth_token, access_token, callback_url, conf)
  -- This will add a 28800 second (8 hour) expiring TTL on this cached value
  -- https://github.com/thibaultcha/lua-resty-mlcache/blob/master/README.md
  local userInfo, err = singletons.cache:get(eoauth_token, { ttl = conf.user_info_periodic_check }, getUserInfo, access_token, callback_url, conf)
	
  if err then
    ngx.log(ngx.ERR, "Could not retrieve UserInfo: ", err)
    return
  end
	
  return userInfo
end

local function is_member(_obj, _set)
  for _,v in pairs(_set) do
    if v == _obj then
      return true
    end
  end
  return false
end


local function validate_roles(conf, token)
  if token["groups"] == nil then
    ngx.log(ngx.ERR, 'oidc.userinfo.groups not availble! Check keycloak settings.')
    return false
  end
  local _allowed_roles = conf.allowed_roles
  local _next = next(_allowed_roles)
  if _next == nil then
   return true-- no roles provided for checking. Ok.
  end
  for _, role in pairs(_allowed_roles) do
    if (is_member(role, token["groups"]) == true) then
      return true
    end
  end
  return false -- no matching roles
end

function redirect_to_auth( conf, callback_url )
    -- Track the endpoint they wanted access to so we can transparently redirect them back
    if type(ngx.header["Set-Cookie"]) == "table" then
	ngx.header["Set-Cookie"] = { "EOAuthRedirectBack=" .. ngx.var.request_uri .. ";Path=/;Expires=" .. ngx.cookie_time(ngx.time() + 120) .. ";Max-Age=120;HttpOnly", unpack(ngx.header["Set-Cookie"]) }
    else
	ngx.header["Set-Cookie"] = { "EOAuthRedirectBack=" .. ngx.var.request_uri .. ";Path=/;Expires=" .. ngx.cookie_time(ngx.time() + 120) .. ";Max-Age=120;HttpOnly", ngx.header["Set-Cookie"] }
    end
	
    -- Redirect to the /oauth endpoint
    local oauth_authorize = nil
    if(conf.pf_idp_adapter_id == "") then --Standard Auth URL(Something other than ping)
       oauth_authorize = conf.authorize_url .. "?response_type=code&client_id=" .. conf.client_id .. "&redirect_uri=" .. callback_url .. "&scope=" .. conf.scope
    else --Ping Federate Auth URL
         oauth_authorize = conf.authorize_url .. "?pfidpadapterid=" .. conf.pf_idp_adapter_id .. "&response_type=code&client_id=" .. conf.client_id .. "&redirect_uri=" .. callback_url .. "&scope=" .. conf.scope
    end
    
    return ngx.redirect(oauth_authorize)
end

function encode_token(token, conf)
      return ngx.encode_base64(aes:encrypt(openssl_digest.new("md5"):final(conf.client_secret), salt, true):final(token))
end

function decode_token(token, conf)
    local status, token = pcall(function () return aes:decrypt(openssl_digest.new("md5"):final(conf.client_secret), salt, true):final(ngx.decode_base64(token)) end)
    
    if status then
        return token
    else
        return nil
    end
end

-- Logout Handling
function  handle_logout(encrypted_token, conf)
   --Terminate the Cookie
   local redirect_url = string.format("%s?redirect_uri=%s", conf.service_logout_url, conf.app_login_redirect_url)
   if type(ngx.header["Set-Cookie"]) == "table" then
	ngx.header["Set-Cookie"] = { "EOAuthToken=;Path=/;Expires=Thu, Jan 01 1970 00:00:00 UTC;Max-Age=0;HttpOnly" .. cookieDomain, unpack(ngx.header["Set-Cookie"]) }
   else
        ngx.header["Set-Cookie"] = { "EOAuthToken=;Path=/;Expires=Thu, Jan 01 1970 00:00:00 UTC;Max-Age=0;HttpOnly" .. cookieDomain, ngx.header["Set-Cookie"] }
   end
   -- Remove session
   if conf.user_info_cache_enabled then
      singletons.cache:invalidate(encrypted_token)
   end
   -- Redirect to IAM service logout
   return ngx.redirect(redirect_url)

end

-- Callback Handling
function  handle_callback( conf, callback_url )
    local args = ngx.req.get_uri_args()
    local code = args.code
    local redirect_url

    if args.redirect_url == nil then
       redirect_url = callback_url
    else
       redirect_url = args.redirect_url
    end
	
    if code then
        local httpc = http:new()
        local res, err = httpc:request_uri(conf.token_url, {
            method = "POST",
            ssl_verify = false,
            body = "grant_type=authorization_code&client_id=" .. conf.client_id .. "&client_secret=" .. conf.client_secret .. "&code=" .. code .. "&redirect_uri=" .. redirect_url,
            headers = {
              ["Content-Type"] = "application/x-www-form-urlencoded",
            }
        })

        if not res then
            oidc_error = {status = ngx.HTTP_INTERNAL_SERVER_ERROR, message = "Failed to request: " .. err}
            return kong.response.exit(oidc_error.status, { message = oidc_error.message })
        end

        local json = cjson.decode(res.body)
        local access_token = json.access_token
        if not access_token then
            oidc_error = {status = ngx.HTTP_BAD_REQUEST, message = json.error_description}
            return kong.response.exit(oidc_error.status, { message = oidc_error.message })
        end

    	if type(ngx.header["Set-Cookie"]) == "table" then
    	   ngx.header["Set-Cookie"] = { "EOAuthToken=" .. encode_token(access_token, conf) .. ";Path=/;Expires=" .. ngx.cookie_time(ngx.time() + 1800) .. ";Max-Age=1800;HttpOnly" .. cookieDomain, unpack(ngx.header["Set-Cookie"]) }
        else
    	   ngx.header["Set-Cookie"] = { "EOAuthToken=" .. encode_token(access_token, conf) .. ";Path=/;Expires=" .. ngx.cookie_time(ngx.time() + 1800) .. ";Max-Age=1800;HttpOnly" .. cookieDomain, ngx.header["Set-Cookie"] }
        end

        -- Support redirection back to Kong if necessary
        local redirect_back = ngx.var.cookie_EOAuthRedirectBack
		
        if redirect_back then
            return ngx.redirect(redirect_back) --Should always land here if no custom Loggedin page defined!
        else
          --return redirect_to_auth(conf, callback_url)
	       return
        end
    else
        oidc_error = {status = ngx.HTTP_UNAUTHORIZED, message = "User has denied access to the resources"}
        return kong.response.exit(oidc_error.status, { message = oidc_error.message })
    end
end

function _M.run(conf)
	local path_prefix = ""
	local callback_url = ""
	cookieDomain = ";Domain=" .. conf.cookie_domain
	salt = conf.salt

	--Fix for /api/team/POC/oidc/v1/service/oauth2/callback?code=*******
	if ngx.var.request_uri:find('?') then
	  path_prefix = ngx.var.request_uri:sub(1, ngx.var.request_uri:find('?') -1)
	else
	  path_prefix = ngx.var.request_uri
	end
	
	if pl_stringx.endswith(path_prefix, "/") then
	  path_prefix = path_prefix:sub(1, path_prefix:len() - 1)
	  callback_url = ngx.var.scheme .. "://" .. ngx.var.host .. path_prefix .. "/oauth2/callback"
	elseif pl_stringx.endswith(path_prefix, "/oauth2/callback") then --We are in the callback of our proxy
	  callback_url = ngx.var.scheme .. "://" .. ngx.var.host .. path_prefix
    handle_callback(conf, callback_url)
	else
	  callback_url = ngx.var.scheme .. "://" .. ngx.var.host .. path_prefix .. "/oauth2/callback"
	end

  -- See if we have a token
  
  -- Try to get token from Bearer string
  
  local access_token = nil
  local auth_header = ngx.var.http_Authorization
  if auth_header then
    _, _, access_token = string.find(auth_header, "Bearer%s+(.+)")
  end

	-- Try to get token from cookie
  local encrypted_token = ngx.var.cookie_EOAuthToken
  
  -- No token, send to auth
  if encrypted_token == nil  and access_token == nil then 
    return redirect_to_auth(conf, callback_url)
  end

  if encrypted_token == nil then
    -- make an encoded token from the passed access_token
    encrypted_token = encode_token(access_token, conf)
  end
	-- check if we are authenticated already
	if access_token == nil then
    access_token = decode_token(encrypted_token, conf)
    if not access_token then
    -- broken access token
       return redirect_to_auth( conf, callback_url )
    end
  end
  
  --They had a valid EOAuthToken so its safe to process a proper logout now.
  if pl_stringx.endswith(path_prefix, "/logout") then
  	return handle_logout(encrypted_token, conf)
  end
  
  --Update the Cookie to increase longevity for 30 more minutes if active proxying
  if type(ngx.header["Set-Cookie"]) == "table" then
  ngx.header["Set-Cookie"] = { "EOAuthToken=" .. encode_token(access_token, conf) .. ";Path=/;Expires=" .. ngx.cookie_time(ngx.time() + 1800) .. ";Max-Age=1800;HttpOnly" .. cookieDomain, unpack(ngx.header["Set-Cookie"]) }
  else
  ngx.header["Set-Cookie"] = { "EOAuthToken=" .. encode_token(access_token, conf) .. ";Path=/;Expires=" .. ngx.cookie_time(ngx.time() + 1800) .. ";Max-Age=1800;HttpOnly" .. cookieDomain, ngx.header["Set-Cookie"] }
  end

   --CACHE LOGIC - Check boolean and then if EOAUTH has existing key -> userInfo value
  if conf.user_info_cache_enabled then
		local userInfo = getKongKey(encrypted_token, access_token, callback_url, conf)
		if userInfo then
      -- Check if allowed_roles is set && enforce
      local valid = validate_roles(conf, userInfo)
      if valid == false then
        return kong.response.exit(401, { message = "User lacks valid role for this OIDC resource" })
      end
		  for i, key in ipairs(conf.user_keys) do
		      ngx.header["X-Oauth-".. key] = userInfo[key]
		      ngx.req.set_header("X-Oauth-".. key, userInfo[key])
		  end
      if (conf.realm ~= "" and (pl_stringx.count(ngx.var.request_uri, conf.realm) > 0)) then -- inject realm name into headers
       ngx.header["X-Oauth-realm"] = conf.realm
      end
      ngx.req.set_header("X-Oauth-Token", access_token)
      ngx.header["X-Oauth-Token"] = access_token
		  return
		end
  end
  -- END OF NEW CACHE LOGIC --

  -- Get user info
  if not ngx.var.cookie_EOAuthUserInfo then
		local json = getUserInfo(access_token, callback_url, conf)

		if json then
        -- Check if allowed_roles is set && enforce
        local valid = validate_roles(conf, json)
        if valid == false then
          return kong.response.exit(401, { message = "User lacks valid role for this OIDC resource" })
        end
		    if conf.hosted_domain ~= "" and conf.email_key ~= "" then
    			if not pl_stringx.endswith(json[conf.email_key], conf.hosted_domain) then
    			    oidc_error = {status = ngx.HTTP_UNAUTHORIZED, message = "Hosted domain is not matching"}
    			    return kong.response.exit(oidc_error.status, { message = oidc_error.message })
    			end
		    end

		    for i, key in ipairs(conf.user_keys) do
    			ngx.header["X-Oauth-".. key] = json[key]
    			ngx.req.set_header("X-Oauth-".. key, json[key])
		    end
        if (conf.realm ~= "" and (pl_stringx.count(ngx.var.request_uri, conf.realm) > 0)) then -- inject realm name into headers
          ngx.header["X-Oauth-realm"] = conf.realm
        end
		    ngx.req.set_header("X-Oauth-Token", access_token)
		    ngx.header["X-Oauth-Token"] = access_token

		    if type(ngx.header["Set-Cookie"]) == "table" then
    			ngx.header["Set-Cookie"] = { "EOAuthUserInfo=0;Path=/;Expires=" .. ngx.cookie_time(ngx.time() + conf.user_info_periodic_check) .. ";Max-Age=" .. conf.user_info_periodic_check .. ";HttpOnly", unpack(ngx.header["Set-Cookie"]) }
		    else
    			ngx.header["Set-Cookie"] = { "EOAuthUserInfo=0;Path=/;Expires=" .. ngx.cookie_time(ngx.time() + conf.user_info_periodic_check) .. ";Max-Age=" .. conf.user_info_periodic_check .. ";HttpOnly", ngx.header["Set-Cookie"] }
		    end

		else
		    return kong.response.exit(500, { message = err })
		end
  end
end

return _M

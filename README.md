# Kong OIDC Auth
OpenID Connect authentication integration with the Kong Gateway

## Configuration
You can add the plugin with the following request:

```bash
$ curl -X POST http://kong:8001/apis/{api}/plugins \
    --data "name=kong-oidc-auth" \
    --data "config.authorize_url=https://oauth.something.net/openid-connect/authorize" \
    --data "config.scope=openid+profile+email" \
    --data "config.pfidpadapterid=CompanyIdOIDCStage" \
    --data "config.token_url=https://oauth.something.net/openid-connect/token" \
    --data "config.client_id=SOME_CLEINT_ID" \
    --data "config.client_secret=SOME_SECRET_KEY" \
    --data "config.user_url=https://oauth.something.net/openid-connect/userinfo" \
    --data "config.user_keys=email,name,sub" \
    --data "config.hosted_domain=mycompany.com" \
    --data "config.email_key=email" \
    --data "config.salt=b3253141ce67204b" \
    --data "config.app_login_redirect_url=https://yourapplication.com/loggedin/dashboard" \
    --data "config.cookie_domain=.company.com" \
    --data "config.user_info_cache_enabled=false"
```

| Form Parameter | default | description |
| --- 						| --- | --- |
| `name` 					        | | plugin name `kong-oidc-auth` |
| `config.authorize_url` 	| | authorization url of the OAUTH provider (the one to which you will be redirected when not authenticated) |
| `config.scope` 			    | | OAUTH scope of the authorization request |
| `config.pfidpadapterid` <br /> <small>Optional</small> 	    | | OAUTH PingFederate Adaptor ID of the authorization request ex: CompanyIdOIDCStage, essentially points to the idp environment, ping federate specific only |
| `config.token_url` 		  | | url of the Oauth provider to request the access token |
| `config.client_id` 		  | | OAUTH Client Id |
| `config.client_secret` 	| | OAUTH Client Secret |
| `config.user_url` 		  | | url of the oauth provider used to retrieve user information and also check the validity of the access token |
| `config.user_keys` <br /> <small>Optional</small>		| `username,email` | keys to extract from the `user_url` endpoint returned json, they will also be added to the headers of the upstream server as `X-OAUTH-XXX` |
| `config.hosted_domain`  | | domain whose users must belong to in order to get logged in. Ignored if empty |
| `config.email_key` 		  | | key to be checked for hosted domain, taken from userinfo endpoint |
| `config.user_info_periodic_check` 		  | 60 | time in seconds between token checks |
| `config.salt` 		  | b3253141ce67204b | salt for the user session token, must be 16 char alphanumeric |
| `config.app_login_redirect_url` 		  | | Needed for Single Page Applications to redirect after initial authentication successful, otherwise a proxy request following initial authentication would redirect data directly to a users browser! |
| `config.cookie_domain` 		  | | Specify the domain in which this cookie is valid for, realistically will need to match the gateway |
| `config.user_info_cache_enabled` 		  | | This enables storing the userInfo in Kong local cache which enables sending the entire requested user information to the backend service upon every request, otherwise user info only comes back occasionally and backend api service providers are required to validate the EOAuth Cookie Session with cached user information within their logic |

In addition to the `user_keys` will be added a `X-OAUTH-TOKEN` header with the access token of the provider.

NOTES:
Ping Federate requires you to authorize a callback URL, all proxies have a standard call back route of:
https://api-gateway.company.com/your/proxy/path/oauth2/callback

## Supported Kong Releases
Kong >= 1.0

## Installation
Recommended:
```
$ luarocks install kong-oidc-auth
```
Other:
```
$ git clone https://github.com/Optum/kong-oidc-auth.git /path/to/kong/plugins/kong-oidc-auth
$ cd /path/to/kong/plugins/kong-oidc-auth
$ luarocks make *.rockspec
```

## Maintainers
[jeremyjpj0916](https://github.com/jeremyjpj0916)  
[rsbrisci](https://github.com/rsbrisci)  

Feel free to open issues, or refer to our [Contribution Guidelines](https://github.com/Optum/kong-oidc-auth/blob/master/CONTRIBUTING.md) if you have any questions.

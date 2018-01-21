# oidcauth

Package oidcauth is an authentication middleware for web applications and microservices, which uses an external [OpenID Connect](http://openid.net/connect/) identity provider (IdP) for user storage and authentication. 

*Note: Work in progress. Not ready for production.*

The library is configurable, except for some choices that have been pre-made on purpose:
 - Supports only the [authorization code flow]  (https://alexbilbie.com/guide-to-oauth-2-grants/#authorisation-code-grant-section-41) of OAuth2, which makes it suitable for multi-page web apps. If you are creating a SPA app, the implicit flow might be a better choice for your project.
 - Uses secure cookies to pass session IDs back and forth between the browser and the app. Session management is handled by [gorilla/sessions](github.com/gorilla/sessions), so you can use any of the many available implementations for it to choose where to store the session data (eg. CookieStore, RedisStore, DynamoStore, etc.).
 - Authenticated handlers [verify same origin with standard headers](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Verifying_Same_Origin_with_Standard_Headers) ('Origin' and 'Referer') and block potential CSRF requests. If neither Origin nor the Referer header is present, the request is blocked.
 Additionally 'Access-Control-Allow-Origin' header is added to responses that were allowed. The list of allowed origins must be specified in the configuration object (usually only the domain of your own app and the domain of the IdP). Use of origin '*' is not allowed.

## Suitability:
Can be used as authentication middleware for (see examples):
 - Standard multi-page web application
 - Complex web application that act as a gateway between the browser and several microservices
   (APIs) by passing the access token acquired during the authentication phase down to the
   microservices.

## What oidcauth is *currently* **not**
- oidcauth *currently* does not contain authorization functionality. Applications can build simple authorization on top of it by leveraging the session data (user ID and claims).

## Tested for compatibility with:
 - [Keycloak 3.4.3.Final](http://www.keycloak.org/), a standalone open source identity and access management server

## Dependencies:
 - github.com/coreos/go-oidc
 - golang.org/x/oauth2
 - github.com/gorilla/sessions

## TODO:
 - Add authorization support.
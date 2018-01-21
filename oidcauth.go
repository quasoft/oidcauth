// Package oidcauth is an authentication middleware for web applications and microservices,
// which uses an external OpenID Connect identity provider (IdP) for user storage and
// authentication.
//
// The library is configurable, except for some choices that have been pre-made on purpose:
// - Supports only the authorization code flow of OAuth2, which makes it suitable for multi-page
//   web apps. If you are creating a SPA app, the implicit flow might be a better choice for your
//   project.
// - Uses secure cookies to pass session IDs back and forth between the browser and the app.
//   Session management is handled by gorilla/sessions, so you can use any of the many available
//   implementations for it to choose where to store the session data (eg. CookieStore,
// 	 RedisStore, DynamoStore, etc.).
// - Authenticated handlers verify same origin with standard headers ('Origin' and 'Referer') and
//   block potential CSRF requests. If neither the 'Origin' nor the 'Referer' header is present,
//   the request is blocked. Additionally 'Access-Control-Allow-Origin' header is added to allowed
//   responses. The list of allowed origins must be specified in the configuration object (usually
//   only the domain of your own app and the domain of the IdP). Use of origin '*' is not allowed.
//
// Can be used as authentication middleware for (see examples):
// - Standard multi-page web application
// - Complex web application that act as a gateway between the browser and several microservices
//   (APIs) by passing the access token acquired during the authentication phase down to the
//   microservices.
//
// Tested for compatibility with:
// - Keycloak 3.4.3.Final, a standalone open source identity and access management server
//   (http://www.keycloak.org/)
//
// Dependencies:
// - github.com/coreos/go-oidc
// - golang.org/x/oauth2
// - github.com/gorilla/sessions
//
// TODO:
// - Add authorization support.
package oidcauth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"context"

	oidc "github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"github.com/quasoft/oauth2state"
	"golang.org/x/oauth2"
)

// The Config object determines the behaviour of the Authenticator.
type Config struct {
	ClientID     string
	ClientSecret string
	// IssuerURL, eg. "https://EXAMPLE.COM/auth/realms/REALM_NAME" for Keycloak.
	IssuerURL string
	// LogoutURL is the endpoint used for logging out of IdP session using GET request,
	// eg. "https://EXAMPLE.COM/auth/realms/REALM_NAME/protocol/openid-connect/logout" for Keycloak.
	LogoutURL string
	// CallbackURL is the absolute URL to a handler in your application, which deals with auth
	// responses from the IdP.
	// You must handle requests to that URL and pass them to the CallbackHandler() method.
	// eg. "https://localhost:5556/auth/callback".
	CallbackURL string
	// List of additional scopes to request from the IdP in addition to the default 'openid' scope
	// (eg. []string{"profile"}).
	Scopes []string
	// AllowedOrigins is a list of hosts (https://example.com) allowed as origins of the HTTP request.
	// Add the origin of your app and that of the IdP to the list.
	// Use domain names in AllowedOrigins, not IP addresses.
	AllowedOrigins []string
	// SessionStore is where session data like user ID and claims are stored.
	// SessionStore could be any of the available gorilla/session implementations
	// (eg. CookieStore with secure flag, RedisStore, DynamoStore, etc.)
	SessionStore sessions.Store
	// TokenStore holds the access tokens that are acquired during authentication.
	// Those tokens can be used to access other services (APIs) that are part of the application.
	// Keeping tokens in a separate store from session data helps to avoid reaching the usual
	// limit on the amount of data that can be stored in a store (eg. 4KB).
	// TokenStore could be any of the available gorilla/session implementations
	// (eg. CookieStore with secure flag, RedisStore, DynamoStore, etc.)
	TokenStore sessions.Store
	// Set StateStore to a sessions store, which will hold the oauth state value.
	// Monoliths and scalable applications with sticky sessions could store state in instance memory.
	// Scalable apps without sticky sessions can use Memcache or Redis for storage.
	StateStore oauth2state.StateStorer
}

// Validate makes basic validation of configuration to make sure that important and required fields
// have been set with values in expected format
func (c Config) Validate() error {
	if strings.TrimSpace(c.ClientID) == "" {
		return fmt.Errorf("ClientID not defined")
	}
	if strings.TrimSpace(c.IssuerURL) == "" {
		return fmt.Errorf("IssuerURL not defined")
	}
	if strings.TrimSpace(c.LogoutURL) == "" {
		return fmt.Errorf("LogoutURL not defined")
	}
	if strings.TrimSpace(c.CallbackURL) == "" {
		return fmt.Errorf("CallbackURL not defined")
	}
	if !strings.HasPrefix(c.CallbackURL, "http://") && !strings.HasPrefix(c.CallbackURL, "https://") {
		return fmt.Errorf("CallbackURL is not absolute URL")
	}
	if len(c.AllowedOrigins) == 0 || strings.TrimSpace(c.AllowedOrigins[0]) == "" {
		return fmt.Errorf("specify at least one allowed origin")
	}
	for _, o := range c.AllowedOrigins {
		if strings.Contains(o, "*") {
			return fmt.Errorf("usage of * in allowed origins is not allowed")
		}
	}
	return nil
}

// The Authenticator type provides middleware methods for authentication of http requests.
// A single authenticator object can be shared by concurrent goroutines.
type Authenticator struct {
	Config   Config
	ctx      context.Context
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth2   *oauth2.Config
}

// TODO: Don't just use log.*, use a configurable Logger object

// New creates a new Authenticator object with the given configuration options.
// The ctx context is used only for the initial connection to the well-known configuration
// endpoint of the IdP and can be set to context.Background.
func New(ctx context.Context, config *Config) (*Authenticator, error) {
	err := config.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}

	idp, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		log.Print("Could not initialize provider object")
		return nil, err
	}
	oidcCfg := &oidc.Config{
		ClientID: config.ClientID,
	}
	ver := idp.Verifier(oidcCfg)

	scopes := []string{oidc.ScopeOpenID}
	scopes = append(scopes, config.Scopes...)

	oauthCfg := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     idp.Endpoint(),
		RedirectURL:  config.CallbackURL,
		Scopes:       scopes,
	}

	var auth = &Authenticator{
		Config:   *config,
		ctx:      ctx,
		provider: idp,
		verifier: ver,
		oauth2:   &oauthCfg,
	}
	return auth, nil
}

// createSession creates a new session with the user ID and claims of the authenticated user
func (a *Authenticator) createSession(
	w http.ResponseWriter,
	r *http.Request,
	token *oauth2.Token,
	idToken *oidc.IDToken,
	claims *json.RawMessage,
) error {
	tokenSession, err := getSession(a.Config.TokenStore, r, "oidcauth-token")
	if err != nil {
		log.Printf("Could not get token store: %v", err)
		return err
	}
	err = setSessionToken(tokenSession, "AccessToken", token)
	if err != nil {
		log.Printf("Could not convert token to json: %v", err)
		return err
	}
	err = tokenSession.Save(r, w)
	if err != nil {
		log.Printf("Could not save token to store: %v", err)
		return err
	}

	session, err := getSession(a.Config.SessionStore, r, "oidcauth")
	if err != nil {
		log.Printf("Could not get session from store: %v", err)
		return err
	}
	setSessionStr(session, "auth", "true")
	setSessionStr(session, "sub", idToken.Subject)
	setSessionStr(session, "claims", string(*claims))
	err = session.Save(r, w)
	if err != nil {
		log.Printf("Could not save session to store: %v", err)
		return err
	}

	return nil
}

// IsAuthenticated checks if current session is authenticated by looking at the
// authentication flag in the session data.
func (a *Authenticator) IsAuthenticated(r *http.Request) error {
	session, err := getSession(a.Config.SessionStore, r, "oidcauth")
	if err != nil {
		return err
	}
	authenticated, err := getSessionStr(session, "auth")
	if err != nil {
		return err
	}

	if authenticated != "true" {
		err := fmt.Errorf("Authentication flag is not set")
		return err
	}

	return nil
}

// Redirects a request to the login path of the identity provider
func (a *Authenticator) RedirectToLoginPage(w http.ResponseWriter, r *http.Request) {
	state, err := a.Config.StateStore.NewState(r.RequestURI)
	if err != nil {
		log.Printf("Could not generate new state value: %v", err)
		http.Error(w, "Error!", http.StatusInternalServerError)
		return
	}
	url := a.oauth2.AuthCodeURL(state)
	log.Printf("Requested %s, redirecting to auth server (%s)...", r.RequestURI, url)
	http.Redirect(w, r, url, http.StatusFound)
}

func (a *Authenticator) checkStateValue(r *http.Request) error {
	value := r.URL.Query().Get("state")

	found, err := a.Config.StateStore.Contains(value)
	if err != nil {
		return err
	}

	if !found {
		return fmt.Errorf("could not find state value %s", value)
	}

	return nil
}

func (a *Authenticator) getStateURL(r *http.Request) (string, error) {
	value := r.URL.Query().Get("state")

	url, err := a.Config.StateStore.URL(value)
	if err != nil {
		return "", err
	}

	return url, nil
}

func (a *Authenticator) deleteStateValue(r *http.Request) error {
	value := r.URL.Query().Get("state")

	err := a.Config.StateStore.Delete(value)
	if err != nil {
		return err
	}

	return nil
}

func (a *Authenticator) authResponseHandler(w http.ResponseWriter, r *http.Request) error {
	err := a.checkStateValue(r)
	if err != nil {
		return err
	}
	authCode := r.URL.Query().Get("code")
	token, err := a.oauth2.Exchange(r.Context(), authCode)
	//token, err := a.oauth2.Exchange(a.ctx, authCode)
	if err != nil {
		log.Printf("Failed to exchange token: %v", err)
		return err
	}
	log.Print("Exchanged auth code for token")

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		err := fmt.Errorf("no id_token field in oauth2 token")
		log.Printf("Error: %v", err)
		return err
	}
	log.Print("Retrieved ID token")

	//idToken, err := a.verifier.Verify(a.ctx, rawIDToken)
	idToken, err := a.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		log.Printf("Failed to verify ID token: %v", err)
		return err
	}
	log.Print("Validated ID token successfully")

	// TODO: VerifyAccessToken

	claims := new(json.RawMessage)
	err = idToken.Claims(&claims)
	if err != nil {
		log.Printf("Failed to retrieve claims from token: %v", err)
		return err
	}
	log.Print("Claims retrieved successfully")
	//log.Print(string(*claims))

	// TODO: store user ID and claims in session
	a.createSession(w, r, token, idToken, claims)

	return nil
}

// TODO: Support two modes: AuthWithSession and AuthWithJWT
func (a *Authenticator) AuthWithSession(next http.Handler) http.Handler {
	return VerifyOrigin(
		a.Config.AllowedOrigins,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("Authenticating request to %s", r.RequestURI)

			err := a.IsAuthenticated(r)
			if err != nil {
				log.Print(err)
				a.RedirectToLoginPage(w, r)
				return
			}

			log.Print("Authenticated")
			next.ServeHTTP(w, r)
		}))
}

func (a *Authenticator) CallbackHandler() http.Handler {
	return VerifyOrigin(
		a.Config.AllowedOrigins,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Print("Authentication callback called")

			err := a.authResponseHandler(w, r)
			if err != nil {
				log.Printf("Authentication failed: %v", err)
				http.Error(w, "Error!", http.StatusBadRequest)
				return
			}
			log.Print("Authenticated successfully")

			returnURL, err := a.getStateURL(r)
			if err != nil {
				http.Error(w, "Error!", http.StatusBadRequest)
				return
			}
			a.deleteStateValue(r)

			log.Printf("Redirecting back to %s", returnURL)
			http.Redirect(w, r, returnURL, http.StatusFound)
		}))
}

// Logout deletes the session data, logout from the IdP and redirect to the URL provided
func (a *Authenticator) Logout(redirectURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Print("Logging out")
		session, err := getSession(a.Config.SessionStore, r, "oidcauth")
		if err != nil {
			log.Printf("Could not get session from store: %v", err)
			http.Error(w, "Error!", http.StatusInternalServerError)
			return
		}
		session.Values["auth"] = "false"
		session.Options.MaxAge = -1
		session.Save(r, w)
		log.Print("Logged out")

		u, err := url.Parse(a.Config.LogoutURL)
		if err != nil {
			log.Printf("Could not parse LogoutURL from config: %v", err)
			http.Error(w, "Error!", http.StatusInternalServerError)
			return
		}
		q := u.Query()
		q.Add("redirect_uri", redirectURL)
		u.RawQuery = q.Encode()
		url := u.String()

		http.Redirect(w, r, url, http.StatusFound)
	})
}

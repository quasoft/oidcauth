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
//   and the request method is anything but GET or OPTIONS, the request is blocked.
//   Additionally 'Access-Control-Allow-Origin' header is added to indicate the allowed origin.
//   The list of allowed origins must be specified in the configuration object (usually only the
//   domain of your own app and the domain of the IdP). Use of origin '*' is not allowed.
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
	// You must handle requests to that URL and pass them to the HandleAuthResponse() method.
	// eg. "https://localhost:5556/auth/callback".
	CallbackURL string
	// The default URL to use as return URL after successful authentication of non GET requests.
	DefaultReturnURL string
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
	// TokenStore holds the access/refresh tokens that are acquired during authentication.
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
// have been set with values in expected format.
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

// createSession creates a new session and stores the user ID and claims of the
// authenticated user inside the session data.
func (a *Authenticator) createSession(
	w http.ResponseWriter,
	r *http.Request,
	token *oauth2.Token,
	idToken *oidc.IDToken,
	claims *json.RawMessage,
) error {
	// Save the token structure containing the access and refresh tokens in a separate
	// store as the total size of that structure can reach 2-3KB, which is close to the
	// usual limit of 4KB in most session storages (eg. in cookies, when using CookieStore).
	tokenSession, err := getSession(a.Config.TokenStore, r, "oidcauth-token")
	if err != nil {
		log.Printf("Could not get token store: %v", err)
		return err
	}
	err = setSessionToken(tokenSession, "token", token)
	if err != nil {
		log.Printf("Could not store token structure: %v", err)
		return err
	}
	err = tokenSession.Save(r, w)
	if err != nil {
		log.Printf("Could not save token to store: %v", err)
		return err
	}

	// Save other session values like subject ID and claims in a separate store.
	// Usually those values already exist in the access token, but storing them
	// separately removes the overhead of parsing the access token JWT at every
	// request.
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

// destroySession deletes all session data associated with this request
// from the SessionStore and removes the cookie with the session ID.
func (a *Authenticator) destroySession(w http.ResponseWriter, r *http.Request) error {
	// Delete sessions from both stores
	session, err := getSession(a.Config.SessionStore, r, "oidcauth")
	if err != nil {
		log.Printf("Could not get session from store: %v", err)
		return err
	}
	session.Values["auth"] = "false"
	session.Options.MaxAge = -1
	err = session.Save(r, w)
	if err != nil {
		log.Printf("Could not save session to store: %v", err)
		return err
	}

	session, err = getSession(a.Config.TokenStore, r, "oidcauth-token")
	if err != nil {
		log.Printf("Could not get session from store: %v", err)
		return err
	}
	session.Options.MaxAge = -1
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

// GetAuthInfo retrieves the subject identifier (user id) with which the
// user is registered with the IdP and the claims that were returned during
// authentication.
// Subject identifer is returned as a string.
// Claims are returned as an opaque JSON value - as provided by the IdP.
// An error is returned if the user has not been authenticated yet or an error
// occurs while reading the session data.
func (a *Authenticator) GetAuthInfo(r *http.Request) (subject string, claims string, err error) {
	subject = ""
	claims = ""
	err = a.IsAuthenticated(r)
	if err != nil {
		return
	}

	session, err := getSession(a.Config.SessionStore, r, "oidcauth")
	if err != nil {
		return
	}
	subject, err = getSessionStr(session, "sub")
	if err != nil {
		return
	}
	claims, err = getSessionStr(session, "claims")
	if err != nil {
		return
	}

	return
}

// GetClaims retrieves the claims that were sent by the IdP during authentication as a map.
func (a *Authenticator) GetClaims(r *http.Request) (map[string]interface{}, bool) {
	m := make(map[string]interface{})

	err := a.IsAuthenticated(r)
	if err != nil {
		return m, false
	}

	session, err := getSession(a.Config.SessionStore, r, "oidcauth")
	if err != nil {
		return m, false
	}
	claims, err := getSessionStr(session, "claims")
	if err != nil {
		return m, false
	}

	var data map[string]interface{}
	err = json.Unmarshal([]byte(claims), &data)
	if err != nil {
		return data, false
	}

	return data, true
}

// GetToken retrieves an oauth2.Token structure containing the access and refresh tokens.
func (a *Authenticator) GetToken(r *http.Request) (*oauth2.Token, error) {
	err := a.IsAuthenticated(r)
	if err != nil {
		return nil, err
	}

	session, err := getSession(a.Config.TokenStore, r, "oidcauth-token")
	if err != nil {
		return nil, err
	}
	token, err := getSessionToken(session, "token")
	if err != nil {
		return nil, err
	}

	return token, nil
}

// RedirectToLoginPage redirects the request to the login endpoint of the identity provider.
func (a *Authenticator) RedirectToLoginPage(w http.ResponseWriter, r *http.Request) {
	returnURL := a.Config.DefaultReturnURL
	if isGET(r) {
		returnURL = r.RequestURI
	}
	state, err := a.Config.StateStore.NewState(returnURL)
	if err != nil {
		log.Printf("Could not generate new state value: %v", err)
		http.Error(w, "Error!", http.StatusInternalServerError)
		return
	}
	url := a.oauth2.AuthCodeURL(state)
	log.Printf("Requested %s, redirecting to auth server (%s)...", returnURL, url)
	http.Redirect(w, r, url, http.StatusFound)
}

// checkStateValue verifies that the state value in the query parameters
// exists in the state store.
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

// extractStateURL retrieves the URL associated with the given
// state value and removes the state value from the state store.
func (a *Authenticator) extractStateURL(r *http.Request) (string, error) {
	value := r.URL.Query().Get("state")

	url, err := a.Config.StateStore.URL(value)
	if err != nil {
		return "", err
	}

	err = a.Config.StateStore.Delete(value)
	if err != nil {
		return "", err
	}

	return url, nil
}

// VerifyAuthResponse verifies the authentication response received
// from the IdP and redirects to the return URL provided on the first request.
func (a *Authenticator) VerifyAuthResponse() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := a.checkStateValue(r)
		if err != nil {
			log.Printf("Authentication failed: %v", err)
			http.Error(w, "Error!", http.StatusBadRequest)
			return
		}
		authCode := r.URL.Query().Get("code")
		token, err := a.oauth2.Exchange(r.Context(), authCode)
		if err != nil {
			log.Printf("Authentication failed: failed to exchange token: %v", err)
			http.Error(w, "Error!", http.StatusBadRequest)
			return
		}
		log.Print("Exchanged auth code for token")

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			log.Print("Authentication failed: no id_token field in oauth2 token")
			http.Error(w, "Error!", http.StatusBadRequest)
			return
		}
		log.Print("Retrieved ID token")

		idToken, err := a.verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			log.Printf("Authentication failed: failed to verify ID token: %v", err)
			http.Error(w, "Error!", http.StatusBadRequest)
			return
		}
		log.Print("Validated ID token successfully")

		claims := new(json.RawMessage)
		err = idToken.Claims(&claims)
		if err != nil {
			log.Printf("Authentication failed: failed to retrieve claims from token: %v", err)
			http.Error(w, "Error!", http.StatusBadRequest)
			return
		}
		log.Print("Claims retrieved successfully")

		log.Print("Creating session")
		err = a.createSession(w, r, token, idToken, claims)
		if err != nil {
			log.Printf("Authentication failed: could not create session: %v", err)
			http.Error(w, "Error!", http.StatusInternalServerError)
			return
		}

		log.Print("Authenticated successfully")

		log.Print("Extracting return URL by state value")
		returnURL, err := a.extractStateURL(r)
		if err != nil {
			log.Printf("Authenticated but could not determine return URL by session value: %v", err)
			http.Error(w, "Error!", http.StatusBadRequest)
			return
		}

		log.Printf("Redirecting back to %s", returnURL)
		http.Redirect(w, r, returnURL, http.StatusFound)
	})
}

// AuthWithSession authenticates the request. On successful authentication the request
// is passed down to the next http handler. The next handler can access information
// about the authenticated user via the GetAuthInfo, GetClaims and GetToken methods.
// If authentication was not successful, the browser is redirected to the login endpoint
// of the IdP.
// If the redirected request is using the GET method, the RequestURI of the
// current request is set as the return URL for successful login. Config.DefaultReturnURL
// is set for non GET requests.
func (a *Authenticator) AuthWithSession(next http.Handler) http.Handler {
	log.Print("AuthWithSession called")

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
		}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Error!", http.StatusBadRequest)
		}),
	)
}

// HandleAuthResponse handles the authentication response sent by the IdP.
// Users of oidcauth should call this method as callback handler for CallbackURL.
func (a *Authenticator) HandleAuthResponse() http.Handler {
	log.Print("HandleAuthResponse called")

	return VerifyOrigin(
		a.Config.AllowedOrigins,
		a.VerifyAuthResponse(),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Error!", http.StatusBadRequest)
		}),
	)
}

// Logout deletes the session data, logouts from the IdP and redirects to the URL provided.
func (a *Authenticator) Logout(redirectURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Print("Logging out")

		err := a.destroySession(w, r)
		if err != nil {
			http.Error(w, "Error!", http.StatusInternalServerError)
			return
		}

		url, err := appendQueryValue(a.Config.LogoutURL, "redirect_uri", redirectURL)
		if err != nil {
			log.Printf("Could not parse LogoutURL from config: %v", err)
			http.Error(w, "Error!", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, url, http.StatusFound)

		log.Print("Logged out")
	})
}

package main

import (
	"log"
	"net/http"
	"os"

	"context"

	"github.com/quasoft/memstore"
	"github.com/quasoft/oauth2state"
	"github.com/quasoft/oidcauth"
)

func main() {
	hostPort := "localhost:5556"
	baseURL := "http://" + hostPort

	// Note: Use only https URLs in production!

	config := oidcauth.Config{
		// Client ID and secret should NOT be exposed in source code or configuration files
		ClientID:     os.Getenv("OIDC_CLIENT"),
		ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),

		// Issuer URL, eg. "http://localhost:8080/auth/realms/REALM-NAME" for Keycloak
		IssuerURL: os.Getenv("OIDC_ISSUER_URL"),

		// Logout URL is provided by your IdP
		// For Keycloak this is: "http://localhost:8080/auth/realms/REALM-NAME/protocol/openid-connect/logout"
		LogoutURL: os.Getenv("OIDC_LOGOUT_URL"),

		CallbackURL: baseURL + "/auth/callback",

		// Add the origin of your app and that of the IdP to the list.
		// Use domain names in AllowedOrigins, not IP addresses.
		AllowedOrigins: []string{"http://localhost:5556", "http://localhost:8080"},

		// TODO: In production store session data in CookieStore, RedisStore, DynamoStore, etc.
		SessionStore: memstore.NewMemStore(
			// Authentication key is required.
			// It is recommended to use an authentication key with 32 or 64 bytes.
			[]byte(os.Getenv("OIDC_AUTH_KEY1")),
			// The encryption key, if set, must be either 16, 24, or 32 bytes to select
			// AES-128, AES-192, or AES-256 modes.
			[]byte(os.Getenv("OIDC_ENC_KEY1")),
		),

		// TODO: In production store access token in CookieStore, RedisStore, DynamoStore, etc.
		TokenStore: memstore.NewMemStore(
			[]byte(os.Getenv("OIDC_AUTH_KEY2")),
			[]byte(os.Getenv("OIDC_ENC_KEY2")),
		),

		// Note: If building a scalable app and sticky sessions are not an option,
		// use something like Memcache to store state values instead of in-memory storage.
		StateStore: oauth2state.NewMemStateStore(),
	}
	var auth, err = oidcauth.New(context.Background(), &config)
	if err != nil {
		log.Fatalf("Authenticator initialization failed! Error: %v", err)
	}

	// Let the authenticator handle callback responses.
	// A callback URL of your choice can be used, but it must match the one configured in config.CallbackURL.
	http.Handle("/auth/callback", auth.CallbackHandler())
	// Allows the authenticator to logout both its own session and the session with the identity provider.
	// A URL pattern of your choice can be used.
	http.Handle("/auth/logout", auth.Logout(baseURL))

	// Example of a public handler that requires no authentication
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>Home page<br><a href="/protected-page">Protected page</a></body></html>`))
	})

	// Example of using Authenticate middleware on a handler to protect content with authentication.
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>Protected content<br><a href="/auth/logout">Log out</a></body></html>`))
	})
	http.Handle("/protected-page", auth.AuthWithSession(protectedHandler))

	log.Printf("listening on %s", baseURL)
	log.Fatal(http.ListenAndServe(hostPort, nil))
}

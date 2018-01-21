package oidcauth

import (
	"fmt"

	"github.com/quasoft/oidcauth"
)

// NewKeycloakConfig is a convenience function for creating the config object for Keycloak IdP.
// Server param should receive the scheme, hostname and port of the IdP server (eg. https://host:port).
// Obviously realm is the name of the Keykloak realm to which the app should authenticate.
// The baseURL is the root URL to your application, which should be in the same format as server.
func NewKeycloakConfig(clientID, clientSecret, server, realm, baseURL string) *oidcauth.Config {
	issuerURL := fmt.Sprintf("%s/auth/realms/%s", server, realm)
	logoutURL := fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/logout", server, realm)

	return &oidcauth.Config{
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		IssuerURL:      issuerURL,
		LogoutURL:      logoutURL,
		AllowedOrigins: []string{server, baseURL},
	}
}

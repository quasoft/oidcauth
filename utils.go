package oidcauth

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// Appends a query value to a given URL.
func appendQueryValue(uri, name, value string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Add(name, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// getURLHost returns the host:port part of an absolute URL or an empty string
// if the host:port part of the URL cannot be determined or if the URL is a relative.
func getURLHost(uri string) string {
	// Make sure this is an absolute URL
	if !strings.HasPrefix(uri, "http://") && !strings.HasPrefix(uri, "https://") {
		log.Printf("URL '%s' is not absolute", uri)
		return ""
	}

	// Get protocol and host part only
	parts, err := url.Parse(uri)
	if err != nil {
		log.Printf("Could not parse URL '%s'", uri)
		return ""
	}

	if parts.Scheme == "" || parts.Host == "" {
		return ""
	}

	return fmt.Sprintf("%s://%s", parts.Scheme, parts.Host)
}

// isGET makes a case insensitive check on the request method,
// and returns true if the method is 'GET', 'get' or "".
func isGET(r *http.Request) bool {
	return r.Method == "" || strings.EqualFold(r.Method, "GET")
}

// isGET makes a case insensitive check on the request method,
// and returns true if the method is 'OPTIONS' or 'options'.
func isOPTIONS(r *http.Request) bool {
	return strings.EqualFold(r.Method, "OPTIONS")
}

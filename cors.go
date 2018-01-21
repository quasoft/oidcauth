package oidcauth

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// VerifyOrigin middleware verifies the origin of requests by checking the 'Origin' and 'Referer'
// headers. Requests are blocked if the origin differs from the list of allowed ones provided
// in allowedOrigins, or if neither of those headers is present in the request.
func VerifyOrigin(allowedOrigins []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			referer := r.Header.Get("Referer")
			// Make sure referer is an absolute URL
			if !strings.HasPrefix(referer, "http://") && !strings.HasPrefix(referer, "https://") {
				http.Error(w, "Error!", http.StatusBadRequest)
				return
			}

			// Get protocol and host part only
			parts, err := url.Parse(referer)
			if err != nil {
				http.Error(w, "Error!", http.StatusBadRequest)
				return
			}

			origin = fmt.Sprintf("%s://%s", parts.Scheme, parts.Host)
		}
		log.Printf("Origin: %v", origin)

		if origin == "" {
			log.Printf("No origin and no referer, blocking request '%s'!", r.RequestURI)
			http.Error(w, "Error!", http.StatusForbidden)
			return
		}

		if len(allowedOrigins) == 0 {
			log.Printf("List of allowed origins is empty, blocking request '%s'!", r.RequestURI)
			http.Error(w, "Error!", http.StatusInternalServerError)
			return
		}

		var allowedOrigin = allowedOrigins[0]
		for _, o := range allowedOrigins {
			if origin == o {
				allowedOrigin = origin
				break
			}
		}
		log.Printf("Chosen allow origin: %v", allowedOrigin)
		w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)

		if r.Method == "OPTIONS" {
			return
		}

		if origin != allowedOrigin {
			log.Printf("Origin %s is not allowed, blocking request '%s'!", origin, r.RequestURI)
			http.Error(w, "Error!", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

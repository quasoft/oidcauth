package oidcauth

import (
	"log"
	"net/http"
)

// VerifyOrigin middleware verifies the origin of requests by checking the 'Origin' and 'Referer'
// headers. Requests are blocked if the origin differs from the list of allowed ones provided
// in allowedOrigins, or if neither of those headers is present in the request.
func VerifyOrigin(allowedOrigins []string, next http.Handler, onErr http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := getURLHost(r.Header.Get("Origin"))
		referer := getURLHost(r.Header.Get("Referer"))

		log.Printf("Origin: %v, Referer: %v", origin, referer)

		if origin == "" {
			origin = referer
		}

		if len(allowedOrigins) == 0 {
			log.Printf("List of allowed origins is empty, blocking request '%s'!", r.RequestURI)
			onErr.ServeHTTP(w, r)
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

		if isOPTIONS(r) {
			return
		}

		// Allow CORS request without Origin and Referer only for GET requests
		if (origin == allowedOrigin) || (origin == "" && isGET(r)) {
			next.ServeHTTP(w, r)
			return
		}

		log.Printf("Origin %s is not allowed, blocking request '%s'!", origin, r.RequestURI)
		onErr.ServeHTTP(w, r)
	})
}

package oidcauth_test

import (
	"log"
	"net/http"
)

func protectedPage(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Protected content"))
}

func ExampleAuthenticate() {
	var config = oidcauth.Configuration{}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Home page"))
	})

	protectedHandler := http.HandlerFunc(protectedPage)

	http.Handle("/protected-page", oidcauth.Authenticate(&config, protectedHandler))

	log.Printf("listening on http://%s/", "127.0.0.1:5556")
	log.Fatal(http.ListenAndServe("127.0.0.1:5556", nil))
}

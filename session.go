package oidcauth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

func getSession(store sessions.Store, r *http.Request, sessionName string) (*sessions.Session, error) {
	session, err := store.Get(r, sessionName)
	if err != nil {
		log.Printf("Failed to get session %s from store: %v", sessionName, err)
		return nil, err
	}

	return session, nil
}

func getSessionStr(session *sessions.Session, valueName string) (string, error) {
	value, ok := session.Values[valueName]
	if !ok {
		err := fmt.Errorf("Could not find value %s in session", valueName)
		return "", err
	}

	str, ok := value.(string)
	if !ok {
		err := fmt.Errorf("Value %s is not a string", valueName)
		return "", err
	}

	return str, nil
}

func setSessionStr(session *sessions.Session, valueName, value string) {
	session.Values[valueName] = value
}

func getSessionToken(session *sessions.Session, valueName string) (*oauth2.Token, error) {
	value, ok := session.Values[valueName]
	if !ok {
		err := fmt.Errorf("Could not find value %s in session", valueName)
		return nil, err
	}
	b, ok := value.([]byte)
	if !ok {
		err := fmt.Errorf("Value %s is not a []byte", valueName)
		return nil, err
	}

	token := new(oauth2.Token)
	err := json.Unmarshal(b, token)
	if err != nil {
		log.Printf("Could not decode token value: %v", err)
		return nil, err
	}

	return token, nil
}

/*
func (a *Authenticator) getSessionOidcToken(req *http.Request) (*oauth2.Token, error) {
	// Add id_token to the raw field of the token, as if it came
	// from a URL query, just to make it compatible with other
	// methods inside go-oidc
	raw := make(url.Values)
	raw["id_token"] = []string{rawIDToken}
	token = token.WithExtra(raw)

	return token, nil
}
*/

func setSessionToken(session *sessions.Session, valueName string, value *oauth2.Token) error {
	b, err := json.Marshal(value)
	if err != nil {
		log.Printf("Could not convert token to json: %v", err)
		return err
	}
	session.Values[valueName] = b
	return nil
}

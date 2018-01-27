package oidcauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	oidc "github.com/coreos/go-oidc"
	"github.com/quasoft/memstore"
	"github.com/quasoft/oauth2state"
	"golang.org/x/oauth2"
)

// Stub replacement for IDTokenVerifier in go-oidc package
type stubVerifier struct {
	verifyOK bool
}

func (v *stubVerifier) Verify(ctx context.Context, token string) (*oidc.IDToken, error) {
	if !v.verifyOK {
		return nil, fmt.Errorf("simulated verify failure")
	}
	return &oidc.IDToken{}, nil
}

// Stub replacement for Config in oauth2 package
type stubOAuthPackage struct {
	oauth2.Config
	exchangeOK bool
}

func (o *stubOAuthPackage) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	if !o.exchangeOK {
		return nil, fmt.Errorf("simulated authorization code rejection")
	}
	tok := oauth2.Token{}
	raw := make(map[string]interface{})
	raw["id_token"] = "12345"
	return tok.WithExtra(raw), nil
}

// Stub implementation of ValueGenerator for generation of predictable values
type StubValueGenerator struct {
	count int
}

func (s StubValueGenerator) String() string {
	curr := s.count
	s.count++
	return strconv.Itoa(curr)
}

// newAuthenticator creates an Authenticator for use in tests.
func newAuthenticator() *Authenticator {
	config := &Config{
		ClientID:         "test1",
		ClientSecret:     "efed2228-081e-4226-8135-55df6e9fa369",
		IssuerURL:        "http://idp.local/auth/realms/test",
		LogoutURL:        "http://idp.local/auth/realms/test/protocol/openid-connect/logout",
		CallbackURL:      "http://app.local/auth/callback",
		DefaultReturnURL: "http://app.local",
		AllowedOrigins:   []string{"http://app.local", "http://idp.local"},
		SessionStore:     memstore.NewMemStore([]byte("1234"), []byte("1234567890123456")),
		TokenStore:       memstore.NewMemStore([]byte("1234"), []byte("1234567890123456")),
		StateStore:       oauth2state.NewMemStateStore(),
	}

	verifier := stubVerifier{
		verifyOK: true, // return OK in simulated calls to Verify
	}
	oauthCfg := stubOAuthPackage{
		Config: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "http://idp.local/auth/realms/test/protocol/openid-connect/auth",
				TokenURL: "http://idp.local/auth/realms/test/protocol/openid-connect/token",
			},
			RedirectURL: config.CallbackURL,
			Scopes:      []string{oidc.ScopeOpenID},
		},
		exchangeOK: true, // return OK in simulated calls to Exchange
	}

	var auth = &Authenticator{
		Config:   *config,
		verifier: &verifier,
		oauth2:   &oauthCfg,
	}
	return auth
}

func TestHandleAuthResponse_NoState(t *testing.T) {
	auth := newAuthenticator()

	r := httptest.NewRequest("GET", "http://localhost:5556/auth/callback&response_type=code&scope=openid", nil)
	w := httptest.NewRecorder()

	handler := auth.HandleAuthResponse()
	handler.ServeHTTP(w, r)

	got := w.Result().StatusCode
	if got != http.StatusBadRequest {
		t.Errorf(
			"Got status %v for authentication response without state, wanted StatusBadRequest (%v)",
			got,
			http.StatusBadRequest,
		)
	}
}

func TestHandleAuthResponse_InvalidState(t *testing.T) {
	auth := newAuthenticator()

	r := httptest.NewRequest("GET", "http://localhost:5556/auth/callback&response_type=code&scope=openid&state=12345678901234567890", nil)
	w := httptest.NewRecorder()

	handler := auth.HandleAuthResponse()
	handler.ServeHTTP(w, r)

	got := w.Result().StatusCode
	if got != http.StatusBadRequest {
		t.Errorf(
			"Got status %v for authentication response without state, wanted StatusBadRequest (%v)",
			got,
			http.StatusBadRequest,
		)
	}
}

func TestHandleAuthResponse_OK(t *testing.T) {
	auth := newAuthenticator()
	stateStore := auth.Config.StateStore.(*oauth2state.MemStateStore)
	stateStore.SetValueGenerator(StubValueGenerator{42})
	stateStore.NewState("http://app.local/protected")

	r := httptest.NewRequest("GET", "http://app.local/auth/callback?state=42&session_state=89cb0b80-c39d-4486-9c71-4aa1047d38e8&code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..8D6XG5XFIKmQ47Y3rroDzg.zDadOzaRanO15lcoOzirZRpQ2hXKgdoKp3Lo5mox1aNfr1wkW7dR70ppQZAMnMqjV1Tu1GrpVGJ8AjJX4-z7kg17-bV5Kql0cDum53wvkvhFypSH7Yz5BCRA0QyA47_e9hDhu3gcieEkivSSLB2oAdk9hA-Ha-C7I4VOGxcWATGBXMY4925hx4nDEcEjAqBOteo9Lxsy_8fDnTnglSgecUV04U_dp0BVg0_l9a4fHvEhkF4VyW5fmCqKzkqMwtbA.4K51w_Ip8T-XiuXOnlymdw", nil)
	r.Header.Set("Origin", "http://idp.local")
	w := httptest.NewRecorder()

	handler := auth.HandleAuthResponse()
	handler.ServeHTTP(w, r)

	got := w.Result().StatusCode
	if got != http.StatusFound {
		t.Errorf(
			"Got status %v for valid authentication response, wanted StatusFound (%v)",
			got,
			http.StatusFound,
		)
	}

	gotLoc := w.Result().Header.Get("Location")
	wantLoc := "http://app.local/protected"
	if gotLoc != wantLoc {
		t.Errorf(
			"Got redirect location %v, wanted %v",
			gotLoc,
			wantLoc,
		)
	}
}

func TestHandleAuthResponse_OAuth2Exchange_Fail(t *testing.T) {
	auth := newAuthenticator()
	auth.oauth2.(*stubOAuthPackage).exchangeOK = false // return error in the simulated call to Exchange

	stateStore := auth.Config.StateStore.(*oauth2state.MemStateStore)
	stateStore.SetValueGenerator(StubValueGenerator{42})
	stateStore.NewState("http://app.local/protected")

	r := httptest.NewRequest("GET", "http://app.local/auth/callback?state=42&session_state=89cb0b80-c39d-4486-9c71-4aa1047d38e8&code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..8D6XG5XFIKmQ47Y3rroDzg.zDadOzaRanO15lcoOzirZRpQ2hXKgdoKp3Lo5mox1aNfr1wkW7dR70ppQZAMnMqjV1Tu1GrpVGJ8AjJX4-z7kg17-bV5Kql0cDum53wvkvhFypSH7Yz5BCRA0QyA47_e9hDhu3gcieEkivSSLB2oAdk9hA-Ha-C7I4VOGxcWATGBXMY4925hx4nDEcEjAqBOteo9Lxsy_8fDnTnglSgecUV04U_dp0BVg0_l9a4fHvEhkF4VyW5fmCqKzkqMwtbA.4K51w_Ip8T-XiuXOnlymdw", nil)
	r.Header.Set("Origin", "http://idp.local")
	w := httptest.NewRecorder()

	handler := auth.HandleAuthResponse()
	handler.ServeHTTP(w, r)

	got := w.Result().StatusCode
	if got != http.StatusBadRequest {
		t.Errorf(
			"Got status %v for simulated authentication response failure, wanted StatusBadRequest (%v)",
			got,
			http.StatusBadRequest,
		)
	}
}

func TestHandleAuthResponse_OAuth2Verifier_Fail(t *testing.T) {
	auth := newAuthenticator()
	auth.verifier.(*stubVerifier).verifyOK = false // return error in the simulated call to Verify

	stateStore := auth.Config.StateStore.(*oauth2state.MemStateStore)
	stateStore.SetValueGenerator(StubValueGenerator{42})
	stateStore.NewState("http://app.local/protected")

	r := httptest.NewRequest("GET", "http://app.local/auth/callback?state=42&session_state=89cb0b80-c39d-4486-9c71-4aa1047d38e8&code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..8D6XG5XFIKmQ47Y3rroDzg.zDadOzaRanO15lcoOzirZRpQ2hXKgdoKp3Lo5mox1aNfr1wkW7dR70ppQZAMnMqjV1Tu1GrpVGJ8AjJX4-z7kg17-bV5Kql0cDum53wvkvhFypSH7Yz5BCRA0QyA47_e9hDhu3gcieEkivSSLB2oAdk9hA-Ha-C7I4VOGxcWATGBXMY4925hx4nDEcEjAqBOteo9Lxsy_8fDnTnglSgecUV04U_dp0BVg0_l9a4fHvEhkF4VyW5fmCqKzkqMwtbA.4K51w_Ip8T-XiuXOnlymdw", nil)
	r.Header.Set("Origin", "http://idp.local")
	w := httptest.NewRecorder()

	handler := auth.HandleAuthResponse()
	handler.ServeHTTP(w, r)

	got := w.Result().StatusCode
	if got != http.StatusBadRequest {
		t.Errorf(
			"Got status %v for simulated authentication response failure, wanted StatusBadRequest (%v)",
			got,
			http.StatusBadRequest,
		)
	}
}

func TestAuthWithSession_NoSession(t *testing.T) {
	auth := newAuthenticator()
	stateStore := auth.Config.StateStore.(*oauth2state.MemStateStore)
	stateStore.SetValueGenerator(StubValueGenerator{42})

	r := httptest.NewRequest("GET", "http://app.local", nil)
	w := httptest.NewRecorder()

	handler := auth.AuthWithSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Protected handler should not have been called for requests without a valid session")
	}))

	handler.ServeHTTP(w, r)

	got := w.Result().StatusCode
	if got != http.StatusFound && got != http.StatusTemporaryRedirect {
		t.Errorf(
			"Got status %v for request without valid session, wanted StatusFound (%v) or StatusTemporaryRedirect (%v)",
			got,
			http.StatusFound,
			http.StatusTemporaryRedirect,
		)
	}

	gotLoc := w.Result().Header.Get("Location")
	wantLoc := "http://idp.local/auth/realms/test/protocol/openid-connect/auth?client_id=test1&redirect_uri=http%3A%2F%2Fapp.local%2Fauth%2Fcallback&response_type=code&scope=openid&state=42"
	if gotLoc != wantLoc {
		t.Errorf(
			"Got redirect location %v, wanted %v",
			gotLoc,
			wantLoc,
		)
	}
}

func TestAuthWithSession_CORS_GET(t *testing.T) {
	auth := newAuthenticator()

	r := httptest.NewRequest("GET", "http://app.local", nil)
	r.Header.Set("Origin", "http://adversary.local")
	w := httptest.NewRecorder()

	handler := auth.AuthWithSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Protected handler should not have been called for CORS GET")
	}))

	handler.ServeHTTP(w, r)

	got := w.Result().StatusCode
	if got != http.StatusForbidden {
		t.Errorf(
			"Got status %v for CORS GET, wanted StatusForbidden (%v)",
			got,
			http.StatusForbidden,
		)
	}
}

func TestAuthWithSession_CORS_OPTIONS(t *testing.T) {
	auth := newAuthenticator()

	r := httptest.NewRequest("OPTIONS", "http://app.local", nil)
	r.Header.Set("Referer", "http://adversary.local")
	w := httptest.NewRecorder()

	handler := auth.AuthWithSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Protected handler should not have been called for CORS OPTIONS")
	}))

	handler.ServeHTTP(w, r)

	gotCode := w.Result().StatusCode
	if gotCode != http.StatusOK {
		t.Errorf(
			"Got status %v for CORS OPTIONS, wanted StatusOK (%v)",
			gotCode,
			http.StatusOK,
		)
	}

	gotAllow := w.Result().Header.Get("Access-Control-Allow-Origin")
	wantAllow := "http://app.local"
	if gotAllow != wantAllow {
		t.Errorf(
			"Got Access-Control-Allow-Origin: '%v' for CORS OPTIONS, wanted '%v'",
			gotAllow,
			wantAllow,
		)
	}
}

func TestAuthWithSession_NoOrigin_POST(t *testing.T) {
	auth := newAuthenticator()

	r := httptest.NewRequest("POST", "http://app.local", nil)
	r.Header.Set("Origin", "")
	r.Header.Set("Referer", "")
	w := httptest.NewRecorder()

	handler := auth.AuthWithSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Protected handler should not have been called for POST requests without origin")
	}))

	handler.ServeHTTP(w, r)

	got := w.Result().StatusCode
	if got != http.StatusForbidden {
		t.Errorf(
			"Got status %v for POST without origin, wanted StatusForbidden (%v)",
			got,
			http.StatusForbidden,
		)
	}
}

func TestAuthWithSession_NoAllowedOrigins(t *testing.T) {
	auth := newAuthenticator()
	auth.Config.AllowedOrigins = []string{}

	r := httptest.NewRequest("POST", "http://app.local", nil)
	r.Header.Set("Origin", "http://app.local")
	r.Header.Set("Referer", "http://app.local")
	w := httptest.NewRecorder()

	handler := auth.AuthWithSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Protected handler should not have been called if no AllowedOrigins have been configured")
	}))

	handler.ServeHTTP(w, r)

	got := w.Result().StatusCode
	if got != http.StatusForbidden {
		t.Errorf(
			"Got status %v for POST without configured AllowOrigins, wanted StatusForbidden (%v)",
			got,
			http.StatusForbidden,
		)
	}
}

func TestAuthWithSession_ValidSession(t *testing.T) {
	auth := newAuthenticator()

	r := httptest.NewRequest("GET", "http://app.local", nil)
	w := httptest.NewRecorder()

	auth.createSession(w, r, &oauth2.Token{}, &oidc.IDToken{}, &json.RawMessage{})

	handlerCalled := false
	handler := auth.AuthWithSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	handler.ServeHTTP(w, r)

	got := w.Result().StatusCode
	if got != http.StatusOK {
		t.Errorf(
			"Got status %v for request with valid session, wanted StatusOK (%v)",
			got,
			http.StatusOK,
		)
	}

	if !handlerCalled {
		t.Error("Protected handler was not called, event though session is valid")
	}
}

func TestLogout(t *testing.T) {
	auth := newAuthenticator()
	stateStore := auth.Config.StateStore.(*oauth2state.MemStateStore)
	stateStore.SetValueGenerator(StubValueGenerator{42})

	r := httptest.NewRequest("GET", "http://app.local", nil)
	w := httptest.NewRecorder()
	auth.createSession(w, r, &oauth2.Token{}, &oidc.IDToken{}, &json.RawMessage{})

	r = httptest.NewRequest("GET", "http://app.local/auth/logout", nil)
	w = httptest.NewRecorder()
	handler := auth.Logout("http://app.local/just-logged-out")
	handler.ServeHTTP(w, r)

	r = httptest.NewRequest("GET", "http://app.local", nil)
	w = httptest.NewRecorder()

	handler = auth.AuthWithSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Protected handler should not be called for logged out session")
	}))
	handler.ServeHTTP(w, r)

	got := w.Result().StatusCode
	if got != http.StatusFound && got != http.StatusTemporaryRedirect {
		t.Errorf(
			"Got status %v for request without valid session, wanted StatusFound (%v) or StatusTemporaryRedirect (%v)",
			got,
			http.StatusFound,
			http.StatusTemporaryRedirect,
		)
	}

	gotLoc := w.Result().Header.Get("Location")
	wantLoc := "http://idp.local/auth/realms/test/protocol/openid-connect/auth?client_id=test1&redirect_uri=http%3A%2F%2Fapp.local%2Fauth%2Fcallback&response_type=code&scope=openid&state=42"
	if gotLoc != wantLoc {
		t.Errorf(
			"Got redirect location %v, wanted %v",
			gotLoc,
			wantLoc,
		)
	}
}

func TestGetAuthInfo(t *testing.T) {
	auth := newAuthenticator()

	r := httptest.NewRequest("GET", "http://app.local", nil)
	w := httptest.NewRecorder()

	idToken := oidc.IDToken{
		Subject: "SomeUserID",
	}
	jsonClaims, _ := json.Marshal(map[string]string{
		"name":  "Some User",
		"email": "email@email.local",
	})
	rawClaims := json.RawMessage(jsonClaims)
	auth.createSession(w, r, &oauth2.Token{}, &idToken, &rawClaims)

	gotSub, gotClaims, err := auth.GetAuthInfo(r)
	if err != nil {
		t.Errorf("GetAuthInfo() failed with valid session data. Error: %v", err)
	}

	if gotSub != idToken.Subject {
		t.Errorf(
			"GetAuthInfo() subject = '%v', want '%v'",
			gotSub,
			idToken.Subject,
		)
	}

	if gotClaims != string(rawClaims) {
		t.Errorf(
			"GetAuthInfo() claims = '%v', want '%v'",
			gotClaims,
			string(rawClaims),
		)
	}
}

func TestGetClaim(t *testing.T) {
	auth := newAuthenticator()

	r := httptest.NewRequest("GET", "http://app.local", nil)
	w := httptest.NewRecorder()

	idToken := oidc.IDToken{
		Subject: "SomeUserID",
	}
	jsonClaims, _ := json.Marshal(map[string]string{
		"name":  "Some User",
		"email": "email@email.local",
	})
	rawClaims := json.RawMessage(jsonClaims)
	auth.createSession(w, r, &oauth2.Token{}, &idToken, &rawClaims)

	m, err := auth.GetClaims(r)
	if err != nil {
		t.Errorf("GetClaims() failed with valid session data. Error: %v", err)
	}

	got, ok := m["name"]
	if !ok {
		t.Errorf("GetClaims() claim['%v'] not found", "name")
	} else {
		if got != "Some User" {
			t.Errorf("GetClaims() got claim['%v'] = '%v', want '%v'", "name", got, "Some User")
		}
	}
}

func TestGetToken(t *testing.T) {
	auth := newAuthenticator()

	r := httptest.NewRequest("GET", "http://app.local", nil)
	w := httptest.NewRecorder()

	want := oauth2.Token{
		AccessToken: "1234567890",
	}
	auth.createSession(w, r, &want, &oidc.IDToken{}, &json.RawMessage{})

	got, err := auth.GetToken(r)
	if err != nil {
		t.Errorf("GetToken() failed with valid session data. Error: %v", err)
	}

	if got.AccessToken != want.AccessToken {
		t.Errorf("GetToken().AccessToken got = '%v', want '%v'", got.AccessToken, want.AccessToken)
	}
}

func TestValidate_Incomplete(t *testing.T) {
	auth := newAuthenticator()
	auth.Config.ClientID = ""
	err := auth.Config.Validate()
	if err == nil {
		t.Errorf("Config.Validate() = true for a config without ClientID value, want false")
	}

	auth = newAuthenticator()
	auth.Config.IssuerURL = ""
	err = auth.Config.Validate()
	if err == nil {
		t.Errorf("Config.Validate() = true for a config without IssuerURL value, want false")
	}

	auth = newAuthenticator()
	auth.Config.LogoutURL = ""
	err = auth.Config.Validate()
	if err == nil {
		t.Errorf("Config.Validate() = true for a config without LogoutURL value, want false")
	}

	auth = newAuthenticator()
	auth.Config.CallbackURL = ""
	err = auth.Config.Validate()
	if err == nil {
		t.Errorf("Config.Validate() = true for a config without CallbackURL value, want false")
	}

	auth = newAuthenticator()
	auth.Config.CallbackURL = "app.local/auth/callback"
	err = auth.Config.Validate()
	if err == nil {
		t.Errorf("Config.Validate() = true for a config with relative CallbackURL, want false")
	}

	auth = newAuthenticator()
	auth.Config.AllowedOrigins = []string{}
	err = auth.Config.Validate()
	if err == nil {
		t.Errorf("Config.Validate() = true for a config with empty AllowedOrigins, want false")
	}

	auth = newAuthenticator()
	auth.Config.AllowedOrigins = []string{""}
	err = auth.Config.Validate()
	if err == nil {
		t.Errorf("Config.Validate() = true for a config with empty string in AllowedOrigins, want false")
	}

	auth = newAuthenticator()
	auth.Config.AllowedOrigins = []string{"http://app.local", "*", "http://idp.local"}
	err = auth.Config.Validate()
	if err == nil {
		t.Errorf("Config.Validate() = true for a config with * in AllowedOrigins, want false")
	}
}

func TestValidate_Complete(t *testing.T) {
	auth := newAuthenticator()
	err := auth.Config.Validate()
	if err != nil {
		t.Errorf("Config.Validate() = false for a valid config, want true")
	}
}

func BenchmarkAuthWithSession_Race(b *testing.B) {
	log.SetOutput(ioutil.Discard)
	for i := 0; i < 200; i++ {
		go func() {
			auth := newAuthenticator()

			r := httptest.NewRequest("GET", "http://app.local", nil)
			w := httptest.NewRecorder()

			auth.createSession(w, r, &oauth2.Token{}, &oidc.IDToken{}, &json.RawMessage{})

			handler := auth.AuthWithSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				log.Print("Handler called from go routine")
			}))

			handler.ServeHTTP(w, r)
		}()
	}
}

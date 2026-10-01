package oidcrp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yundera/appshield/internal/config"
	"github.com/yundera/appshield/internal/jose"
	"github.com/yundera/appshield/internal/session"
)

const (
	testNowMS = int64(1_700_000_000_000)
	clientID  = "test-client"
)

func now() time.Time { return time.UnixMilli(testNowMS) }

// fakeOP is a minimal OpenID Provider: discovery, JWKS and a token endpoint
// that mints ID tokens we control.
type fakeOP struct {
	*httptest.Server
	key *jose.Key
	// public, when set, is the issuer the OP claims to be — in discovery and in
	// every token — while actually listening on URL. That is a deployment where
	// the issuer's public hostname and its on-box address differ.
	public    string
	idClaims  map[string]any // claims to put in the next id_token
	sawPKCE   atomic.Bool
	tokenHits atomic.Int32
}

func (op *fakeOP) issuer() string {
	if op.public != "" {
		return op.public
	}
	return op.URL
}

func newFakeOP(t *testing.T) *fakeOP {
	t.Helper()
	key, err := jose.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	op := &fakeOP{key: key}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                 op.issuer(),
			"authorization_endpoint": op.issuer() + "/auth",
			"token_endpoint":         op.issuer() + "/token",
			"jwks_uri":               op.issuer() + "/jwks",
			"end_session_endpoint":   op.issuer() + "/logout",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, op.key.PublicJWKS())
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		op.tokenHits.Add(1)
		_ = r.ParseForm()
		if r.PostFormValue("code_verifier") != "" {
			op.sawPKCE.Store(true)
		}
		claims := map[string]any{
			"iss": op.issuer(),
			"aud": clientID,
			"sub": "user-1",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		}
		for k, v := range op.idClaims {
			claims[k] = v
		}
		idToken, err := op.key.Sign("JWT", claims)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, map[string]any{
			"access_token": "at-1",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	})

	op.Server = httptest.NewServer(mux)
	t.Cleanup(op.Close)
	return op
}

// signLogoutToken mints a back-channel logout token. Fields are deliberately
// overridable so each mandatory check can be tested in isolation.
func (op *fakeOP) signLogoutToken(t *testing.T, override map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"iss": op.issuer(),
		"aud": clientID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(2 * time.Minute).Unix(),
		"jti": "logout-1",
		"events": map[string]any{
			backchannelEvent: map[string]any{},
		},
		"sid": "sid-1",
	}
	for k, v := range override {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	tok, err := op.key.Sign("logout+jwt", claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// fakeRegistrar answers /register the way the real one does.
type fakeRegistrar struct {
	*httptest.Server
	calls    atomic.Int32
	failNext atomic.Bool
	respond  func() map[string]any
}

func newFakeRegistrar(t *testing.T, op *fakeOP) *fakeRegistrar {
	t.Helper()
	reg := &fakeRegistrar{}
	reg.respond = func() map[string]any {
		return map[string]any{
			"client_id":     clientID,
			"client_secret": "test-secret",
			"issuer_url":    op.URL,
		}
	}
	reg.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/register" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		reg.calls.Add(1)
		if reg.failNext.CompareAndSwap(true, false) {
			http.Error(w, "registrar is down", http.StatusInternalServerError)
			return
		}
		writeJSON(w, reg.respond())
	}))
	t.Cleanup(reg.Close)
	return reg
}

func newClient(t *testing.T, reg *fakeRegistrar, extra map[string]string) (*Client, *session.Store, http.Handler) {
	t.Helper()
	kv := map[string]string{
		"BACKEND_HOST":           "whoami",
		"BACKEND_PORT":           "80",
		"LISTEN_PORT":            "80",
		"OIDC_REGISTRAR_URL":     reg.URL,
		"APP_NAME":               "beacon",
		"REDIRECT_HOST_SUFFIXES": "example.com",
	}
	for k, v := range extra {
		kv[k] = v
	}
	cfg, _, err := config.Load(func(k string) string { return kv[k] }, "beacon")
	if err != nil {
		t.Fatal(err)
	}
	store := session.Open("", now)
	t.Cleanup(func() { store.Close() })

	c := New(cfg, store, now)
	mux := http.NewServeMux()
	c.RegisterRoutes(mux)
	return c, store, mux
}

// request builds a request that looks like it arrived through Caddy on the
// app's canonical host.
func request(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Host = "beacon-example.com"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "beacon-example.com")
	return r
}

// --- login ---------------------------------------------------------------

func TestLoginRedirectsWithPKCEAndState(t *testing.T) {
	op := newFakeOP(t)
	reg := newFakeRegistrar(t, op)
	_, _, mux := newClient(t, reg, nil)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, request("GET", "/nhl-auth/oidc/login?redirect=%2Fdash"))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302: %s", rec.Code, rec.Body.String())
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u.String(), op.URL+"/auth") {
		t.Errorf("Location = %q, want the OP authorization endpoint", u)
	}
	q := u.Query()
	if q.Get("code_challenge") == "" {
		t.Error("no PKCE challenge was sent")
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
	if q.Get("state") == "" {
		t.Error("no state was sent")
	}
	if got := q.Get("redirect_uri"); got != "https://beacon-example.com"+CallbackPath {
		t.Errorf("redirect_uri = %q", got)
	}
	if got := q.Get("response_type"); got != "code" {
		t.Errorf("response_type = %q, want code", got)
	}
}

// login is the first thing that ever contacts the registrar.
func TestRegistrationHappensOnceAndIsShared(t *testing.T) {
	op := newFakeOP(t)
	reg := newFakeRegistrar(t, op)
	_, _, mux := newClient(t, reg, nil)

	for i := 0; i < 3; i++ {
		mux.ServeHTTP(httptest.NewRecorder(), request("GET", "/nhl-auth/oidc/login"))
	}
	if n := reg.calls.Load(); n != 1 {
		t.Errorf("registrar was called %d times, want 1", n)
	}
}

// A failed registration must not be cached, or one blip poisons every later
// login for the life of the process.
func TestFailedRegistrationIsRetried(t *testing.T) {
	op := newFakeOP(t)
	reg := newFakeRegistrar(t, op)
	reg.failNext.Store(true)
	_, _, mux := newClient(t, reg, nil)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, request("GET", "/nhl-auth/oidc/login"))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	// The upstream error text must not reach the browser.
	if strings.Contains(rec.Body.String(), "registrar is down") {
		t.Error("the upstream error was echoed to the client")
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, request("GET", "/nhl-auth/oidc/login"))
	if rec.Code != http.StatusFound {
		t.Errorf("retry status = %d, want 302 — a failure was cached", rec.Code)
	}
}

// --- internal issuer -----------------------------------------------------

// publicIssuer cannot be resolved, so any request the gate sends to it rather
// than to the internal address fails the test on its own.
const publicIssuer = "https://auth-example.invalid"

func newInternalOP(t *testing.T) (*fakeOP, *fakeRegistrar) {
	t.Helper()
	op := newFakeOP(t)
	op.public = publicIssuer
	reg := newFakeRegistrar(t, op)
	reg.respond = func() map[string]any {
		return map[string]any{
			"client_id":           clientID,
			"client_secret":       "test-secret",
			"issuer_url":          publicIssuer,
			"internal_issuer_url": op.URL,
		}
	}
	return op, reg
}

// Discovery, the code exchange and the JWKS fetch all go to the internal
// address, while the identity and everything the browser sees stay public.
func TestInternalIssuerKeepsTheBackChannelOnBox(t *testing.T) {
	op, reg := newInternalOP(t)
	op.idClaims = map[string]any{"sid": "sid-1"}
	c, store, mux := newClient(t, reg, nil)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, request("GET", "/nhl-auth/oidc/login"))
	if rec.Code != http.StatusFound {
		t.Fatalf("login status = %d, want 302 — discovery did not use the internal address: %s", rec.Code, rec.Body.String())
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if !strings.HasPrefix(loc.String(), publicIssuer+"/auth") {
		t.Errorf("Location = %q, want the PUBLIC authorization endpoint", loc)
	}

	rec = callback(t, mux, loc.Query().Get("state"))
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302 — the exchange or the JWKS fetch left the box: %s", rec.Code, rec.Body.String())
	}
	if n := op.tokenHits.Load(); n != 1 {
		t.Errorf("internal token endpoint was hit %d times, want 1", n)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %+v", cookies)
	}
	sess, ok := store.Get(cookies[0].Value)
	if !ok {
		t.Fatal("no session was created")
	}

	if got := c.EndSessionURL(request("GET", "/"), sess); !strings.HasPrefix(got, publicIssuer+"/logout?") {
		t.Errorf("end-session URL = %q, want the PUBLIC endpoint", got)
	}

	// A logout token is issued by — and verified against — the public identity.
	form := strings.NewReader("logout_token=" + url.QueryEscape(op.signLogoutToken(t, nil)))
	req := httptest.NewRequest("POST", BackchannelPath, form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || store.Count() != 0 {
		t.Errorf("back-channel logout: status %d, %d session(s) left", rec.Code, store.Count())
	}
}

// An internal address that does not answer is a failed login, not a quiet
// return to the public path — and it is retried, not cached.
func TestUnusableInternalIssuerFailsInsteadOfFallingBack(t *testing.T) {
	op := newFakeOP(t) // public issuer == a server that WOULD answer
	reg := newFakeRegistrar(t, op)
	internal := "::not a url::"
	reg.respond = func() map[string]any {
		return map[string]any{
			"client_id":           clientID,
			"client_secret":       "test-secret",
			"issuer_url":          op.URL,
			"internal_issuer_url": internal,
		}
	}
	_, _, mux := newClient(t, reg, nil)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, request("GET", "/nhl-auth/oidc/login"))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}

	internal = op.URL
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, request("GET", "/nhl-auth/oidc/login"))
	if rec.Code != http.StatusFound {
		t.Errorf("retry status = %d, want 302 — the failure was cached", rec.Code)
	}
}

type recordingTransport struct{ got *http.Request }

func (rt *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.got = r
	return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Request: r}, nil
}

func TestBackchannelRewritesOnlyURLsUnderTheIssuer(t *testing.T) {
	for _, tc := range []struct {
		name, issuer, internal, request, want string
	}{
		{"origin", "https://auth.example.com", "http://dex:5556", "https://auth.example.com/token", "http://dex:5556/token"},
		{"query survives", "https://auth.example.com", "http://dex:5556", "https://auth.example.com/keys?x=1", "http://dex:5556/keys?x=1"},
		{"issuer with a path", "https://example.com/dex", "http://dex:5556/dex/", "https://example.com/dex/token", "http://dex:5556/dex/token"},
		{"path moves", "https://example.com/dex", "http://dex:5556", "https://example.com/dex/token", "http://dex:5556/token"},
		{"sibling path", "https://example.com/dex", "http://dex:5556", "https://example.com/dexter/token", "https://example.com/dexter/token"},
		{"outside the path", "https://example.com/dex", "http://dex:5556", "https://example.com/token", "https://example.com/token"},
		{"another host", "https://auth.example.com", "http://dex:5556", "https://other.example.com/token", "https://other.example.com/token"},
		{"another scheme", "https://auth.example.com", "http://dex:5556", "http://auth.example.com/token", "http://auth.example.com/token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &recordingTransport{}
			c := &Client{http: &http.Client{Transport: rt}}
			hc, err := c.backchannelClient(tc.issuer, tc.internal)
			if err != nil {
				t.Fatal(err)
			}
			req, _ := http.NewRequest("GET", tc.request, nil)
			resp, err := hc.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if got := rt.got.URL.String(); got != tc.want {
				t.Errorf("dialled %q, want %q", got, tc.want)
			}
			if req.URL.String() != tc.request {
				t.Errorf("the caller's request was modified: %q", req.URL)
			}
		})
	}
}

// startLogin drives the login leg and returns the state the gate generated.
func startLogin(t *testing.T, mux http.Handler, redirect string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	target := "/nhl-auth/oidc/login"
	if redirect != "" {
		target += "?redirect=" + url.QueryEscape(redirect)
	}
	mux.ServeHTTP(rec, request("GET", target))
	if rec.Code != http.StatusFound {
		t.Fatalf("login status = %d: %s", rec.Code, rec.Body.String())
	}
	u, _ := url.Parse(rec.Header().Get("Location"))
	return u.Query().Get("state")
}

func callback(t *testing.T, mux http.Handler, state string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, request("GET", CallbackPath+"?code=auth-code&state="+url.QueryEscape(state)))
	return rec
}

func TestCallbackCreatesSessionAndRedirects(t *testing.T) {
	op := newFakeOP(t)
	op.idClaims = map[string]any{
		"preferred_username": "alice",
		"email":              "alice@example.com",
		"name":               "Alice Example",
		"groups":             []string{"admins", "staff"},
		"sid":                "sid-1",
	}
	reg := newFakeRegistrar(t, op)
	_, store, mux := newClient(t, reg, nil)

	state := startLogin(t, mux, "/dash?tab=2")
	rec := callback(t, mux, state)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/dash?tab=2" {
		t.Errorf("Location = %q, want the original target", got)
	}
	if !op.sawPKCE.Load() {
		t.Error("the code exchange did not send a code_verifier")
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != session.CookieName {
		t.Fatalf("cookies = %+v", cookies)
	}
	c := cookies[0]
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Domain != "" {
		t.Errorf("cookie attributes wrong: %+v", c)
	}

	sess, ok := store.Get(c.Value)
	if !ok {
		t.Fatal("no session was created")
	}
	if sess.OIDCSub != "user-1" || sess.OIDCSid != "sid-1" || sess.IDToken == "" {
		t.Errorf("session = %+v", sess)
	}
	if sess.Claims == nil || sess.Claims.User != "alice" || sess.Claims.Email != "alice@example.com" ||
		sess.Claims.Name != "Alice Example" || len(sess.Claims.Groups) != 2 {
		t.Errorf("claims = %+v", sess.Claims)
	}
}

// user falls back preferred_username -> email -> sub.
func TestClaimUserFallback(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims map[string]any
		want   string
	}{
		{"preferred_username", map[string]any{"preferred_username": "alice", "email": "a@e.com"}, "alice"},
		{"email", map[string]any{"email": "a@e.com"}, "a@e.com"},
		{"sub", map[string]any{}, "user-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op := newFakeOP(t)
			op.idClaims = tc.claims
			reg := newFakeRegistrar(t, op)
			_, store, mux := newClient(t, reg, nil)

			state := startLogin(t, mux, "")
			rec := callback(t, mux, state)
			cookies := rec.Result().Cookies()
			if len(cookies) == 0 {
				t.Fatalf("no cookie set, status %d: %s", rec.Code, rec.Body.String())
			}
			sess, ok := store.Get(cookies[0].Value)
			if !ok {
				t.Fatal("no session")
			}
			if sess.Claims.User != tc.want {
				t.Errorf("user = %q, want %q", sess.Claims.User, tc.want)
			}
		})
	}
}

func TestCallbackRejectsUnknownState(t *testing.T) {
	op := newFakeOP(t)
	reg := newFakeRegistrar(t, op)
	_, store, mux := newClient(t, reg, nil)
	startLogin(t, mux, "") // register a real flow so the client is initialised

	rec := callback(t, mux, "not-a-real-state")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if store.Count() != 0 {
		t.Error("a session was created for an unknown state")
	}
}

// The authorization code and its state are single use.
func TestCallbackStateCannotBeReplayed(t *testing.T) {
	op := newFakeOP(t)
	reg := newFakeRegistrar(t, op)
	c, _, mux := newClient(t, reg, nil)

	state := startLogin(t, mux, "")
	if rec := callback(t, mux, state); rec.Code != http.StatusFound {
		t.Fatalf("first callback failed: %d", rec.Code)
	}
	if rec := callback(t, mux, state); rec.Code != http.StatusBadRequest {
		t.Errorf("replayed state produced %d, want 400", rec.Code)
	}
	if c.PendingFlows() != 0 {
		t.Errorf("pending flows = %d, want 0", c.PendingFlows())
	}
}

func TestCallbackPropagatesProviderError(t *testing.T) {
	op := newFakeOP(t)
	reg := newFakeRegistrar(t, op)
	_, _, mux := newClient(t, reg, nil)
	startLogin(t, mux, "")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, request("GET", CallbackPath+"?error=access_denied&state=x"))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// Refusing before minting avoids leaving a cookie that makes every subsequent
// request an unclearable 403.
func TestGroupDenialRefusesBeforeCreatingASession(t *testing.T) {
	op := newFakeOP(t)
	op.idClaims = map[string]any{"groups": []string{"guests"}}
	reg := newFakeRegistrar(t, op)
	_, store, mux := newClient(t, reg, map[string]string{"OIDC_REQUIRED_GROUPS": "admins"})

	state := startLogin(t, mux, "")
	rec := callback(t, mux, state)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if store.Count() != 0 {
		t.Error("a session was created for a user who is not allowed in")
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("a cookie was set despite the denial")
	}
}

func TestGroupMemberIsAdmitted(t *testing.T) {
	op := newFakeOP(t)
	op.idClaims = map[string]any{"groups": []string{"staff", "admins"}}
	reg := newFakeRegistrar(t, op)
	_, store, mux := newClient(t, reg, map[string]string{"OIDC_REQUIRED_GROUPS": "admins"})

	state := startLogin(t, mux, "")
	if rec := callback(t, mux, state); rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if store.Count() != 1 {
		t.Error("no session was created for an allowed user")
	}
}

// --- RP-initiated logout -------------------------------------------------

func TestEndSessionURL(t *testing.T) {
	op := newFakeOP(t)
	reg := newFakeRegistrar(t, op)
	c, store, mux := newClient(t, reg, nil)

	state := startLogin(t, mux, "")
	rec := callback(t, mux, state)
	sess, _ := store.Get(rec.Result().Cookies()[0].Value)

	raw := c.EndSessionURL(request("GET", "/nhl-auth/logout"), sess)
	if raw == "" {
		t.Fatal("no end-session URL was produced")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, op.URL+"/logout") {
		t.Errorf("URL = %q", raw)
	}
	q := u.Query()
	if q.Get("id_token_hint") != sess.IDToken {
		t.Error("id_token_hint missing or wrong")
	}
	if q.Get("client_id") != clientID {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if got := q.Get("post_logout_redirect_uri"); got != "https://beacon-example.com"+PostLogoutPath {
		t.Errorf("post_logout_redirect_uri = %q", got)
	}
}

// The OP has rotated away the key that signed this session's ID token — what a
// 30-day gate session meets at an OP that keeps a key for about a day. A hint
// the OP cannot verify is refused outright (Dex: 400), so it is left out, and
// post_logout_redirect_uri with it: the OP only honours that for a client the
// hint names.
func TestEndSessionURLDropsAHintTheOPCanNoLongerVerify(t *testing.T) {
	op := newFakeOP(t)
	reg := newFakeRegistrar(t, op)
	c, store, mux := newClient(t, reg, nil)

	state := startLogin(t, mux, "")
	rec := callback(t, mux, state)
	sess, _ := store.Get(rec.Result().Cookies()[0].Value)

	rotated, err := jose.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	op.key = rotated

	raw := c.EndSessionURL(request("GET", "/nhl-auth/logout"), sess)
	if !strings.HasPrefix(raw, op.URL+"/logout") {
		t.Fatalf("URL = %q, want the OP end-session endpoint — the OP session must still be ended", raw)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	if q.Has("id_token_hint") {
		t.Error("sent an id_token_hint the OP cannot verify")
	}
	if q.Has("post_logout_redirect_uri") {
		t.Error("sent post_logout_redirect_uri without a hint to name the client")
	}
	if q.Get("client_id") != clientID {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
}

// Expiry alone must not cost the hint: an OP accepts an expired one, and every
// session older than the token lifetime holds exactly that.
func TestEndSessionURLKeepsAnExpiredHint(t *testing.T) {
	op := newFakeOP(t)
	reg := newFakeRegistrar(t, op)
	c, _, mux := newClient(t, reg, nil)
	startLogin(t, mux, "") // registers, which is what gives the client its keys

	expired, err := op.key.Sign("JWT", map[string]any{
		"iss": op.URL,
		"aud": clientID,
		"sub": "user-1",
		"iat": time.Now().Add(-48 * time.Hour).Unix(),
		"exp": time.Now().Add(-24 * time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	raw := c.EndSessionURL(request("GET", "/nhl-auth/logout"), &session.Session{IDToken: expired})
	u, _ := url.Parse(raw)
	q := u.Query()
	if q.Get("id_token_hint") != expired {
		t.Error("an expired but verifiable hint was dropped")
	}
	if got := q.Get("post_logout_redirect_uri"); got != "https://beacon-example.com"+PostLogoutPath {
		t.Errorf("post_logout_redirect_uri = %q", got)
	}
}

// Logging out must never be the thing that first contacts the registrar.
func TestEndSessionURLEmptyBeforeRegistration(t *testing.T) {
	op := newFakeOP(t)
	reg := newFakeRegistrar(t, op)
	c, _, _ := newClient(t, reg, nil)

	got := c.EndSessionURL(request("GET", "/nhl-auth/logout"), &session.Session{IDToken: "x"})
	if got != "" {
		t.Errorf("EndSessionURL = %q, want empty", got)
	}
	if reg.calls.Load() != 0 {
		t.Error("logout triggered registration")
	}
}

// --- back-channel logout -------------------------------------------------

func postLogoutToken(t *testing.T, mux http.Handler, token string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"logout_token": {token}}
	r := httptest.NewRequest("POST", BackchannelPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}

// loggedIn drives a full login so the client has keys and a live session.
func loggedIn(t *testing.T, sid string) (*fakeOP, *session.Store, http.Handler) {
	t.Helper()
	op := newFakeOP(t)
	op.idClaims = map[string]any{"sid": sid}
	reg := newFakeRegistrar(t, op)
	_, store, mux := newClient(t, reg, nil)
	state := startLogin(t, mux, "")
	if rec := callback(t, mux, state); rec.Code != http.StatusFound {
		t.Fatalf("login failed: %d", rec.Code)
	}
	return op, store, mux
}

func TestBackchannelLogoutEndsMatchingSession(t *testing.T) {
	op, store, mux := loggedIn(t, "sid-1")

	rec := postLogoutToken(t, mux, op.signLogoutToken(t, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %q, want empty", rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	if store.Count() != 0 {
		t.Error("the session survived back-channel logout")
	}
}

// This is what stops an ID token being replayed as a logout token.
func TestBackchannelLogoutRejectsNonce(t *testing.T) {
	op, store, mux := loggedIn(t, "sid-1")

	rec := postLogoutToken(t, mux, op.signLogoutToken(t, map[string]any{"nonce": "n-1"}))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if store.Count() != 1 {
		t.Error("a token carrying a nonce ended a session")
	}
}

func TestBackchannelLogoutRequiresEventClaim(t *testing.T) {
	op, store, mux := loggedIn(t, "sid-1")

	for _, override := range []map[string]any{
		{"events": nil},
		{"events": map[string]any{"http://example.com/other-event": map[string]any{}}},
	} {
		rec := postLogoutToken(t, mux, op.signLogoutToken(t, override))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 for %v", rec.Code, override)
		}
	}
	if store.Count() != 1 {
		t.Error("a token without the logout event ended a session")
	}
}

func TestBackchannelLogoutRequiresSidOrSub(t *testing.T) {
	op, store, mux := loggedIn(t, "sid-1")
	rec := postLogoutToken(t, mux, op.signLogoutToken(t, map[string]any{"sid": nil, "sub": nil}))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if store.Count() != 1 {
		t.Error("a token with neither sid nor sub ended a session")
	}
}

func TestBackchannelLogoutRejectsForeignSignature(t *testing.T) {
	_, store, mux := loggedIn(t, "sid-1")

	// A token signed by a different key entirely.
	other := newFakeOP(t)
	rec := postLogoutToken(t, mux, other.signLogoutToken(t, nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if store.Count() != 1 {
		t.Error("a forged logout token ended a session")
	}
}

func TestBackchannelLogoutMissingTokenIsBadRequest(t *testing.T) {
	_, _, mux := loggedIn(t, "sid-1")
	r := httptest.NewRequest("POST", BackchannelPath, strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// Before anyone has logged in there are no keys to verify with. That is
// retryable, so it must not look like a permanent rejection.
func TestBackchannelLogoutBeforeRegistrationIsRetryable(t *testing.T) {
	op := newFakeOP(t)
	reg := newFakeRegistrar(t, op)
	_, _, mux := newClient(t, reg, nil)

	rec := postLogoutToken(t, mux, op.signLogoutToken(t, nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

// Zero matches is still success — otherwise the response leaks whether this
// user has a session on this app.
func TestBackchannelLogoutZeroMatchesIsSuccess(t *testing.T) {
	op, store, mux := loggedIn(t, "sid-1")

	rec := postLogoutToken(t, mux, op.signLogoutToken(t, map[string]any{"sid": "some-other-sid"}))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if store.Count() != 1 {
		t.Error("a non-matching token ended a session")
	}
}

// Sessions minted before the gate recorded sid can never match a sid-bearing
// token. Without the sub fallback they survive every logout for 30 days while
// looking exactly like broken logout — 14 such sessions were found on wisera.
func TestBackchannelLogoutMatchesPreSidLegacySessionsBySub(t *testing.T) {
	op, store, mux := loggedIn(t, "sid-1")

	legacy, err := store.Create(&session.Session{
		Expires: testNowMS + 100_000,
		OIDCSub: "user-1", // same subject, no sid: written by an older build
	})
	if err != nil {
		t.Fatal(err)
	}

	// A token carrying only sub must reach the legacy session.
	rec := postLogoutToken(t, mux, op.signLogoutToken(t, map[string]any{"sid": nil, "sub": "user-1"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if _, ok := store.Get(legacy); ok {
		t.Error("the pre-sid legacy session survived logout")
	}
}

// The fallback must stay scoped to sessions with no sid, so a sub-only token
// cannot sweep away sessions belonging to other browser sessions of the same
// user that the OP did not name.
func TestSidBearingSessionsAreMatchedBySidNotSub(t *testing.T) {
	op, store, mux := loggedIn(t, "sid-1")

	other, err := store.Create(&session.Session{
		Expires: testNowMS + 100_000,
		OIDCSub: "user-1",
		OIDCSid: "sid-2",
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := postLogoutToken(t, mux, op.signLogoutToken(t, map[string]any{"sid": "sid-1"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if _, ok := store.Get(other); !ok {
		t.Error("a session with a different sid was also ended")
	}
}

// An app with no REDIRECT_HOST_SUFFIXES must still register. 2.x fell back to
// the request's own public origin, because a registrar predating the
// callback_path contract requires a non-empty redirect_uris and rejects the
// registration otherwise — which surfaces as "SSO is broken", not as a
// configuration warning.
func TestRegistrationFallsBackToRequestOriginWithNoHostSuffixes(t *testing.T) {
	op := newFakeOP(t)
	reg := newFakeRegistrar(t, op)

	var got registerRequest
	reg.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		writeJSON(w, reg.respond())
	})

	kv := map[string]string{
		"BACKEND_HOST": "whoami", "BACKEND_PORT": "80", "LISTEN_PORT": "80",
		"OIDC_REGISTRAR_URL": reg.URL,
		// deliberately no APP_NAME / REDIRECT_HOST_SUFFIXES
	}
	cfg, _, err := config.Load(func(k string) string { return kv[k] }, "")
	if err != nil {
		t.Fatal(err)
	}
	store := session.Open("", now)
	defer store.Close()

	mux := http.NewServeMux()
	New(cfg, store, now).RegisterRoutes(mux)
	mux.ServeHTTP(httptest.NewRecorder(), request("GET", "/nhl-auth/oidc/login"))

	if len(got.RedirectURIs) != 1 {
		t.Fatalf("redirect_uris = %v, want exactly one derived from the request origin", got.RedirectURIs)
	}
	if want := "https://beacon-example.com" + CallbackPath; got.RedirectURIs[0] != want {
		t.Errorf("redirect_uris[0] = %q, want %q", got.RedirectURIs[0], want)
	}
	if got.CallbackPath != CallbackPath {
		t.Errorf("callback_path = %q", got.CallbackPath)
	}
}

// A registrar too old to return redirect_uris must not leave the gate with an
// empty origin set.
func TestPre120RegistrarKeepsLocalHostSet(t *testing.T) {
	op := newFakeOP(t)
	reg := newFakeRegistrar(t, op)
	reg.respond = func() map[string]any {
		return map[string]any{
			"client_id": clientID, "client_secret": "test-secret", "issuer_url": op.URL,
			// no redirect_uris, as a pre-1.2.0 registrar answers
		}
	}
	c, _, mux := newClient(t, reg, nil)

	state := startLogin(t, mux, "")
	if rec := callback(t, mux, state); rec.Code != http.StatusFound {
		t.Fatalf("login failed against a pre-1.2.0 registrar: %d", rec.Code)
	}
	// The locally computed host set must survive, so redirect_uri stays stable.
	if got := c.chosenOrigin(request("GET", "/")); got != "https://beacon-example.com" {
		t.Errorf("chosenOrigin = %q, want the configured canonical origin", got)
	}
}

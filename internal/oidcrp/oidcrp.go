// Package oidcrp is the OIDC relying party: the SSO login that 43 of the 45
// production deployments actually use.
//
// The gate does not hold static client credentials. On the first login it
// registers itself with the registrar, which answers with a client_id,
// client_secret and issuer. Registration is lazy because the redirect URI has
// to be derived from the public Host, which only a real request carries.
package oidcrp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/yundera/appshield/internal/authn"
	"github.com/yundera/appshield/internal/config"
	"github.com/yundera/appshield/internal/proxy"
	"github.com/yundera/appshield/internal/session"
	"github.com/yundera/appshield/web"
)

const (
	CallbackPath    = "/nhl-auth/oidc/callback"
	PostLogoutPath  = "/nhl-auth/logged-out"
	BackchannelPath = "/nhl-auth/backchannel-logout"

	// flowTTL bounds how long a half-finished login may sit in memory.
	flowTTL = 10 * time.Minute

	backchannelEvent = "http://schemas.openid.net/event/backchannel-logout"
)

// flow is one in-flight authorization request, keyed by state.
type flow struct {
	verifier    string
	originalURI string
	created     time.Time
}

// registration is what the registrar gave us, plus everything derived from it.
type registration struct {
	clientID     string
	clientSecret string
	issuer       string

	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	// jwksURI is kept for logout, which has to ask the OP for its keys afresh
	// rather than trust the verifier's cache. See hintUsable.
	jwksURI    string
	endSession string

	// http carries every request the gate itself sends to the issuer:
	// discovery, the code exchange and the JWKS fetches. See backchannel.
	http *http.Client
}

// backchannel keeps the gate's own calls to the issuer on the box.
//
// The issuer is a public hostname and has to stay one: the string is the
// discovery URL, the `iss` of every token and where the browser is sent. But
// resolved from inside a deployment it leads out through the gateway/CDN and
// back in — for a call between two containers on one bridge. When the registrar
// names an internal address for the same issuer, requests for a URL under the
// public issuer go to the same path under the internal one instead.
//
// Only the dial moves. Every URL string is untouched, so go-oidc's issuer check
// passes unmodified, and the authorization and end-session endpoints — which
// the gate never fetches, only redirects to — stay public.
type backchannel struct {
	public, internal *url.URL
	next             http.RoundTripper
}

func (b *backchannel) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != b.public.Scheme || r.URL.Host != b.public.Host {
		return b.next.RoundTrip(r)
	}
	// Under the issuer's path, on a segment boundary: /dex and /dex/token, not
	// /dexter.
	rest, ok := strings.CutPrefix(r.URL.Path, b.public.Path)
	if !ok || (rest != "" && rest[0] != '/') {
		return b.next.RoundTrip(r)
	}
	r = r.Clone(r.Context()) // a RoundTripper must not modify its request
	r.URL.Scheme, r.URL.Host = b.internal.Scheme, b.internal.Host
	r.URL.Path, r.URL.RawPath = b.internal.Path+rest, ""
	r.Host = ""
	return b.next.RoundTrip(r)
}

// backchannelClient builds the client for the gate's calls to the issuer. With
// no internal address it is the plain client, and those calls go wherever the
// public issuer resolves.
func (c *Client) backchannelClient(issuer, internal string) (*http.Client, error) {
	if internal == "" {
		return c.http, nil
	}
	pub, err := parseBase(issuer)
	if err != nil {
		return nil, fmt.Errorf("issuer_url: %w", err)
	}
	in, err := parseBase(internal)
	if err != nil {
		return nil, fmt.Errorf("internal_issuer_url: %w", err)
	}
	next := c.http.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	return &http.Client{
		Timeout:   c.http.Timeout,
		Transport: &backchannel{public: pub, internal: in, next: next},
	}, nil
}

func parseBase(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("%q is not an http(s) URL", raw)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}

type Client struct {
	cfg      *config.Config
	sessions *session.Store
	http     *http.Client
	now      func() time.Time

	// regMu serialises registration, which also collapses concurrent
	// first-logins into a single /register call.
	regMu sync.Mutex
	reg   *registration

	originsMu      sync.RWMutex
	allowedOrigins map[string]bool
	fallbackOrigin string

	flowsMu sync.Mutex
	flows   map[string]*flow
}

func New(cfg *config.Config, sessions *session.Store, now func() time.Time) *Client {
	if now == nil {
		now = time.Now
	}
	origins := map[string]bool{}
	for _, o := range cfg.AllowedOrigins {
		origins[o] = true
	}
	return &Client{
		cfg:            cfg,
		sessions:       sessions,
		now:            now,
		http:           &http.Client{Timeout: 15 * time.Second},
		allowedOrigins: origins,
		fallbackOrigin: cfg.CanonicalOrigin,
		flows:          map[string]*flow{},
	}
}

func (c *Client) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /nhl-auth/oidc/login", c.handleLogin)
	mux.HandleFunc("GET "+CallbackPath, c.handleCallback)
	mux.HandleFunc("POST "+BackchannelPath, c.handleBackchannelLogout)
}

// --- registration --------------------------------------------------------

type registerRequest struct {
	CallbackPath          string   `json:"callback_path"`
	RedirectURIs          []string `json:"redirect_uris"`
	PostLogoutPath        string   `json:"post_logout_path"`
	BackchannelLogoutPath string   `json:"backchannel_logout_path"`
}

type registerResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	IssuerURL    string `json:"issuer_url"`
	// The same issuer as reached from inside the deployment. Optional: a
	// registrar that does not send it leaves the gate on the public path.
	InternalIssuerURL string   `json:"internal_issuer_url"`
	RedirectURIs      []string `json:"redirect_uris"`
}

// ensure returns the registration, performing it on first use. A failure is
// deliberately not cached: the next request retries rather than inheriting a
// dead result forever.
func (c *Client) ensure(ctx context.Context, publicOrigin string) (*registration, error) {
	c.regMu.Lock()
	defer c.regMu.Unlock()
	if c.reg != nil {
		return c.reg, nil
	}

	guessed := c.guessRedirectURIs(publicOrigin)
	body, _ := json.Marshal(registerRequest{
		CallbackPath:          CallbackPath,
		RedirectURIs:          guessed,
		PostLogoutPath:        PostLogoutPath,
		BackchannelLogoutPath: BackchannelPath,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.RegistrarURL+"/register", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registrar unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var buf [512]byte
		n, _ := resp.Body.Read(buf[:])
		return nil, fmt.Errorf("registrar returned %d: %s", resp.StatusCode, strings.TrimSpace(string(buf[:n])))
	}

	var rr registerResponse
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return nil, fmt.Errorf("registrar response: %w", err)
	}
	if rr.ClientID == "" || rr.IssuerURL == "" {
		return nil, errors.New("registrar returned no client_id or issuer_url")
	}

	// The registrar's list is authoritative once we have it. A registrar
	// predating the callback_path contract returns none, in which case our
	// guess is exactly what it registered. Either way this never moves
	// CANONICAL_ORIGIN — the OAuth issuer baked into already-signed tokens —
	// and only fills the fallback if we had no host config at all.
	callbacks := rr.RedirectURIs
	if len(callbacks) == 0 {
		log.Print("[oidc] registrar returned no redirect_uris (pre-1.2.0); keeping the locally computed host set")
		callbacks = guessed
	}
	c.adoptRedirectURIs(callbacks)

	// No fallback to the public path when the internal one fails: a silent
	// detour is exactly what hid the round trip this exists to remove. The
	// failure is not cached, so the next login retries.
	backHTTP, err := c.backchannelClient(rr.IssuerURL, rr.InternalIssuerURL)
	if err != nil {
		return nil, err
	}
	// The provider keeps this client for its key set, so later JWKS refreshes
	// follow it too.
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, backHTTP), rr.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discovering %s: %w", rr.IssuerURL, err)
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
		JWKSURI    string `json:"jwks_uri"`
	}
	_ = provider.Claims(&meta)

	c.reg = &registration{
		clientID:     rr.ClientID,
		clientSecret: rr.ClientSecret,
		issuer:       rr.IssuerURL,
		provider:     provider,
		verifier:     provider.Verifier(&oidc.Config{ClientID: rr.ClientID}),
		jwksURI:      meta.JWKSURI,
		endSession:   meta.EndSession,
		http:         backHTTP,
	}
	via := "the public issuer"
	if rr.InternalIssuerURL != "" {
		via = rr.InternalIssuerURL
	}
	log.Printf("[oidc] registered with %s as client %s (issuer %s, back-channel via %s)", c.cfg.RegistrarURL, rr.ClientID, rr.IssuerURL, via)
	return c.reg, nil
}

// guessRedirectURIs is our own guess at the host set, sent alongside
// callback_path so a registrar predating that contract — which requires a
// non-empty redirect_uris and ignores everything else — still answers.
//
// When no host set is configured at all, fall back to the origin this request
// arrived on. Sending an empty list instead would make an older registrar
// reject the registration outright, and the failure would look like "SSO is
// broken" rather than "this app has no REDIRECT_HOST_SUFFIXES".
func (c *Client) guessRedirectURIs(publicOrigin string) []string {
	c.originsMu.RLock()
	defer c.originsMu.RUnlock()
	if len(c.allowedOrigins) == 0 {
		if publicOrigin == "" {
			return nil
		}
		return []string{publicOrigin + CallbackPath}
	}
	out := make([]string, 0, len(c.allowedOrigins))
	for o := range c.allowedOrigins {
		out = append(out, o+CallbackPath)
	}
	return out
}

func (c *Client) adoptRedirectURIs(uris []string) {
	origins := map[string]bool{}
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		origins[u.Scheme+"://"+u.Host] = true
	}
	if len(origins) == 0 {
		return
	}
	c.originsMu.Lock()
	defer c.originsMu.Unlock()
	c.allowedOrigins = origins
	if c.fallbackOrigin == "" {
		for o := range origins {
			c.fallbackOrigin = o
			break
		}
	}
}

// chosenOrigin picks the origin to build a redirect_uri from: this request's
// own if we recognise it, otherwise the fallback.
func (c *Client) chosenOrigin(r *http.Request) string {
	origin := authn.PublicOrigin(r)
	c.originsMu.RLock()
	defer c.originsMu.RUnlock()
	if c.allowedOrigins[origin] {
		return origin
	}
	if c.fallbackOrigin != "" {
		return c.fallbackOrigin
	}
	return origin
}

func (c *Client) oauth2Config(reg *registration, r *http.Request) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     reg.clientID,
		ClientSecret: reg.clientSecret,
		Endpoint:     reg.provider.Endpoint(),
		RedirectURL:  c.chosenOrigin(r) + CallbackPath,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}
}

// --- login ---------------------------------------------------------------

func (c *Client) handleLogin(w http.ResponseWriter, r *http.Request) {
	reg, err := c.ensure(r.Context(), authn.PublicOrigin(r))
	if err != nil {
		log.Printf("[oidc] registration failed: %v", err)
		// Never echo the upstream error to the browser.
		http.Error(w, "Single sign-on is temporarily unavailable", http.StatusBadGateway)
		return
	}

	verifier := oauth2.GenerateVerifier()
	state, err := randomState()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	c.flowsMu.Lock()
	c.sweepFlowsLocked()
	c.flows[state] = &flow{
		verifier:    verifier,
		originalURI: authn.SafeRedirect(r, r.URL.Query().Get("redirect")),
		created:     c.now(),
	}
	c.flowsMu.Unlock()

	authURL := c.oauth2Config(reg, r).AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (c *Client) handleCallback(w http.ResponseWriter, r *http.Request) {
	reg, err := c.ensure(r.Context(), authn.PublicOrigin(r))
	if err != nil {
		http.Error(w, "Single sign-on is temporarily unavailable", http.StatusBadGateway)
		return
	}

	q := r.URL.Query()
	if errCode := q.Get("error"); errCode != "" {
		log.Printf("[oidc] provider returned error %q", errCode)
		http.Error(w, "Sign-in was not completed", http.StatusBadRequest)
		return
	}

	state := q.Get("state")
	c.flowsMu.Lock()
	f, ok := c.flows[state]
	delete(c.flows, state) // single use
	c.flowsMu.Unlock()
	if !ok || c.now().Sub(f.created) > flowTTL {
		// A restart mid-login orphans in-flight flows; this is the honest
		// answer rather than a confusing 500.
		http.Error(w, "This sign-in link has expired. Please try again.", http.StatusBadRequest)
		return
	}

	tok, err := c.oauth2Config(reg, r).Exchange(oidc.ClientContext(r.Context(), reg.http), q.Get("code"), oauth2.VerifierOption(f.verifier))
	if err != nil {
		log.Printf("[oidc] code exchange failed: %v", err)
		http.Error(w, "Sign-in failed", http.StatusBadGateway)
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		log.Print("[oidc] token response contained no id_token")
		http.Error(w, "Sign-in failed", http.StatusBadGateway)
		return
	}
	idToken, err := reg.verifier.Verify(r.Context(), rawID)
	if err != nil {
		log.Printf("[oidc] id_token verification failed: %v", err)
		http.Error(w, "Sign-in failed", http.StatusBadGateway)
		return
	}

	claims := claimsFrom(idToken)

	// Refuse before minting: leaving an unusable cookie behind would make
	// every later request a 403 the user cannot clear.
	if !c.groupsAllowed(claims.Groups) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write(web.ForbiddenHTML)
		return
	}

	var sidClaim struct {
		Sid string `json:"sid"`
	}
	_ = idToken.Claims(&sidClaim)

	sess := &session.Session{
		Expires: c.sessions.NewExpiry(c.cfg.SessionDuration),
		OIDCSub: idToken.Subject,
		Claims:  claims,
		IDToken: rawID,
		OIDCSid: sidClaim.Sid,
	}
	id, err := c.sessions.Create(sess)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     session.CookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   proxy.Scheme(r) == "https",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(c.cfg.SessionDuration / time.Second),
	})
	log.Printf("[oidc] login ok for sub=%s", idToken.Subject)

	target := f.originalURI
	if target == "" {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// claimsFrom maps the ID token onto the session's claim record. `user` follows
// preferred_username -> email -> sub so there is always something to show.
func claimsFrom(idToken *oidc.IDToken) *session.Claims {
	var raw struct {
		PreferredUsername string   `json:"preferred_username"`
		Email             string   `json:"email"`
		Name              string   `json:"name"`
		Groups            []string `json:"groups"`
	}
	_ = idToken.Claims(&raw)

	user := raw.PreferredUsername
	if user == "" {
		user = raw.Email
	}
	if user == "" {
		user = idToken.Subject
	}
	return &session.Claims{
		Sub:    idToken.Subject,
		User:   user,
		Email:  raw.Email,
		Name:   raw.Name,
		Groups: raw.Groups,
	}
}

func (c *Client) groupsAllowed(groups []string) bool {
	if len(c.cfg.RequiredGroups) == 0 {
		return true
	}
	for _, want := range c.cfg.RequiredGroups {
		for _, have := range groups {
			if have == want {
				return true
			}
		}
	}
	return false
}

// sweepFlowsLocked drops abandoned logins. Callers hold flowsMu.
func (c *Client) sweepFlowsLocked() {
	cutoff := c.now().Add(-flowTTL)
	for state, f := range c.flows {
		if f.created.Before(cutoff) {
			delete(c.flows, state)
		}
	}
}

// PendingFlows is exported for tests and diagnostics.
func (c *Client) PendingFlows() int {
	c.flowsMu.Lock()
	defer c.flowsMu.Unlock()
	return len(c.flows)
}

// --- logout --------------------------------------------------------------

// EndSessionURL implements authn.Logouter. It never triggers registration:
// logging out must not be the thing that first contacts the registrar.
func (c *Client) EndSessionURL(r *http.Request, sess *session.Session) string {
	c.regMu.Lock()
	reg := c.reg
	c.regMu.Unlock()

	if reg == nil || reg.endSession == "" || sess == nil || sess.IDToken == "" {
		return ""
	}
	u, err := url.Parse(reg.endSession)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("client_id", reg.clientID)
	if c.hintUsable(r.Context(), reg, sess.IDToken) {
		q.Set("id_token_hint", sess.IDToken)
		q.Set("post_logout_redirect_uri", c.chosenOrigin(r)+PostLogoutPath)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// hintUsable reports whether the OP can still verify this session's ID token.
//
// The token is the one from login, kept for the whole session — 30 days by
// default — while an OP rotates its signing keys far more often (Dex: every 6h,
// each key kept for verification about a day more). An OP accepts an EXPIRED
// hint, by spec, but not one whose signing key it has dropped: Dex answers 400
// "Invalid id_token_hint" and the user is left on an error page, signed out of
// this app and of nothing else.
//
// So check the signature against the OP's current key set first — fetched now,
// not the login verifier's cached copy: that cache is only replaced when a
// token arrives signed by a key it has never seen, so it goes on vouching for a
// key long after the OP dropped it. When it no
// longer verifies, the hint is left out — and post_logout_redirect_uri with it,
// which an OP only honours for a client the hint names (Dex: 400 "requires
// id_token_hint"). The OP then asks the user to confirm and ends its session on
// its own page: one extra click, and no return to this app, in exchange for a
// logout that works.
//
// A key set that cannot be fetched counts as unusable too. Sending a hint the
// OP may reject is the failure being avoided; asking for a confirmation is not.
func (c *Client) hintUsable(ctx context.Context, reg *registration, rawIDToken string) bool {
	ctx, cancel := context.WithTimeout(oidc.ClientContext(ctx, reg.http), 5*time.Second)
	defer cancel()
	current := oidc.NewVerifier(reg.issuer, oidc.NewRemoteKeySet(ctx, reg.jwksURI),
		&oidc.Config{ClientID: reg.clientID, SkipExpiryCheck: true})
	if _, err := current.Verify(ctx, rawIDToken); err != nil {
		log.Printf("[oidc] logout without id_token_hint: the session's ID token no longer verifies against the OP's keys (%v)", err)
		return false
	}
	return true
}

// --- back-channel logout -------------------------------------------------

// handleBackchannelLogout receives a signed logout token when another app ends
// the shared session. Unauthenticated by design: the signature is the
// authentication.
func (c *Client) handleBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	c.regMu.Lock()
	reg := c.reg
	c.regMu.Unlock()
	if reg == nil {
		// Nobody has logged in here yet, so we have no keys to verify with.
		// Retryable, so say so rather than failing permanently.
		http.Error(w, "temporarily_unavailable", http.StatusServiceUnavailable)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	raw := r.PostFormValue("logout_token")
	if raw == "" {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}

	n, err := c.applyLogoutToken(r.Context(), reg, raw)
	if err != nil {
		log.Printf("[oidc] rejected back-channel logout: %v", err)
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}

	log.Printf("[oidc] back-channel logout ended %d session(s)", n)
	// Always 200 with an empty body, even for zero matches: reporting
	// otherwise would leak whether this user has a session on this app.
	w.WriteHeader(http.StatusOK)
}

type logoutToken struct {
	Events map[string]json.RawMessage `json:"events"`
	Nonce  string                     `json:"nonce"`
	Sid    string                     `json:"sid"`
	Sub    string                     `json:"sub"`
}

func (c *Client) applyLogoutToken(ctx context.Context, reg *registration, raw string) (int, error) {
	// Verify signature, issuer and audience against the OP's JWKS.
	tok, err := reg.verifier.Verify(ctx, raw)
	if err != nil {
		return 0, fmt.Errorf("signature/claims: %w", err)
	}
	var lt logoutToken
	if err := tok.Claims(&lt); err != nil {
		return 0, fmt.Errorf("claims: %w", err)
	}
	if _, ok := lt.Events[backchannelEvent]; !ok {
		return 0, errors.New("missing the back-channel logout event claim")
	}
	// An ID token replayed as a logout token would carry a nonce. Its absence
	// is what distinguishes the two.
	if lt.Nonce != "" {
		return 0, errors.New("logout token must not carry a nonce")
	}
	if lt.Sid == "" && lt.Sub == "" {
		return 0, errors.New("logout token carries neither sid nor sub")
	}

	var legacy int
	n := c.sessions.Revoke(func(_ string, sess *session.Session) bool {
		switch {
		case lt.Sid != "" && sess.OIDCSid != "":
			return sess.OIDCSid == lt.Sid
		case lt.Sub != "" && sess.OIDCSub != "":
			// Sessions minted before the gate recorded sid can never match a
			// sid-bearing token, so they would otherwise survive every logout
			// for their full TTL while looking exactly like broken logout.
			// The fallback is scoped to those and ages out with them.
			if sess.OIDCSub == lt.Sub {
				if sess.OIDCSid == "" {
					legacy++
				}
				return true
			}
		}
		return false
	})
	if legacy > 0 {
		log.Printf("[oidc] back-channel logout matched %d pre-sid legacy session(s)", legacy)
	}
	return n, nil
}

// randomState produces the CSRF state parameter binding the authorization
// request to its callback.
func randomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

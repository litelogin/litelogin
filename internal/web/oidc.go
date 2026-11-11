package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/jwt"
	"github.com/litelogin/litelogin/internal/store"
)

// OAuth 2.1 and OpenID Connect endpoints (Architecture.md, "Protocol";
// Datamodel.md, "Authorize", "Exchange authorization code", "Refresh
// tokens", "UserInfo", "Logout").

// Client types and token endpoint auth methods, as the Admin API stores
// them.
const (
	clientConfidential = "confidential"
	grantCode          = "authorization_code"
	grantRefresh       = "refresh_token"
)

// CodeLifetime is how long an authorization code works.
const CodeLifetime = 60 * time.Second

// pkceVerifier and pkceChallenge are RFC 7636's formats: 43–128
// unreserved characters (a S256 challenge is always 43).
var (
	pkceVerifier  = regexp.MustCompile(`^[A-Za-z0-9\-._~]{43,128}$`)
	pkceChallenge = regexp.MustCompile(`^[A-Za-z0-9\-_]{43}$`)
)

// issuer is the tenant's issuer: the URL of the login host.
func (s *Server) issuer(t *tenant) string { return s.link(t, "", nil) }

// ---- Discovery and JWKS ----

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	t, err := s.resolve(r)
	if err != nil {
		s.jsonFailure(w, r, err)
		return
	}
	iss := s.issuer(t)
	doc := map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/authorize",
		"token_endpoint":                        iss + "/token",
		"userinfo_endpoint":                     iss + "/userinfo",
		"jwks_uri":                              iss + "/.well-known/jwks.json",
		"end_session_endpoint":                  iss + "/logout",
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{grantCode, grantRefresh},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{store.CodeChallengeS256},
		"scopes_supported":                      []string{"openid", "email", "offline_access"},
		"claims_supported": []string{
			"iss", "sub", "aud", "azp", "exp", "iat", "auth_time", "nonce", "amr", "email", "email_verified",
		},
		"prompt_values_supported":                        []string{"none", "login"},
		"authorization_response_iss_parameter_supported": true,
		"claims_parameter_supported":                     false,
		"request_parameter_supported":                    false,
		"request_uri_parameter_supported":                false,
	}
	publicCORS(w)
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, doc)
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	if _, err := s.resolve(r); err != nil {
		s.jsonFailure(w, r, err)
		return
	}
	body, err := s.Keys.JWKS(r.Context())
	if err != nil {
		s.jsonFailure(w, r, err)
		return
	}
	publicCORS(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(body)
}

func publicCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
}

func (s *Server) publicPreflight(w http.ResponseWriter, _ *http.Request) {
	publicCORS(w)
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusNoContent)
}

// allowOrigin allows a cross-origin request to /token or /userinfo if its
// Origin is in origins; otherwise it removes any CORS header set earlier,
// so browsers block the response.
func allowOrigin(w http.ResponseWriter, r *http.Request, origins []string) bool {
	w.Header().Set("Vary", "Origin")
	o := r.Header.Get("Origin")
	if o == "" || !slices.Contains(origins, o) {
		w.Header().Del("Access-Control-Allow-Origin")
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", o)
	return true
}

// requestCORS applies the CORS rule of a /token or /userinfo response: the
// allowed_origins of the request's client once it's known, and before
// that (an error response) those of every client on the host, as for a
// preflight.
func (s *Server) requestCORS(w http.ResponseWriter, r *http.Request, t *tenant) {
	if r.Header.Get("Origin") == "" {
		return
	}
	if t.Client != nil {
		allowOrigin(w, r, t.Client.AllowedOrigins)
		return
	}
	origins, err := s.hostOrigins(r.Context(), t)
	if err != nil {
		s.log().WarnContext(r.Context(), "list host origins", "error", err)
	}
	allowOrigin(w, r, origins)
}

// clientPreflight answers CORS preflight requests for /token and
// /userinfo. They carry no credentials or client_id, so the origins of
// every client on the host are allowed; the request itself is then checked
// against its own client's origins.
func (s *Server) clientPreflight(w http.ResponseWriter, r *http.Request) {
	t, err := s.resolve(r)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	origins, err := s.hostOrigins(r.Context(), t)
	if err != nil {
		s.log().WarnContext(r.Context(), "list host origins", "error", err)
	}
	if allowOrigin(w, r, origins) {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "600")
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Authorization endpoint ----

// authzRequest is a validated authorization request.
type authzRequest struct {
	RedirectURI   string
	State         string
	Scope         string
	Nonce         string
	CodeChallenge string
	Prompt        map[string]bool
	MaxAge        int64 // -1 when absent
	IDTokenHint   string
}

// authzError is an error returned to the client at its redirect URI.
type authzError struct{ code, description string }

func (e *authzError) Error() string { return e.code + ": " + e.description }

// singleParams may appear at most once (RFC 6749 §3.1).
var singleParams = []string{
	"client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge",
	"code_challenge_method", "prompt", "max_age", "response_mode", "id_token_hint",
}

// authorize implements "Authorize" (Datamodel.md). Until the client and
// redirect URI are known to be valid, errors are shown to the user, never
// redirected (RFC 6749 §4.1.2.1). After that, errors go to the redirect
// URI with state and iss.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	t, err := s.resolve(r)
	if err != nil {
		s.fail(w, r, nil, err)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.badAuthz(w, r, t, "The sign-in request is malformed.")
		return
	}
	q := r.Form
	c, err := s.hostClient(r.Context(), t, q.Get("client_id"))
	if errors.Is(err, errUnavailable) || len(q["client_id"]) > 1 {
		s.badAuthz(w, r, t, "The sign-in request is for an application this page doesn't serve, or names no application.")
		return
	}
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	t.Client = c
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" || len(q["redirect_uri"]) > 1 || !slices.Contains(t.Client.RedirectURIs, redirectURI) {
		s.badAuthz(w, r, t, "The sign-in request's return address isn't registered for this application.")
		return
	}

	req, aerr := parseAuthz(q, t)
	if aerr != nil {
		s.redirectAuthz(w, r, t, redirectURI, q.Get("state"), url.Values{"error": {aerr.code}, "error_description": {aerr.description}})
		return
	}

	sess, u, err := s.currentSession(r, t)
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	usable := sess != nil && !req.Prompt["login"]
	// max_age=0 is equivalent to prompt=login (OIDC Core §3.1.2.1); without
	// this, a sign-in in the same second would count as fresh enough.
	if usable && (req.MaxAge == 0 || req.MaxAge > 0 && s.now().Unix()-sess.AuthTime > req.MaxAge) {
		usable = false
	}
	if usable && req.IDTokenHint != "" {
		hint, err := s.Verifier.VerifyIDTokenHint(r.Context(), req.IDTokenHint, s.issuer(t))
		if err != nil || hint.Subject != u.ID {
			usable = false
		}
	}
	if !usable {
		if req.Prompt["none"] {
			s.redirectAuthz(w, r, t, redirectURI, req.State, url.Values{"error": {"login_required"}})
			return
		}
		http.Redirect(w, r, "/login?"+url.Values{"authz": {q.Encode()}}.Encode(), http.StatusSeeOther)
		return
	}

	code := crypto.NewToken()
	err = s.Store.CreateCode(r.Context(), &store.AuthCode{
		Hash: crypto.HashToken(code), Iss: s.issuer(t), ClientID: t.Client.ID, RedirectURI: redirectURI,
		Scope: req.Scope, Nonce: req.Nonce, CodeChallenge: req.CodeChallenge, CodeChallengeMethod: challengeMethod(req.CodeChallenge),
		PoolID: t.Pool.ID, UserID: u.ID, SessionHash: sess.Hash, AuthVersion: sess.AuthVersion, AuthTime: sess.AuthTime,
	}, CodeLifetime)
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	s.redirectAuthz(w, r, t, redirectURI, req.State, url.Values{"code": {code}})
}

func challengeMethod(challenge string) string {
	if challenge == "" {
		return ""
	}
	return store.CodeChallengeS256
}

func parseAuthz(q url.Values, t *tenant) (*authzRequest, *authzError) {
	for _, p := range singleParams {
		if len(q[p]) > 1 {
			return nil, &authzError{"invalid_request", p + " is repeated"}
		}
	}
	switch {
	case q.Has("request"):
		return nil, &authzError{"request_not_supported", "request objects aren't supported"}
	case q.Has("request_uri"):
		return nil, &authzError{"request_uri_not_supported", "request_uri isn't supported"}
	case q.Has("registration"):
		return nil, &authzError{"registration_not_supported", "registration isn't supported"}
	}
	if rt := q.Get("response_type"); rt != "code" {
		return nil, &authzError{"unsupported_response_type", "only response_type=code is supported"}
	}
	if rm := q.Get("response_mode"); rm != "" && rm != "query" {
		return nil, &authzError{"invalid_request", "only response_mode=query is supported"}
	}
	req := &authzRequest{State: q.Get("state"), Nonce: q.Get("nonce"), IDTokenHint: q.Get("id_token_hint"), MaxAge: -1}
	if len(req.State) > 2048 || len(req.Nonce) > 512 {
		return nil, &authzError{"invalid_request", "state or nonce is too long"}
	}

	// Scopes the client isn't allowed are left out (RFC 6749 §3.3); the
	// token response says what was granted. openid is required.
	var granted []string
	for _, sc := range strings.Fields(q.Get("scope")) {
		if slices.Contains(t.Client.AllowedScopes, sc) && !slices.Contains(granted, sc) {
			granted = append(granted, sc)
		}
	}
	if !slices.Contains(granted, "openid") {
		return nil, &authzError{"invalid_scope", "the openid scope is required"}
	}
	req.Scope = strings.Join(granted, " ")
	if err := parsePrompt(q, req); err != nil {
		return nil, err
	}

	// PKCE S256 is required unless a confidential client has opted out
	// (OAuth 2.1, RFC 9700). Whenever PKCE is sent it's checked, and plain
	// is never accepted.
	method, challenge := q.Get("code_challenge_method"), q.Get("code_challenge")
	switch {
	case challenge == "" && method != "":
		return nil, &authzError{"invalid_request", "code_challenge_method was sent without code_challenge"}
	case challenge == "" && pkceOptional(t.Client):
		return req, nil
	case challenge == "":
		return nil, &authzError{"invalid_request", "code_challenge is required (PKCE with S256)"}
	case method != store.CodeChallengeS256:
		return nil, &authzError{"invalid_request", "code_challenge_method must be S256"}
	case !pkceChallenge.MatchString(challenge):
		return nil, &authzError{"invalid_request", "code_challenge is malformed"}
	}
	req.CodeChallenge = challenge
	return req, nil
}

// pkceOptional reports whether a client may send authorization requests
// without PKCE: only a confidential client that opted out. Redeeming the
// code then has further conditions (mayOmitPKCE).
func pkceOptional(c *store.Client) bool {
	return c.ClientType == clientConfidential && c.PKCEOptional
}

// parsePrompt reads prompt and max_age.
func parsePrompt(q url.Values, req *authzRequest) *authzError {
	req.Prompt = map[string]bool{}
	for _, p := range strings.Fields(q.Get("prompt")) {
		req.Prompt[p] = true
	}
	if req.Prompt["none"] && len(req.Prompt) > 1 {
		return &authzError{"invalid_request", "prompt=none can't be combined with other values"}
	}
	if v := q.Get("max_age"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return &authzError{"invalid_request", "max_age must be a non-negative integer"}
		}
		req.MaxAge = n
	}
	return nil
}

// badAuthz shows an authorization error that can't be sent to the client.
func (s *Server) badAuthz(w http.ResponseWriter, r *http.Request, t *tenant, msg string) {
	s.render(w, r, t, http.StatusBadRequest, "error", pageData{Title: "Sign-in request not valid", Error: msg})
}

// redirectAuthz sends an authorization response to the client's redirect
// URI, keeping any query it already has, with state and iss (RFC 9207).
func (s *Server) redirectAuthz(w http.ResponseWriter, r *http.Request, t *tenant, redirectURI, state string, params url.Values) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		s.badAuthz(w, r, t, "The sign-in request's return address is malformed.")
		return
	}
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", s.issuer(t))
	u.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // a redirect URI registered for the client (exact match)
}

// continueAuthz returns where to go after signing in: the pending
// authorization request, or the account page. authz is the original
// request's query; it's only ever used as the query of our own
// /authorize, so it can't redirect anywhere else. The user just signed in,
// so prompt=login and max_age are satisfied and removed (keeping them
// would ask again).
func continueAuthz(authz string) string {
	if authz == "" {
		return "/account"
	}
	q, err := url.ParseQuery(authz)
	if err != nil {
		return "/account"
	}
	if q.Get("prompt") != "" {
		var keep []string
		for _, p := range strings.Fields(q.Get("prompt")) {
			if p != "login" {
				keep = append(keep, p)
			}
		}
		if len(keep) == 0 {
			q.Del("prompt")
		} else {
			q.Set("prompt", strings.Join(keep, " "))
		}
	}
	q.Del("max_age")
	return "/authorize?" + q.Encode()
}

// ---- Token endpoint ----

// tokenError is an OAuth error response from the token endpoint.
type tokenError struct {
	status      int
	code        string
	description string
}

func (e *tokenError) Error() string { return e.code + ": " + e.description }

var errInvalidGrant = &tokenError{http.StatusBadRequest, "invalid_grant", "the grant is invalid, expired or already used"}

// token implements the token endpoint.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	t, err := s.resolve(r)
	if errors.Is(err, errUnavailable) {
		s.tokenFail(w, r, &tokenError{http.StatusUnauthorized, "invalid_client", "unknown client"}, false)
		return
	}
	if err != nil {
		s.tokenFail(w, r, err, false)
		return
	}
	fail := func(err error, basic bool) {
		s.requestCORS(w, r, t)
		s.tokenFail(w, r, err, basic)
	}
	if err := r.ParseForm(); err != nil || r.Method != http.MethodPost {
		fail(&tokenError{http.StatusBadRequest, "invalid_request", "send the request as a form POST"}, false)
		return
	}
	for _, p := range []string{"grant_type", "code", "redirect_uri", "code_verifier", "refresh_token", "client_id", "client_secret", "scope"} {
		if len(r.PostForm[p]) > 1 {
			fail(&tokenError{http.StatusBadRequest, "invalid_request", p + " is repeated"}, false)
			return
		}
	}
	basic, err := s.authenticateClient(r, t)
	if err != nil {
		fail(err, basic)
		return
	}

	var resp *tokenResponse
	switch gt := r.PostForm.Get("grant_type"); {
	case gt == grantCode && slices.Contains(t.Client.GrantTypes, grantCode):
		resp, err = s.exchangeCode(r, t)
	case gt == grantRefresh && slices.Contains(t.Client.GrantTypes, grantRefresh):
		resp, err = s.refresh(r, t)
	case gt == grantCode || gt == grantRefresh:
		err = &tokenError{http.StatusBadRequest, "unauthorized_client", "the client may not use this grant type"}
	case gt == "":
		err = &tokenError{http.StatusBadRequest, "invalid_request", "grant_type is required"}
	default:
		err = &tokenError{http.StatusBadRequest, "unsupported_grant_type", "only authorization_code and refresh_token are supported"}
	}
	if err != nil {
		fail(err, basic)
		return
	}
	s.requestCORS(w, r, t)
	writeJSON(w, http.StatusOK, resp)
}

// authenticateClient authenticates the client of a token request
// (client_secret_basic, client_secret_post, or none for public clients),
// which must be on the host, and makes it the tenant's client. It reports
// whether HTTP Basic was used, for the WWW-Authenticate header.
func (s *Server) authenticateClient(r *http.Request, t *tenant) (bool, error) {
	bad := &tokenError{http.StatusUnauthorized, "invalid_client", "client authentication failed"}
	id, secret, basic := r.BasicAuth()
	if basic {
		var err1, err2 error
		id, err1 = url.QueryUnescape(id) // RFC 6749 §2.3.1
		secret, err2 = url.QueryUnescape(secret)
		if err1 != nil || err2 != nil || r.PostForm.Has("client_secret") {
			return true, bad
		}
		if formID := r.PostForm.Get("client_id"); formID != "" && formID != id {
			return true, bad
		}
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	c, err := s.hostClient(r.Context(), t, id)
	if errors.Is(err, errUnavailable) {
		return basic, bad
	}
	if err != nil {
		return basic, err
	}
	if c.ClientType != clientConfidential {
		if secret != "" {
			return basic, bad // public clients have no secret
		}
		t.Client = c
		return basic, nil
	}
	if secret == "" || c.ClientSecretHash == "" ||
		subtle.ConstantTimeCompare([]byte(crypto.HashToken(secret)), []byte(c.ClientSecretHash)) != 1 {
		return basic, bad
	}
	t.Client = c
	return basic, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

// exchangeCode implements "Exchange authorization code". Every check runs
// before the code is consumed, so a bad request can't burn a valid code.
func (s *Server) exchangeCode(r *http.Request, t *tenant) (*tokenResponse, error) {
	ctx := r.Context()
	f := r.PostForm
	raw, verifier := f.Get("code"), f.Get("code_verifier")
	if raw == "" || f.Get("redirect_uri") == "" {
		return nil, &tokenError{http.StatusBadRequest, "invalid_request", "code and redirect_uri are required"}
	}
	if verifier != "" && !pkceVerifier.MatchString(verifier) {
		return nil, &tokenError{http.StatusBadRequest, "invalid_grant", "code_verifier is malformed"}
	}
	if !validToken(raw) {
		return nil, errInvalidGrant
	}
	code, err := s.Store.GetCode(ctx, crypto.HashToken(raw))
	if errors.Is(err, store.ErrNotFound) {
		return nil, errInvalidGrant
	}
	if err != nil {
		return nil, err
	}
	if code.UsedAt != 0 {
		// Reuse: revoke whatever the first redemption issued.
		if code.FamilyID != "" {
			if err := s.Store.RevokeRefreshFamily(ctx, code.FamilyID); err != nil {
				return nil, err
			}
		}
		s.log().WarnContext(ctx, "authorization code reused", "client_id", t.Client.ID)
		return nil, errInvalidGrant
	}
	if code.ClientID != t.Client.ID || code.RedirectURI != f.Get("redirect_uri") || code.Iss != s.issuer(t) ||
		!pkceMatches(code.CodeChallenge, verifier) || !mayOmitPKCE(r, t, code) {
		return nil, errInvalidGrant
	}
	u, err := s.Store.GetUser(ctx, code.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errInvalidGrant
	}
	if err != nil {
		return nil, err
	}
	if u.Status != store.UserActive || u.AuthVersion != code.AuthVersion {
		return nil, errInvalidGrant
	}

	var grant *store.NewRefreshGrant
	var refresh string
	if slices.Contains(t.Client.GrantTypes, grantRefresh) {
		refresh = crypto.NewToken()
		grant = &store.NewRefreshGrant{
			FamilyID: crypto.NewID(), TokenHash: crypto.HashToken(refresh),
			FamilyLifetime: seconds(t.Client.RefreshFamilyTTL), TokenLifetime: seconds(t.Client.RefreshTokenTTL),
		}
	}
	if _, err := s.Store.RedeemCode(ctx, code, grant); err != nil {
		if errors.Is(err, store.ErrReused) || errors.Is(err, store.ErrConditionFailed) {
			return nil, errInvalidGrant
		}
		return nil, err
	}
	return s.issue(r, t, u, code.Iss, code.Scope, code.AuthTime, code.Nonce, refresh)
}

// mayOmitPKCE enforces the PKCE opt-out when a code issued without PKCE is
// redeemed (Datamodel.md, Decision 6): PKCE isn't required only when the
// client authenticates. So the client must still be a confidential client
// that opted out (it was authenticated with its secret to get here), and
// the request must not come from a browser: a request with an Origin
// header must always use PKCE.
func mayOmitPKCE(r *http.Request, t *tenant, code *store.AuthCode) bool {
	if code.CodeChallenge != "" {
		return true
	}
	return pkceOptional(t.Client) && r.Header.Get("Origin") == ""
}

// pkceMatches checks the code_verifier against the code's challenge. A code
// issued with PKCE needs the matching verifier. A code issued without it
// rejects any verifier: accepting one would let an attacker who injects a
// code from a non-PKCE request pass it off as protected (RFC 9700 §2.1.1).
func pkceMatches(challenge, verifier string) bool {
	if challenge == "" {
		return verifier == ""
	}
	if verifier == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

// refresh implements "Refresh tokens": the token is rotated on every use,
// and a reused token revokes its family.
func (s *Server) refresh(r *http.Request, t *tenant) (*tokenResponse, error) {
	ctx := r.Context()
	raw := r.PostForm.Get("refresh_token")
	if raw == "" {
		return nil, &tokenError{http.StatusBadRequest, "invalid_request", "refresh_token is required"}
	}
	if !validToken(raw) {
		return nil, errInvalidGrant
	}
	old, err := s.Store.GetRefreshToken(ctx, crypto.HashToken(raw))
	if errors.Is(err, store.ErrNotFound) {
		return nil, errInvalidGrant
	}
	if err != nil {
		return nil, err
	}
	if old.ClientID != t.Client.ID {
		return nil, errInvalidGrant
	}
	if old.UsedAt != 0 {
		if err := s.Store.RevokeRefreshFamily(ctx, old.FamilyID); err != nil {
			return nil, err
		}
		s.log().WarnContext(ctx, "refresh token reused; family revoked", "client_id", t.Client.ID)
		return nil, errInvalidGrant
	}
	family, err := s.Store.GetRefreshFamily(ctx, old.FamilyID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errInvalidGrant
	}
	if err != nil {
		return nil, err
	}
	if family.Iss != s.issuer(t) || family.ClientID != t.Client.ID {
		return nil, errInvalidGrant
	}
	scope := family.Scope
	if v := r.PostForm.Get("scope"); v != "" {
		// A refresh may narrow the scope, never widen it.
		have := strings.Fields(family.Scope)
		for _, sc := range strings.Fields(v) {
			if !slices.Contains(have, sc) {
				return nil, &tokenError{http.StatusBadRequest, "invalid_scope", "the scope exceeds what was granted"}
			}
		}
		scope = strings.Join(strings.Fields(v), " ")
	}
	u, err := s.Store.GetUser(ctx, family.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errInvalidGrant
	}
	if err != nil {
		return nil, err
	}
	if u.Status != store.UserActive || u.AuthVersion != family.AuthVersion {
		return nil, errInvalidGrant
	}
	next := crypto.NewToken()
	if _, err := s.Store.RotateRefreshToken(ctx, old, family, crypto.HashToken(next), seconds(t.Client.RefreshTokenTTL)); err != nil {
		if errors.Is(err, store.ErrReused) || errors.Is(err, store.ErrConditionFailed) {
			return nil, errInvalidGrant
		}
		return nil, err
	}
	return s.issue(r, t, u, family.Iss, scope, family.AuthTime, "", next)
}

// issue signs the access token and, with the openid scope, the ID token.
func (s *Server) issue(r *http.Request, t *tenant, u *store.User, iss, scope string, authTime int64, nonce, refresh string) (*tokenResponse, error) {
	ctx := r.Context()
	now := s.now()
	scopes := strings.Fields(scope)
	at, err := s.Signer.SignAccessToken(ctx, jwt.NewAccessTokenClaims(jwt.AccessTokenParams{
		Issuer: iss, UserID: u.ID, ClientID: t.Client.ID, Scope: scope, TTL: seconds(t.Client.AccessTokenTTL), Now: now,
	}))
	if err != nil {
		return nil, err
	}
	resp := &tokenResponse{
		AccessToken: at, TokenType: "Bearer", ExpiresIn: t.Client.AccessTokenTTL, RefreshToken: refresh, Scope: scope,
	}
	if slices.Contains(scopes, "openid") {
		resp.IDToken, err = s.Signer.SignIDToken(ctx, jwt.NewIDTokenClaims(jwt.IDTokenParams{
			Issuer: iss, UserID: u.ID, ClientID: t.Client.ID, AuthTime: authTime, Nonce: nonce, AMR: []string{"pwd"},
			IncludeEmail: slices.Contains(scopes, "email"), Email: u.Email, EmailVerified: u.EmailVerified,
			TTL: seconds(t.Client.IDTokenTTL), Now: now,
		}))
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func (s *Server) tokenFail(w http.ResponseWriter, r *http.Request, err error, basic bool) {
	var te *tokenError
	if !errors.As(err, &te) {
		s.log().ErrorContext(r.Context(), "token request failed", "error", err)
		te = &tokenError{http.StatusInternalServerError, "server_error", "the request couldn't be completed"}
	}
	if te.status == http.StatusUnauthorized && basic {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
	}
	writeJSON(w, te.status, map[string]string{"error": te.code, "error_description": te.description})
}

// ---- UserInfo ----

// userinfo implements "UserInfo": the access token is verified locally,
// and the user's status read on every request.
func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	w.Header().Set("Cache-Control", "no-store")
	t, err := s.resolve(r)
	if err != nil {
		s.jsonFailure(w, r, err)
		return
	}
	s.requestCORS(w, r, t)
	token, ok := bearerToken(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_request", "error_description": "a bearer access token is required"})
		return
	}
	invalidToken := func() {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo", error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": "the access token is invalid or expired"})
	}
	claims, err := s.Verifier.VerifyAccessToken(r.Context(), token, s.issuer(t))
	if errors.Is(err, jwt.ErrInvalidToken) {
		invalidToken()
		return
	}
	if err != nil {
		s.jsonFailure(w, r, err)
		return
	}
	// The token's client must still be on this host.
	c, err := s.hostClient(r.Context(), t, claims.ClientID)
	if errors.Is(err, errUnavailable) {
		invalidToken()
		return
	}
	if err != nil {
		s.jsonFailure(w, r, err)
		return
	}
	t.Client = c
	s.requestCORS(w, r, t)
	scopes := strings.Fields(claims.Scope)
	if !slices.Contains(scopes, "openid") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo", error="insufficient_scope", scope="openid"`)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient_scope"})
		return
	}
	u, err := s.Store.GetUser(r.Context(), claims.Subject)
	if errors.Is(err, store.ErrNotFound) || (err == nil && u.Status != store.UserActive) {
		invalidToken()
		return
	}
	if err != nil {
		s.jsonFailure(w, r, err)
		return
	}
	out := map[string]any{"sub": u.ID}
	if slices.Contains(scopes, "email") {
		out["email"], out["email_verified"] = u.Email, u.EmailVerified
	}
	writeJSON(w, http.StatusOK, out)
}

// bearerToken reads the access token from the Authorization header or, for
// a form POST, the access_token parameter (RFC 6750 §2.1–2.2). Using both
// is an error.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	var form string
	if r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		form = r.PostFormValue("access_token")
	}
	if h != "" {
		scheme, tok, ok := strings.Cut(h, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(tok) == "" || form != "" {
			return "", false
		}
		return strings.TrimSpace(tok), true
	}
	return form, form != ""
}

// ---- Helpers ----

func seconds(n int64) time.Duration { return time.Duration(n) * time.Second }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// jsonFailure answers a JSON endpoint whose request couldn't be served.
func (s *Server) jsonFailure(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errUnavailable) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	s.log().ErrorContext(r.Context(), "request failed", "path", r.URL.Path, "error", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
}

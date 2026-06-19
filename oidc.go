package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func (b *Bridge) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"issuer":                                b.cfg.Issuer,
		"authorization_endpoint":                b.cfg.Issuer + "/authorize",
		"token_endpoint":                        b.cfg.Issuer + "/token",
		"jwks_uri":                              b.cfg.Issuer + "/jwks",
		"userinfo_endpoint":                     b.cfg.Issuer + "/userinfo",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
	}
	writeJSON(w, http.StatusOK, doc)
}

// loginTmpl is the bridge's own minimal login form (server-side credential proxy
// to CasaOS — see README "Design decision"). Deliberately bare for the skeleton.
var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<html><body>
<h2>Sign in (CasaOS)</h2>
<form method="POST" action="/login">
<input type="hidden" name="rid" value="{{.RID}}">
<p>Username: <input name="username"></p>
<p>Password: <input name="password" type="password"></p>
<button type="submit">Sign in</button>
</form>
</body></html>`))

func (b *Bridge) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		httpErr(w, http.StatusBadRequest, "unsupported response_type")
		return
	}
	if q.Get("client_id") != b.cfg.ClientID {
		httpErr(w, http.StatusBadRequest, "unknown client_id")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if !contains(b.cfg.RedirectURIs, redirectURI) {
		httpErr(w, http.StatusBadRequest, "redirect_uri not allowed")
		return
	}
	ccm := q.Get("code_challenge_method")
	if q.Get("code_challenge") != "" && ccm != "S256" {
		httpErr(w, http.StatusBadRequest, "only S256 PKCE supported")
		return
	}
	rid := b.store.putRequest(AuthRequest{
		ClientID:            q.Get("client_id"),
		RedirectURI:         redirectURI,
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),
		Scope:               q.Get("scope"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: ccm,
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTmpl.Execute(w, map[string]string{"RID": rid})
}

func (b *Bridge) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpErr(w, http.StatusBadRequest, "bad form")
		return
	}
	rid := r.PostForm.Get("rid")
	req, ok := b.store.getRequest(rid)
	if !ok {
		httpErr(w, http.StatusBadRequest, "unknown or expired auth request")
		return
	}

	user, accessToken, err := b.casa.Login(r.Context(), r.PostForm.Get("username"), r.PostForm.Get("password"))
	if err != nil {
		// Re-show the form on bad credentials.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_ = loginTmpl.Execute(w, map[string]string{"RID": rid})
		return
	}
	// Verify the CasaOS-issued token against the live JWKS (proof of identity).
	if err := b.casa.VerifyToken(r.Context(), accessToken); err != nil {
		httpErr(w, http.StatusBadGateway, "casaos token verification failed: "+err.Error())
		return
	}

	b.store.delRequest(rid)
	sub := user.Username
	if sub == "" {
		sub = fmt.Sprintf("casaos-%d", user.Id)
	}
	code := b.store.putCode(AuthCode{
		Req:     req,
		Sub:     sub,
		Email:   user.Email,
		Groups:  []string{user.Role}, // CasaOS role -> groups (default "admin"), Gate 2
		Expires: time.Now().Add(60 * time.Second),
	})

	u, _ := url.Parse(req.RedirectURI)
	qs := u.Query()
	qs.Set("code", code)
	if req.State != "" {
		qs.Set("state", req.State)
	}
	u.RawQuery = qs.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (b *Bridge) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenErr(w, "invalid_request")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		tokenErr(w, "unsupported_grant_type")
		return
	}
	cid, csec := clientCreds(r)
	if cid != b.cfg.ClientID || csec != b.cfg.ClientSecret {
		tokenErr(w, "invalid_client")
		return
	}
	ac, ok := b.store.consumeCode(r.PostForm.Get("code"))
	if !ok || time.Now().After(ac.Expires) {
		tokenErr(w, "invalid_grant")
		return
	}
	if r.PostForm.Get("redirect_uri") != ac.Req.RedirectURI {
		tokenErr(w, "invalid_grant")
		return
	}
	// PKCE (S256) when the auth request used it.
	if ac.Req.CodeChallenge != "" {
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != ac.Req.CodeChallenge {
			tokenErr(w, "invalid_grant")
			return
		}
	}

	now := time.Now()
	idTok, err := b.signToken(ac, now, true)
	if err != nil {
		tokenErr(w, "server_error")
		return
	}
	accTok, err := b.signToken(ac, now, false)
	if err != nil {
		tokenErr(w, "server_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": string(accTok),
		"id_token":     string(idTok),
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

func (b *Bridge) signToken(ac AuthCode, now time.Time, isID bool) ([]byte, error) {
	builder := jwt.NewBuilder().
		Issuer(b.cfg.Issuer).
		Subject(ac.Sub).
		Audience([]string{ac.Req.ClientID}).
		IssuedAt(now).
		Expiration(now.Add(time.Hour)).
		Claim("email", ac.Email).
		Claim("groups", ac.Groups)
	if isID && ac.Req.Nonce != "" {
		builder = builder.Claim("nonce", ac.Req.Nonce)
	}
	tok, err := builder.Build()
	if err != nil {
		return nil, err
	}
	return jwt.Sign(tok, jwt.WithKey(jwa.RS256, b.signKey))
}

func (b *Bridge) handleJWKS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, b.pubKeys)
}

func (b *Bridge) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	raw := strings.TrimPrefix(auth, "Bearer ")
	if raw == auth || raw == "" {
		httpErr(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	tok, err := jwt.Parse([]byte(raw), jwt.WithKeySet(b.pubKeys))
	if err != nil {
		httpErr(w, http.StatusUnauthorized, "invalid token")
		return
	}
	email, _ := tok.Get("email")
	groups, _ := tok.Get("groups")
	writeJSON(w, http.StatusOK, map[string]any{"sub": tok.Subject(), "email": email, "groups": groups})
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) { http.Error(w, msg, code) }

func tokenErr(w http.ResponseWriter, e string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": e})
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func clientCreds(r *http.Request) (string, string) {
	if u, p, ok := r.BasicAuth(); ok {
		return u, p
	}
	return r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
}

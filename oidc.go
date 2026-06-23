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

// loginTmpl is the bridge's own login form (server-side credential proxy to
// CasaOS — see README "Design decision"). Self-contained: all styles are inline
// so the page renders with no external network dependency.
var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style>
  :root {
    --bg-1: #0f172a;
    --bg-2: #1e293b;
    --accent: #6366f1;
    --accent-hover: #4f46e5;
    --card: rgba(255, 255, 255, 0.06);
    --border: rgba(255, 255, 255, 0.12);
    --text: #f1f5f9;
    --muted: #94a3b8;
    --error-bg: rgba(239, 68, 68, 0.12);
    --error-border: rgba(239, 68, 68, 0.4);
    --error-text: #fca5a5;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: var(--text);
    background:
      radial-gradient(1200px 600px at 15% -10%, rgba(99, 102, 241, 0.25), transparent 60%),
      radial-gradient(900px 500px at 110% 110%, rgba(14, 165, 233, 0.18), transparent 55%),
      linear-gradient(160deg, var(--bg-1), var(--bg-2));
  }
  .card {
    width: 100%;
    max-width: 380px;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 36px 32px 32px;
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.45);
  }
  .logo {
    width: 48px;
    height: 48px;
    border-radius: 14px;
    display: grid;
    place-items: center;
    margin-bottom: 20px;
    background: linear-gradient(135deg, var(--accent), #0ea5e9);
    box-shadow: 0 6px 18px rgba(99, 102, 241, 0.45);
  }
  .logo svg { width: 24px; height: 24px; color: #fff; }
  h1 { font-size: 21px; font-weight: 650; margin: 0 0 4px; }
  .lede { color: var(--muted); font-size: 13.5px; margin: 0 0 22px; }
  .field { margin-bottom: 16px; }
  label {
    display: block;
    font-size: 12.5px;
    font-weight: 550;
    color: var(--muted);
    margin-bottom: 7px;
  }
  input[type=text], input[type=password] {
    width: 100%;
    padding: 12px 14px;
    font-size: 14.5px;
    color: var(--text);
    background: rgba(0, 0, 0, 0.25);
    border: 1px solid var(--border);
    border-radius: 10px;
    outline: none;
    transition: border-color 0.15s, box-shadow 0.15s, background 0.15s;
  }
  input::placeholder { color: rgba(148, 163, 184, 0.55); }
  input:focus {
    border-color: var(--accent);
    background: rgba(0, 0, 0, 0.35);
    box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.25);
  }
  button {
    width: 100%;
    margin-top: 6px;
    padding: 12px 14px;
    font-size: 14.5px;
    font-weight: 600;
    color: #fff;
    background: var(--accent);
    border: none;
    border-radius: 10px;
    cursor: pointer;
    transition: background 0.15s, transform 0.05s;
  }
  button:hover { background: var(--accent-hover); }
  button:active { transform: translateY(1px); }
  .alert {
    display: flex;
    gap: 9px;
    align-items: flex-start;
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-text);
    font-size: 13px;
    line-height: 1.4;
    padding: 11px 13px;
    border-radius: 10px;
    margin-bottom: 20px;
  }
  .alert svg { width: 16px; height: 16px; flex-shrink: 0; margin-top: 1px; }
</style>
</head>
<body>
  <main class="card">
    <div class="logo" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2"></rect>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
      </svg>
    </div>

    <h1>Sign in</h1>
    <p class="lede">Enter your credentials to continue.</p>

    {{if .Error}}
    <div class="alert" role="alert">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"></circle>
        <line x1="12" y1="8" x2="12" y2="12"></line>
        <line x1="12" y1="16" x2="12.01" y2="16"></line>
      </svg>
      <span>Incorrect username or password. Please try again.</span>
    </div>
    {{end}}

    <form method="POST" action="/login">
      <input type="hidden" name="rid" value="{{.RID}}">
      <div class="field">
        <label for="username">Username</label>
        <input id="username" name="username" type="text" autocomplete="username"
               autocapitalize="none" autocorrect="off" spellcheck="false"
               placeholder="admin" autofocus required>
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password"
               placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required>
      </div>
      <button type="submit">Sign in</button>
    </form>
  </main>
</body>
</html>`))

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
	_ = loginTmpl.Execute(w, map[string]any{"RID": rid})
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
		_ = loginTmpl.Execute(w, map[string]any{"RID": rid, "Error": true})
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
		Claim("email_verified", true).
		Claim("name", ac.Sub).
		Claim("preferred_username", ac.Sub).
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

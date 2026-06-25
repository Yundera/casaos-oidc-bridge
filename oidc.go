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
// CasaOS — see README "Design decision"). Styled to match the CasaOS UI login
// screen (frosted-glass panel over the CasaOS wallpaper, astronaut avatar,
// casablue button) so users recognise it as the same sign-in. All CSS is inline
// and the artwork is served from the bridge's own /assets routes (embedded into
// the binary, see assets.go) — no external network dependency.
//
// Style values are lifted from CasaOS-UI: primary = $casablue hsl(216,90%,54%),
// panel background rgba(255,255,255,.46) + blur(1rem), input background
// rgba(255,255,255,.32), label colour #dfdfdf (see CasaOS-UI Login.vue /
// _variables.scss).
var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style>
  :root {
    --primary: hsl(216, 90%, 54%);
    --primary-dark: hsl(216, 90%, 47%);
    --panel: rgba(255, 255, 255, 0.46);
    --input-bg: rgba(255, 255, 255, 0.32);
    --label: #dfdfdf;
    --text: #1d2530;
    --danger: hsl(348, 86%, 61%);
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; }
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
      linear-gradient(180deg, rgba(0, 0, 0, 0) 55%, rgba(0, 0, 0, 0.55) 100%),
      url("/assets/wallpaper.jpg") center / cover no-repeat fixed;
  }
  .login-panel {
    width: 100%;
    max-width: 28rem;
    text-align: left;
    background: var(--panel);
    backdrop-filter: blur(1rem);
    -webkit-backdrop-filter: blur(1rem);
    border-radius: 8px;
    padding: 2.5rem 4rem;
    box-shadow: 0 1.5rem 3rem rgba(0, 0, 0, 0.25);
  }
  .avatar-wrap { display: flex; justify-content: center; padding-bottom: 0.75rem; }
  .avatar {
    width: 128px;
    height: 128px;
    border-radius: 50%;
    display: block;
  }
  label {
    display: block;
    font-size: 1rem;
    font-weight: 700;
    color: var(--label);
    margin-bottom: 0.5rem;
  }
  .field { margin-bottom: 0.75rem; }
  .field.first { margin-top: 0.75rem; }
  input[type=text], input[type=password] {
    width: 100%;
    height: 2.5em;
    padding: 0 0.75em;
    font-size: 1rem;
    color: var(--text);
    background: var(--input-bg);
    border: 1px solid transparent;
    border-radius: 6px;
    outline: none;
    transition: box-shadow 0.15s, background 0.15s;
  }
  input::placeholder { color: rgba(29, 37, 48, 0.45); }
  input:focus {
    background: rgba(255, 255, 255, 0.45);
    box-shadow: 0 0 0 2px rgba(33, 110, 230, 0.45);
  }
  button {
    width: 100%;
    margin-top: 1.25rem;
    height: 2.75em;
    font-size: 1rem;
    font-weight: 600;
    color: #fff;
    background: var(--primary);
    border: none;
    border-radius: 290486px;
    cursor: pointer;
    transition: background 0.15s, transform 0.05s;
  }
  button:hover { background: var(--primary-dark); }
  button:active { transform: translateY(1px); }
  .alert {
    background: var(--danger);
    color: #fff;
    font-size: 0.875rem;
    line-height: 1.4;
    padding: 0.75rem 1rem;
    border-radius: 6px;
    margin-bottom: 1rem;
    text-align: center;
  }
  @media screen and (max-width: 480px) {
    .login-panel { padding: 2rem; margin: 0 1rem; }
    .avatar { width: 96px; height: 96px; }
  }
</style>
</head>
<body>
  <main class="login-panel">
    <div class="avatar-wrap">
      <img class="avatar" src="/assets/avatar.svg" alt="" aria-hidden="true">
    </div>

    {{if .Error}}
    <div class="alert" role="alert">Incorrect username or password. Please try again.</div>
    {{end}}

    <form method="POST" action="/login">
      <input type="hidden" name="rid" value="{{.RID}}">
      <div class="field first">
        <label for="username">Username</label>
        <input id="username" name="username" type="text" autocomplete="username"
               autocapitalize="none" autocorrect="off" spellcheck="false"
               autofocus required>
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password"
               required>
      </div>
      <button type="submit">Login</button>
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
	req := AuthRequest{
		ClientID:            q.Get("client_id"),
		RedirectURI:         redirectURI,
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),
		Scope:               q.Get("scope"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: ccm,
	}

	// SSO: if the browser already holds a valid bridge session, skip the login
	// form and issue a code straight away. This is what makes login on one app
	// silently grant access to the next — Dex re-runs this connector per client,
	// so the shared session has to live here.
	if sess, ok := b.currentSession(r); ok {
		b.completeAuth(w, r, req, sess)
		return
	}

	rid := b.store.putRequest(req)
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
	sess := Session{
		Sub:     sub,
		Email:   user.Email,
		Groups:  []string{user.Role}, // CasaOS role -> groups (default "admin"), Gate 2
		Expires: time.Now().Add(b.cfg.SessionTTL),
	}
	// Open the SSO session so subsequent apps' /authorize calls don't re-prompt.
	b.setSessionCookie(w, b.store.putSession(sess))
	b.completeAuth(w, r, req, sess)
}

// completeAuth mints a one-time code for an authenticated subject and redirects
// back to the client. Shared by the fresh-login path (/login) and the
// already-have-a-session path (/authorize).
func (b *Bridge) completeAuth(w http.ResponseWriter, r *http.Request, req AuthRequest, sess Session) {
	code := b.store.putCode(AuthCode{
		Req:     req,
		Sub:     sess.Sub,
		Email:   sess.Email,
		Groups:  sess.Groups,
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

// handleLogout ends the bridge SSO session: drops the server-side session and
// clears the cookie. After this, the next /authorize re-prompts for credentials.
func (b *Bridge) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		b.store.delSession(c.Value)
	}
	b.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

const sessionCookie = "bridge_session"

func (b *Bridge) currentSession(r *http.Request) (Session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return Session{}, false
	}
	return b.store.getSession(c.Value)
}

func (b *Bridge) setSessionCookie(w http.ResponseWriter, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   b.secureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(b.cfg.SessionTTL / time.Second),
	})
}

func (b *Bridge) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   b.secureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// secureCookies marks the session cookie Secure whenever the bridge is reached
// over HTTPS (it sits behind Caddy TLS in production; the issuer scheme is the
// reliable signal since the bridge itself terminates plain HTTP).
func (b *Bridge) secureCookies() bool {
	return strings.HasPrefix(b.cfg.Issuer, "https://")
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

// e2e drives the bridge through a full OIDC authorization-code + PKCE flow,
// standing in for Dex (the downstream client). It asserts the bridge issues a
// valid, correctly-signed id_token with the expected claims. Exit 0 = PASS.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func main() {
	if err := run(); err != nil {
		fmt.Println("E2E FAIL:", err)
		os.Exit(1)
	}
	fmt.Println("E2E PASS")
}

func run() error {
	issuer := env("BRIDGE_ISSUER", "http://bridge:8089")
	clientID := env("CLIENT_ID", "dex")
	clientSecret := env("CLIENT_SECRET", "dex-secret")
	redirect := env("REDIRECT_URI", "http://e2e:9000/callback")
	user := env("MOCK_USER", "admin")
	pass := env("MOCK_PASS", "casaos")
	ctx := context.Background()

	noRedir := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	if err := waitHealthy(issuer + "/healthz"); err != nil {
		return err
	}

	// 1. Discovery
	var disc map[string]any
	if err := getJSON(issuer+"/.well-known/openid-configuration", &disc); err != nil {
		return fmt.Errorf("discovery: %w", err)
	}
	authEP, _ := disc["authorization_endpoint"].(string)
	tokenEP, _ := disc["token_endpoint"].(string)
	jwksURI, _ := disc["jwks_uri"].(string)
	if authEP == "" || tokenEP == "" || jwksURI == "" {
		return fmt.Errorf("discovery missing endpoints: %v", disc)
	}
	fmt.Println("  discovery OK")

	// 2. PKCE + state + nonce
	verifier := randStr()
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := randStr()
	nonce := randStr()

	// 3. GET /authorize -> login form carrying the request id
	au, _ := url.Parse(authEP)
	q := au.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirect)
	q.Set("scope", "openid profile email groups")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	au.RawQuery = q.Encode()
	form, err := getBody(au.String())
	if err != nil {
		return fmt.Errorf("authorize: %w", err)
	}
	m := regexp.MustCompile(`name="rid" value="([^"]+)"`).FindStringSubmatch(form)
	if m == nil {
		return fmt.Errorf("no rid in login form")
	}
	fmt.Println("  authorize OK (login form returned)")

	// 4. POST /login -> 302 redirect with code
	resp, err := noRedir.PostForm(issuer+"/login", url.Values{
		"rid": {m[1]}, "username": {user}, "password": {pass},
	})
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		return fmt.Errorf("login expected 302, got %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return fmt.Errorf("bad redirect location: %w", err)
	}
	if loc.Query().Get("state") != state {
		return fmt.Errorf("state mismatch in redirect")
	}
	code := loc.Query().Get("code")
	if code == "" {
		return fmt.Errorf("no code in redirect: %s", loc.String())
	}
	fmt.Println("  login OK (code issued, state echoed)")

	// 5. POST /token (authorization_code + PKCE verifier)
	tr, err := http.PostForm(tokenEP, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}
	defer tr.Body.Close()
	var tok map[string]any
	if err := json.NewDecoder(tr.Body).Decode(&tok); err != nil {
		return fmt.Errorf("token decode: %w", err)
	}
	idToken, _ := tok["id_token"].(string)
	accessToken, _ := tok["access_token"].(string)
	if idToken == "" {
		return fmt.Errorf("no id_token in token response: %v", tok)
	}
	fmt.Println("  token OK (id_token + access_token returned)")

	// 6. Verify id_token signature against the bridge JWKS + assert claims
	set, err := jwk.Fetch(ctx, jwksURI)
	if err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}
	idt, err := jwt.Parse([]byte(idToken),
		jwt.WithKeySet(set),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(clientID),
	)
	if err != nil {
		return fmt.Errorf("id_token verify: %w", err)
	}
	if n, _ := idt.Get("nonce"); n != nonce {
		return fmt.Errorf("nonce mismatch: got %v", n)
	}
	email, _ := idt.Get("email")
	groups, _ := idt.Get("groups")
	if email == "" {
		return fmt.Errorf("id_token missing email claim")
	}
	fmt.Printf("  id_token verified: sub=%s email=%v groups=%v nonce-ok\n", idt.Subject(), email, groups)

	// 7. /userinfo with the access token
	req, _ := http.NewRequest(http.MethodGet, issuer+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	ur, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("userinfo: %w", err)
	}
	defer ur.Body.Close()
	var ui map[string]any
	if err := json.NewDecoder(ur.Body).Decode(&ui); err != nil {
		return fmt.Errorf("userinfo decode: %w", err)
	}
	if ui["sub"] != idt.Subject() {
		return fmt.Errorf("userinfo sub mismatch: %v vs %s", ui["sub"], idt.Subject())
	}
	fmt.Printf("  userinfo OK: %v\n", ui)
	return nil
}

// --- helpers ---

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func randStr() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func waitHealthy(u string) error {
	for i := 0; i < 60; i++ {
		resp, err := http.Get(u)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("service never became healthy: %s", u)
}

func getJSON(u string, v any) error {
	resp, err := http.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}

func getBody(u string) (string, error) {
	resp, err := http.Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

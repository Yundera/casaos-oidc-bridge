package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// casaosKeySetOpts make verification tolerant of CasaOS's JWKS quirks: the
// access token carries no `kid`, and the published JWK omits `alg`. UseDefault
// falls back to the single key when the token has no kid; InferAlgorithmFromKey
// derives the alg (ES256) from the key type.
var casaosKeySetOpts = []interface{}{
	jws.WithUseDefault(true),
	jws.WithInferAlgorithmFromKey(true),
}

// CasaUser mirrors the data.user object returned by CasaOS /v1/users/login (Gate 2).
type CasaUser struct {
	Id       int    `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Email    string `json:"email"`
}

// casaLoginResp is the envelope CasaOS returns: { success, message, data:{ token, user } }.
type casaLoginResp struct {
	Success int    `json:"success"`
	Message string `json:"message"`
	Data    struct {
		Token struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			ExpiresAt    int64  `json:"expires_at"`
		} `json:"token"`
		User CasaUser `json:"user"`
	} `json:"data"`
}

type CasaOSClient struct {
	loginURL string
	jwksURL  string
	cache    *jwk.Cache
	http     *http.Client
}

func NewCasaOSClient(ctx context.Context, loginURL, jwksURL string) (*CasaOSClient, error) {
	// Dynamic JWKS with cache + refresh. CasaOS regenerates its signing keypair on
	// every restart (Gate 2), so we must never pin a static key.
	c := jwk.NewCache(ctx)
	if err := c.Register(jwksURL, jwk.WithMinRefreshInterval(15*time.Second)); err != nil {
		return nil, err
	}
	return &CasaOSClient{
		loginURL: loginURL,
		jwksURL:  jwksURL,
		cache:    c,
		http:     &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// Login posts credentials to CasaOS and returns the user object + raw access token.
func (c *CasaOSClient) Login(ctx context.Context, username, password string) (CasaUser, string, error) {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.loginURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return CasaUser{}, "", err
	}
	defer resp.Body.Close()
	var lr casaLoginResp
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return CasaUser{}, "", err
	}
	if lr.Success != 200 || lr.Message != "ok" {
		return CasaUser{}, "", fmt.Errorf("casaos login rejected: success=%d message=%q", lr.Success, lr.Message)
	}
	return lr.Data.User, lr.Data.Token.AccessToken, nil
}

// VerifyToken checks the CasaOS access token signature against the live JWKS —
// proof that CasaOS (not the caller) issued it. On failure it forces one JWKS
// refresh, which handles kid rotation after a CasaOS restart.
func (c *CasaOSClient) VerifyToken(ctx context.Context, raw string) error {
	set, err := c.cache.Get(ctx, c.jwksURL)
	if err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}
	if _, err := jwt.Parse([]byte(raw), jwt.WithKeySet(set, casaosKeySetOpts...)); err != nil {
		if set2, e2 := c.cache.Refresh(ctx, c.jwksURL); e2 == nil {
			if _, e3 := jwt.Parse([]byte(raw), jwt.WithKeySet(set2, casaosKeySetOpts...)); e3 == nil {
				return nil
			}
		}
		return fmt.Errorf("token verify: %w", err)
	}
	return nil
}

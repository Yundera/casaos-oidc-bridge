package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// handleValidate is a NON-INTERACTIVE credential check for API / machine clients.
// It is not part of the OIDC redirect flow — it lets a trusted internal caller
// (the AppShield gate) verify a CasaOS credential with no browser involved:
//
//	Authorization: Basic base64(user:pass)  -> validated via CasaOS /v1/users/login
//	Authorization: Bearer <casaos-jwt>      -> verified against the live CasaOS JWKS
//
// On success: 200 + {"ok":true,"username":...,"sub":...}. Otherwise: 401.
//
// SECURITY: this sits in the CasaOS credential path (passwords transit it for the
// Basic case) and, left open, is a CasaOS password-bruteforce oracle. Keep it on
// the internal `pcs` network only, never log credentials, and — recommended — set
// VALIDATE_SECRET so only callers presenting the matching X-Validate-Secret header
// (i.e. the AppShield gate) may use it.
func (b *Bridge) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Optional shared-secret guard (defense against arbitrary pcs-network callers).
	if want := os.Getenv("VALIDATE_SECRET"); want != "" {
		if r.Header.Get("X-Validate-Secret") != want {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	authz := r.Header.Get("Authorization")
	if authz == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="CasaOS"`)
		http.Error(w, "missing Authorization", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	var username, sub string

	switch {
	case strings.HasPrefix(authz, "Basic "):
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(authz, "Basic ")))
		if err != nil {
			http.Error(w, "malformed basic credential", http.StatusUnauthorized)
			return
		}
		user, pass, ok := strings.Cut(string(raw), ":")
		if !ok {
			http.Error(w, "malformed basic credential", http.StatusUnauthorized)
			return
		}
		casaUser, _, err := b.casa.Login(ctx, user, pass)
		if err != nil {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		username = casaUser.Username
		sub = fmt.Sprintf("casaos:%d", casaUser.Id)

	case strings.HasPrefix(authz, "Bearer "):
		token := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
		if err := b.casa.VerifyToken(ctx, token); err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		// Verified as CasaOS-issued; pull the subject best-effort for attribution.
		if parsed, err := jwt.ParseInsecure([]byte(token)); err == nil {
			sub = parsed.Subject()
		}

	default:
		http.Error(w, "unsupported Authorization scheme", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "username": username, "sub": sub})
}

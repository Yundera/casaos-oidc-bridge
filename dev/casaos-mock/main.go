// casaos-mock is a tiny stand-in for CasaOS-UserService: just enough of the
// real contract (Gate 2) for the bridge to authenticate against in isolation:
//   - POST /v1/users/login  -> { success, message, data:{ token, user } }
//   - GET  /.well-known/jwks.json -> ES256 public key (rotates per process start)
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	signKey jwk.Key
	pubSet  jwk.Set
	user    = envOr("MOCK_USER", "admin")
	pass    = envOr("MOCK_PASS", "casaos")
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	k, err := jwk.FromRaw(raw)
	if err != nil {
		log.Fatal(err)
	}
	// Faithfully match real CasaOS: it sets NEITHER a `kid` NOR `alg` on its
	// signing key / JWKS. (An earlier mock set both, which masked a bridge bug:
	// verification must tolerate a missing kid + infer the alg.)
	signKey = k
	pub, _ := k.PublicKey()
	pubSet = jwk.NewSet()
	_ = pubSet.AddKey(pub)

	http.HandleFunc("/v1/users/login", login)
	http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pubSet)
	})
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })

	log.Printf("casaos-mock on :8080 (user=%s)", user)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	w.Header().Set("Content-Type", "application/json")
	if body.Username != user || body.Password != pass {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": 401, "message": "user not exist or password invalid"})
		return
	}
	now := time.Now()
	tok, _ := jwt.NewBuilder().
		Claim("id", 1).
		Claim("username", user).
		IssuedAt(now).
		Expiration(now.Add(3 * time.Hour)).
		Build()
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, signKey))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": 200,
		"message": "ok",
		"data": map[string]any{
			"token": map[string]any{
				"access_token":  string(signed),
				"refresh_token": "mock-refresh",
				"expires_at":    now.Add(3 * time.Hour).Unix(),
			},
			"user": map[string]any{
				"id": 1, "username": user, "role": "admin", "email": user + "@local",
			},
		},
	})
}

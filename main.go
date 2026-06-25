// Command casaos-oidc-bridge is a minimal OIDC provider that fronts CasaOS's
// existing login API. Dex (the broker) talks to it as an OIDC connector; the
// bridge in turn authenticates the user against CasaOS and issues OIDC tokens.
//
// SKELETON — proves the end-to-end chain (CasaOS login -> verify CasaOS JWT ->
// issue a signed OIDC id_token). NOT production-hardened: see README.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Config struct {
	Issuer       string
	Addr         string
	KeyPath      string // where the bridge's signing key is persisted
	CasaLoginURL string
	CasaJWKSURL  string
	ClientID     string // the single downstream OIDC client (Dex, or the e2e harness)
	ClientSecret string
	RedirectURIs []string
	SessionTTL   time.Duration // lifetime of the bridge SSO session cookie
}

func loadConfig() Config {
	return Config{
		Issuer:       env("BRIDGE_ISSUER", "http://localhost:8089"),
		Addr:         env("BRIDGE_ADDR", ":8089"),
		KeyPath:      env("BRIDGE_KEY_PATH", "/data/signing-key.json"),
		CasaLoginURL: env("CASAOS_LOGIN_URL", "http://casaos-mock:8080/v1/users/login"),
		CasaJWKSURL:  env("CASAOS_JWKS_URL", "http://casaos-mock:8080/.well-known/jwks.json"),
		ClientID:     env("CLIENT_ID", "dex"),
		ClientSecret: env("CLIENT_SECRET", "dex-secret"),
		RedirectURIs: strings.Split(env("REDIRECT_URIS", "http://localhost:9000/callback"), ","),
		SessionTTL:   time.Duration(envInt("BRIDGE_SESSION_TTL", 43200)) * time.Second,
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

type Bridge struct {
	cfg     Config
	signKey jwk.Key // private signing key (RS256), with kid + alg set
	pubKeys jwk.Set // published at /jwks
	casa    *CasaOSClient
	store   *Store
}

func main() {
	cfg := loadConfig()
	ctx := context.Background()

	// The bridge's own token-signing key, persisted across restarts so issued
	// tokens keep verifying and Dex's cached JWKS stays valid.
	priv, err := loadOrCreateSigningKey(cfg.KeyPath)
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		log.Fatalf("public key: %v", err)
	}
	set := jwk.NewSet()
	_ = set.AddKey(pub)

	casa, err := NewCasaOSClient(ctx, cfg.CasaLoginURL, cfg.CasaJWKSURL)
	if err != nil {
		log.Fatalf("casaos client: %v", err)
	}

	b := &Bridge{cfg: cfg, signKey: priv, pubKeys: set, casa: casa, store: NewStore()}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", b.handleDiscovery)
	mux.HandleFunc("/authorize", b.handleAuthorize)
	mux.HandleFunc("/assets/", b.handleAsset)
	mux.HandleFunc("/login", b.handleLogin)
	mux.HandleFunc("/logout", b.handleLogout)
	mux.HandleFunc("/token", b.handleToken)
	mux.HandleFunc("/jwks", b.handleJWKS)
	mux.HandleFunc("/userinfo", b.handleUserinfo)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })

	// Internal-only credential validation listener (deliberately NOT on the public,
	// gateway-routed port). /validate authenticates CasaOS Basic/Bearer credentials
	// for the AppShield gate; if it were internet-reachable it would be a CasaOS
	// password-bruteforce oracle. It binds a separate port that is exposed only on
	// the internal `pcs` network (no Caddy label), so no shared secret is needed.
	validateAddr := env("VALIDATE_ADDR", ":8090")
	vmux := http.NewServeMux()
	vmux.HandleFunc("/validate", b.handleValidate)
	vmux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	go func() {
		log.Printf("casaos-oidc-bridge /validate (internal, pcs-net only) listening on %s", validateAddr)
		vsrv := &http.Server{Addr: validateAddr, Handler: vmux, ReadHeaderTimeout: 5 * time.Second}
		log.Fatal(vsrv.ListenAndServe())
	}()

	log.Printf("casaos-oidc-bridge listening on %s (issuer=%s, casaos=%s)", cfg.Addr, cfg.Issuer, cfg.CasaLoginURL)
	srv := &http.Server{Addr: cfg.Addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

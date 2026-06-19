package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// loadOrCreateSigningKey loads the bridge's RSA signing key (JWK JSON) from
// path, or generates a new one and persists it. Persistence matters: a
// per-start key would invalidate every issued token on restart and stale Dex's
// cached JWKS. If the key cannot be persisted (e.g. read-only/ephemeral dev
// fs), it falls back to an in-memory key with a warning rather than failing.
func loadOrCreateSigningKey(path string) (jwk.Key, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		key, perr := jwk.ParseKey(data)
		if perr != nil {
			return nil, fmt.Errorf("parse signing key %s: %w", path, perr)
		}
		ensureKeyMeta(key)
		log.Printf("loaded signing key from %s (kid=%s)", path, key.KeyID())
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read signing key %s: %w", path, err)
	}

	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	key, err := jwk.FromRaw(raw)
	if err != nil {
		return nil, fmt.Errorf("jwk from raw: %w", err)
	}
	ensureKeyMeta(key)

	if err := persistKey(path, key); err != nil {
		log.Printf("WARNING: could not persist signing key to %s (%v) — using in-memory key; issued tokens will not survive a restart", path, err)
	} else {
		log.Printf("generated + persisted new signing key at %s (kid=%s)", path, key.KeyID())
	}
	return key, nil
}

func ensureKeyMeta(key jwk.Key) {
	if key.KeyID() == "" {
		_ = key.Set(jwk.KeyIDKey, "bridge-sign-1")
	}
	_ = key.Set(jwk.AlgorithmKey, jwa.RS256)
}

func persistKey(path string, key jwk.Key) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	data, err := json.Marshal(key)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

package main

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// AuthRequest is an in-flight OIDC authorization request, parked between
// /authorize and the user completing /login.
type AuthRequest struct {
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// AuthCode is a one-time authorization code bound to the authenticated subject.
type AuthCode struct {
	Req     AuthRequest
	Sub     string
	Email   string
	Groups  []string
	Expires time.Time
}

// Store is an in-memory store for auth requests + codes. Fine for the skeleton;
// production would use Dex-style storage or at least TTL eviction.
type Store struct {
	mu       sync.Mutex
	requests map[string]AuthRequest
	codes    map[string]AuthCode
}

func NewStore() *Store {
	return &Store{requests: map[string]AuthRequest{}, codes: map[string]AuthCode{}}
}

func randID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Store) putRequest(r AuthRequest) string {
	id := randID()
	s.mu.Lock()
	s.requests[id] = r
	s.mu.Unlock()
	return id
}

func (s *Store) getRequest(id string) (AuthRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.requests[id]
	return r, ok
}

func (s *Store) delRequest(id string) {
	s.mu.Lock()
	delete(s.requests, id)
	s.mu.Unlock()
}

func (s *Store) putCode(c AuthCode) string {
	code := randID()
	s.mu.Lock()
	s.codes[code] = c
	s.mu.Unlock()
	return code
}

// consumeCode returns and deletes the code (one-time use).
func (s *Store) consumeCode(code string) (AuthCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[code]
	if ok {
		delete(s.codes, code)
	}
	return c, ok
}

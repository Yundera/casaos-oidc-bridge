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

// Session is a logged-in bridge session, keyed by the value of the
// `bridge_session` cookie. It lets a second app's /authorize skip the login
// form: Dex re-runs the CasaOS connector for every client (it keeps no SSO
// session of its own), so the cross-app single-sign-on session must live here,
// at the one identity source every app funnels through.
type Session struct {
	Sub     string
	Email   string
	Groups  []string
	Expires time.Time
}

// Store is an in-memory store for auth requests + codes + sessions. Fine for the
// skeleton; production would use Dex-style storage or at least TTL eviction.
// Sessions are intentionally not persisted across restarts — a bridge restart
// just forces a re-login, same as the request/code maps.
type Store struct {
	mu       sync.Mutex
	requests map[string]AuthRequest
	codes    map[string]AuthCode
	sessions map[string]Session
}

func NewStore() *Store {
	return &Store{requests: map[string]AuthRequest{}, codes: map[string]AuthCode{}, sessions: map[string]Session{}}
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

func (s *Store) putSession(sess Session) string {
	id := randID()
	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()
	return id
}

// getSession returns the session for id, treating an expired session as absent
// (and evicting it).
func (s *Store) getSession(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return Session{}, false
	}
	if time.Now().After(sess.Expires) {
		delete(s.sessions, id)
		return Session{}, false
	}
	return sess, true
}

func (s *Store) delSession(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

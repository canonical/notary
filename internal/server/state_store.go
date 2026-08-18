package server

import (
	"sync"
	"time"
)

// StateEntry represents a stored OAuth state with metadata
type StateEntry struct {
	CreatedAt time.Time
	UserAgent string
	UserID    *int64
	Type      string
	// CodeVerifier is the PKCE code verifier generated for this login attempt.
	// It never leaves the server; only its S256 challenge is sent to the IdP.
	CodeVerifier string
	// Provider is the name of the OIDC provider this login attempt was started
	// against, so the callback resolves the same one.
	Provider string
}

// StateStore manages OAuth state parameters for CSRF protection
// Each state is unique per login attempt and expires after a short time
type StateStore struct {
	mu     sync.RWMutex
	states map[string]StateEntry
}

// NewStateStore creates a new state store
func NewStateStore() *StateStore {
	return &StateStore{
		states: make(map[string]StateEntry),
	}
}

// Store saves a state parameter with associated metadata
func (s *StateStore) Store(state string, userAgent string) {
	s.StorePKCE(state, userAgent, "", "")
}

// StorePKCE saves a state parameter along with the PKCE code verifier and the
// OIDC provider selected for the same login attempt.
func (s *StateStore) StorePKCE(state string, userAgent string, codeVerifier string, provider string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.states[state] = StateEntry{
		CreatedAt:    time.Now(),
		UserAgent:    userAgent,
		Type:         "login", // Default to login type
		CodeVerifier: codeVerifier,
		Provider:     provider,
	}
}

// Validate checks if a state is valid and removes it (one-time use)
// Returns true if the state is valid, false otherwise
func (s *StateStore) Validate(state string, userAgent string) bool {
	_, ok := s.Consume(state, userAgent)
	return ok
}

// Consume validates a state and removes it (one-time use), returning the stored
// entry so callers can recover metadata such as the PKCE code verifier.
func (s *StateStore) Consume(state string, userAgent string) (*StateEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.states[state]
	if !exists {
		return nil, false
	}

	if time.Since(entry.CreatedAt) > 5*time.Minute {
		delete(s.states, state)
		return nil, false
	}

	if entry.UserAgent != userAgent {
		delete(s.states, state)
		return nil, false
	}

	delete(s.states, state)
	return &entry, true
}

// Get retrieves a state entry without deleting it (for inspecting metadata)
// Returns the entry and whether it exists and is valid
func (s *StateStore) Get(state string, userAgent string) (*StateEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.states[state]
	if !exists {
		return nil, false
	}

	if time.Since(entry.CreatedAt) > 5*time.Minute {
		return nil, false
	}

	if entry.UserAgent != userAgent {
		return nil, false
	}

	return &entry, true
}

// Delete removes a state from the store
func (s *StateStore) Delete(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, state)
}

// Cleanup removes expired states from the store
// Should be called periodically to prevent memory leaks
func (s *StateStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for state, entry := range s.states {
		if now.Sub(entry.CreatedAt) > 5*time.Minute {
			delete(s.states, state)
		}
	}
}

// Size returns the current number of stored states (useful for monitoring)
func (s *StateStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.states)
}

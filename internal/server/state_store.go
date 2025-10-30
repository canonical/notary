package server

import (
	"sync"
	"time"
)

// StateEntry represents a stored OAuth state with metadata
type StateEntry struct {
	CreatedAt time.Time
	UserAgent string
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
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.states[state] = StateEntry{
		CreatedAt: time.Now(),
		UserAgent: userAgent,
	}
}

// Validate checks if a state is valid and removes it (one-time use)
// Returns true if the state is valid, false otherwise
func (s *StateStore) Validate(state string, userAgent string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	entry, exists := s.states[state]
	if !exists {
		return false
	}
	
	if time.Since(entry.CreatedAt) > 5*time.Minute {
		delete(s.states, state)
		return false
	}

	if entry.UserAgent != userAgent {
		delete(s.states, state)
		return false
	}
	
	delete(s.states, state)
	return true
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


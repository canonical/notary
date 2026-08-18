package encryption

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// SealState reports whether this node has unwrapped its data encryption key yet.
//
// A node is sealed from the moment it starts until its own unwrap against the
// configured backend succeeds. While sealed it replicates data and participates
// in Raft normally, but it cannot serve any route that needs plaintext key
// material. Unsealing is automatic and per-node: nothing outside the node acts
// on this signal.
type SealState struct {
	mu       sync.RWMutex
	unsealed bool
	lastErr  error
}

// NewSealState returns a state that starts out sealed.
func NewSealState() *SealState {
	return &SealState{}
}

// Sealed reports whether the node still has to unwrap its encryption key.
//
// A nil SealState reads as unsealed. Only the server tracks seal state; every
// other construction of an EncryptionRepository (tests, CLI subcommands) has
// already completed its unwrap synchronously by the time anything asks.
func (s *SealState) Sealed() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.unsealed
}

// LastError returns the error from the most recent failed unwrap attempt, or nil
// if the node is unsealed or has not attempted an unwrap yet.
func (s *SealState) LastError() error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.unsealed {
		return nil
	}
	return s.lastErr
}

// Unseal marks the unwrap as complete.
func (s *SealState) Unseal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unsealed = true
	s.lastErr = nil
}

// RecordFailure stores the reason the most recent unwrap attempt failed so that
// operators can see it without reading the node's logs.
func (s *SealState) RecordFailure(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastErr = err
}

// StartUnsealing runs unseal once and, if it fails, keeps retrying every
// interval in the background until it succeeds or ctx is done. The returned
// state stays sealed until an attempt succeeds.
//
// A node whose encryption backend is unreachable must still start: it joins
// Raft, replicates, and votes while sealed, and unseals itself as soon as the
// backend comes back, with no operator action.
func StartUnsealing(ctx context.Context, interval time.Duration, logger *zap.Logger, unseal func() error) *SealState {
	state := NewSealState()

	err := unseal()
	if err == nil {
		state.Unseal()
		return state
	}
	state.RecordFailure(err)
	logger.Warn(
		"Node is sealed and will retry in the background",
		zap.Error(err),
		zap.Duration("retry_interval", interval),
	)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := unseal(); err != nil {
					state.RecordFailure(err)
					logger.Warn("Unseal attempt failed", zap.Error(err))
					continue
				}
				state.Unseal()
				logger.Info("Node unsealed")
				return
			}
		}
	}()

	return state
}

package encryption_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/canonical/notary/internal/backends/encryption"
	"go.uber.org/zap"
)

func TestSealStateStartsSealed(t *testing.T) {
	state := encryption.NewSealState()
	if !state.Sealed() {
		t.Fatal("expected a new seal state to be sealed")
	}
	if state.LastError() != nil {
		t.Fatalf("expected no failure before the first attempt, got %s", state.LastError())
	}

	failure := errors.New("vault unreachable")
	state.RecordFailure(failure)
	if !errors.Is(state.LastError(), failure) {
		t.Fatalf("expected the recorded failure, got %v", state.LastError())
	}

	state.Unseal()
	if state.Sealed() {
		t.Fatal("expected the state to be unsealed")
	}
	if state.LastError() != nil {
		t.Fatalf("expected unsealing to clear the last failure, got %s", state.LastError())
	}
}

// A nil state reads as unsealed so that every construction of an
// EncryptionRepository that unwraps synchronously does not have to opt in.
func TestNilSealStateIsUnsealed(t *testing.T) {
	var state *encryption.SealState
	if state.Sealed() {
		t.Fatal("expected a nil seal state to read as unsealed")
	}
	if state.LastError() != nil {
		t.Fatalf("expected a nil seal state to have no failure, got %s", state.LastError())
	}
}

func TestStartUnsealingUnsealsImmediatelyWhenTheBackendIsReachable(t *testing.T) {
	var attempts atomic.Int64
	state := encryption.StartUnsealing(t.Context(), time.Millisecond, zap.NewNop(), func() error {
		attempts.Add(1)
		return nil
	})

	if state.Sealed() {
		t.Fatal("expected the node to be unsealed after a successful attempt")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("expected exactly one attempt, got %d", got)
	}
}

// This is spec.md §5's "recovers automatically" row: a node that could not reach
// its backend at startup unseals itself once the backend comes back, with no
// restart and no operator action.
func TestStartUnsealingRetriesUntilTheBackendRecovers(t *testing.T) {
	failure := errors.New("vault unreachable")
	var reachable atomic.Bool

	state := encryption.StartUnsealing(t.Context(), time.Millisecond, zap.NewNop(), func() error {
		if !reachable.Load() {
			return failure
		}
		return nil
	})

	if !state.Sealed() {
		t.Fatal("expected the node to stay sealed while the backend is unreachable")
	}
	if !errors.Is(state.LastError(), failure) {
		t.Fatalf("expected the backend failure to be reported, got %v", state.LastError())
	}

	reachable.Store(true)
	waitUntilUnsealed(t, state)

	if state.LastError() != nil {
		t.Fatalf("expected no failure once unsealed, got %s", state.LastError())
	}
}

func TestStartUnsealingStopsRetryingWhenTheContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var attempts atomic.Int64

	state := encryption.StartUnsealing(ctx, time.Millisecond, zap.NewNop(), func() error {
		attempts.Add(1)
		return errors.New("vault unreachable")
	})
	cancel()

	// The retry goroutine may already be mid-attempt when the context is
	// cancelled, so allow it to settle before sampling the count.
	time.Sleep(20 * time.Millisecond)
	settled := attempts.Load()
	time.Sleep(20 * time.Millisecond)

	if got := attempts.Load(); got != settled {
		t.Fatalf("expected retries to stop after cancellation, attempts went from %d to %d", settled, got)
	}
	if !state.Sealed() {
		t.Fatal("expected the node to stay sealed")
	}
}

func waitUntilUnsealed(t *testing.T, state *encryption.SealState) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !state.Sealed() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for the node to unseal")
}

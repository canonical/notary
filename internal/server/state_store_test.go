package server

import (
	"testing"
	"time"
)

func TestStateStore_StoreAndValidate(t *testing.T) {
	t.Run("valid state validates successfully", func(t *testing.T) {
		store := NewStateStore()
		state := "test-state-123"
		userAgent := "Mozilla/5.0"

		store.Store(state, userAgent)

		if !store.Validate(state, userAgent) {
			t.Error("expected valid state to validate successfully")
		}
	})

	t.Run("state can only be used once", func(t *testing.T) {
		store := NewStateStore()
		state := "test-state-456"
		userAgent := "Mozilla/5.0"

		store.Store(state, userAgent)

		if !store.Validate(state, userAgent) {
			t.Error("expected first validation to succeed")
		}

		if store.Validate(state, userAgent) {
			t.Error("expected second validation to fail - state should be one-time use")
		}
	})

	t.Run("invalid state fails validation", func(t *testing.T) {
		store := NewStateStore()
		userAgent := "Mozilla/5.0"

		if store.Validate("nonexistent-state", userAgent) {
			t.Error("expected nonexistent state to fail validation")
		}
	})

	t.Run("wrong user agent fails validation", func(t *testing.T) {
		store := NewStateStore()
		state := "test-state-789"
		userAgent1 := "Mozilla/5.0 (Chrome)"
		userAgent2 := "Mozilla/5.0 (Firefox)"

		store.Store(state, userAgent1)

		if store.Validate(state, userAgent2) {
			t.Error("expected validation to fail with different user agent")
		}

		if store.Validate(state, userAgent1) {
			t.Error("expected state to be deleted after failed validation")
		}
	})

	t.Run("expired state fails validation", func(t *testing.T) {
		store := NewStateStore()
		state := "test-state-expired"
		userAgent := "Mozilla/5.0"

		store.mu.Lock()
		store.states[state] = StateEntry{
			CreatedAt: time.Now().Add(-10 * time.Minute),
			UserAgent: userAgent,
		}
		store.mu.Unlock()

		if store.Validate(state, userAgent) {
			t.Error("expected expired state to fail validation")
		}
	})
}

func TestStateStore_Cleanup(t *testing.T) {
	t.Run("cleanup removes expired states", func(t *testing.T) {
		store := NewStateStore()

		store.Store("fresh-state", "Mozilla/5.0")

		store.mu.Lock()
		store.states["expired-state"] = StateEntry{
			CreatedAt: time.Now().Add(-10 * time.Minute),
			UserAgent: "Mozilla/5.0",
		}
		store.mu.Unlock()

		if store.Size() != 2 {
			t.Errorf("expected 2 states before cleanup, got %d", store.Size())
		}

		store.Cleanup()

		if store.Size() != 1 {
			t.Errorf("expected 1 state after cleanup, got %d", store.Size())
		}

		if !store.Validate("fresh-state", "Mozilla/5.0") {
			t.Error("expected fresh state to still be valid after cleanup")
		}
	})

	t.Run("cleanup doesn't remove recent states", func(t *testing.T) {
		store := NewStateStore()

		store.Store("state-1", "Agent1")
		store.Store("state-2", "Agent2")
		store.Store("state-3", "Agent3")

		store.Cleanup()

		if store.Size() != 3 {
			t.Errorf("expected 3 states after cleanup, got %d", store.Size())
		}
	})
}

func TestStateStore_Size(t *testing.T) {
	store := NewStateStore()

	if store.Size() != 0 {
		t.Errorf("expected empty store to have size 0, got %d", store.Size())
	}

	store.Store("state-1", "Agent1")
	store.Store("state-2", "Agent2")

	if store.Size() != 2 {
		t.Errorf("expected store to have size 2, got %d", store.Size())
	}

	store.Validate("state-1", "Agent1")

	if store.Size() != 1 {
		t.Errorf("expected store to have size 1 after validation, got %d", store.Size())
	}
}

func TestStateStore_ConcurrentAccess(t *testing.T) {
	t.Run("concurrent store operations", func(t *testing.T) {
		store := NewStateStore()
		done := make(chan bool)

		for i := 0; i < 100; i++ {
			go func(n int) {
				state := generateRandomString(32)
				store.Store(state, "Agent")
				done <- true
			}(i)
		}

		for i := 0; i < 100; i++ {
			<-done
		}

		if store.Size() != 100 {
			t.Errorf("expected 100 states after concurrent stores, got %d", store.Size())
		}
	})

	t.Run("concurrent validate operations", func(t *testing.T) {
		store := NewStateStore()
		state := "concurrent-test-state"
		userAgent := "Mozilla/5.0"

		store.Store(state, userAgent)

		successCount := 0
		done := make(chan bool)

		for i := 0; i < 10; i++ {
			go func() {
				if store.Validate(state, userAgent) {
					successCount++
				}
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}

		if successCount > 1 {
			t.Errorf("expected only 1 successful validation, got %d", successCount)
		}
	})
}

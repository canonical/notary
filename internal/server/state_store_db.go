package server

import (
	"github.com/canonical/notary/internal/db"
	"go.uber.org/zap"
)

// DBStateStore stores OIDC CSRF state in dqlite so any member can validate the callback.
type DBStateStore struct {
	db     *db.DatabaseRepository
	logger *zap.Logger
}

func NewDBStateStore(database *db.DatabaseRepository, logger *zap.Logger) *DBStateStore {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &DBStateStore{db: database, logger: logger}
}

func (s *DBStateStore) Store(state string, userAgent string) {
	if err := s.db.StoreOIDCState(state, userAgent); err != nil {
		s.logger.Error("failed to store OIDC state", zap.Error(err))
	}
}

func (s *DBStateStore) Validate(state string, userAgent string) bool {
	return s.db.ValidateOIDCState(state, userAgent)
}

func (s *DBStateStore) Cleanup() {
	if err := s.db.CleanupOIDCStates(); err != nil {
		s.logger.Warn("failed to clean up expired OIDC states", zap.Error(err))
	}
}

func (s *DBStateStore) Size() int {
	return s.db.CountOIDCStates()
}

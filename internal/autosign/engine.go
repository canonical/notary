package autosign

import (
	"context"
	"time"

	"github.com/canonical/notary/internal/db"
	"go.uber.org/zap"
)

const DefaultPollInterval = 5 * time.Second

type Engine struct {
	database         *db.DatabaseRepository
	logger           *zap.Logger
	externalHostname string
	pollInterval     time.Duration
}

func New(database *db.DatabaseRepository, logger *zap.Logger, externalHostname string) *Engine {
	return &Engine{database, logger, externalHostname, DefaultPollInterval}
}

func (e *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(e.pollInterval)
	defer ticker.Stop()

	e.processOutstandingCSRs()

	for {
		select {
		case <-ticker.C:
			e.processOutstandingCSRs()
		case <-ctx.Done():
			e.logger.Info("auto-sign engine shutting down")
			return
		}
	}
}

func (e *Engine) processOutstandingCSRs() {
	policies, err := e.database.ListActiveAutoSignPolicies()
	if err != nil {
		e.logger.Error("failed to list active auto-sign policies", zap.Error(err))
		return
	}
	if len(policies) == 0 {
		return
	}

	csrs, err := e.database.ListOutstandingCSRsExcludingCAs()
	if err != nil {
		e.logger.Error("failed to list outstanding CSRs", zap.Error(err))
		return
	}
	if len(csrs) == 0 {
		return
	}

	policy := policies[0]
	for _, csr := range csrs {
		err := e.database.SignCertificateRequest(db.ByCSRID(csr.CSR_ID), db.ByCertificateAuthorityDenormalizedID(policy.CertificateAuthorityID), e.externalHostname)
		if err != nil {
			e.logger.Error("failed to auto-sign CSR",
				zap.Int64("csr_id", csr.CSR_ID),
				zap.Int64("ca_id", policy.CertificateAuthorityID),
				zap.Error(err),
			)
			continue
		}
		e.logger.Info("auto-signed CSR",
			zap.Int64("csr_id", csr.CSR_ID),
			zap.Int64("ca_id", policy.CertificateAuthorityID),
		)
	}
}

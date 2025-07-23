package server

import (
	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/encryption_backend"
	"go.uber.org/zap"
)

type ServerOpts struct {
	Port                       int
	Cert                       []byte
	Key                        []byte
	DBPath                     string
	ExternalHostname           string
	PebbleNotificationsEnabled bool
	Logger                     *zap.Logger
	EncryptionBackend          encryption_backend.EncryptionBackend
	PublicConfig               config.PublicConfigData
	Token                      string
}

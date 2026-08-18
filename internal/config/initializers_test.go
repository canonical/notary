package config_test

import (
	"testing"

	"github.com/canonical/notary/internal/acme"
	"github.com/canonical/notary/internal/config"
	tu "github.com/canonical/notary/internal/testutils"
	"github.com/spf13/viper"
)

// The JWT secret is stored encrypted under the data encryption key, so it is
// loaded as part of the unseal sequence. It used to be loaded only as a side
// effect of configuring OIDC, which left deployments without an identity
// provider signing every session token with an empty HMAC key.
func TestJWTSecretIsLoadedWithoutOIDCConfigured(t *testing.T) {
	appConfig := tu.MustCreateTestAppConfig(t)
	appConfig.OIDCConfig = nil
	encryptionConfig := viper.New()
	encryptionConfig.Set("type", "none")
	appConfig.EncryptionConfig = encryptionConfig

	database := tu.MustPrepareEmptyDB(t)
	// Drop the secret the test fixture loaded, so only the code under test can
	// put it back.
	database.JWTSecret = nil

	appEnv, err := config.InitializeAppEnvironment(t.Context(), appConfig, database, nil, acme.NewReconciler())
	if err != nil {
		t.Fatalf("couldn't initialize app environment: %s", err)
	}

	if appEnv.EncryptionRepository.Sealed() {
		t.Fatal("expected a reachable encryption backend to leave the node unsealed")
	}
	if len(appEnv.Database.JWTSecret) == 0 {
		t.Fatal("expected the JWT secret to be loaded when no OIDC provider is configured")
	}
}

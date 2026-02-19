package config

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/canonical/notary/internal/backends/authentication"
	authz "github.com/canonical/notary/internal/backends/authorization"
	"github.com/canonical/notary/internal/backends/encryption"
	"github.com/canonical/notary/internal/backends/observability/log"
	"github.com/canonical/notary/internal/backends/observability/tracing"
	"github.com/canonical/notary/internal/db"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/viper"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/oauth2"
)

// InitializeAppEnvironment takes an AppConfig and database, then initializes all subsystems,
// returning an AppEnvironment with the initialized resources.
func InitializeAppEnvironment(appConfig *AppConfig, database *db.DatabaseRepository) (*AppEnvironment, error) {
	appEnv := &AppEnvironment{}
	appEnv.Database = database

	// initialize system logger
	systemLogger, err := initializeLogger(appConfig.LoggingConfig.Sub("system"))
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize system logging subsystem: %w", err)
	}

	// initialize audit logger
	auditLogger, err := initializeAuditLogger(appConfig.LoggingConfig.Sub("audit"))
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize audit logging subsystem: %w", err)
	}

	// initialize tracing server routine
	tracingRepo, err := initializeTracing(appConfig.TracingConfig, systemLogger)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize tracing subsystem: %w", err)
	}

	// initialize encryption backend connection
	encryptionRepo, err := initializeEncryptionBackend(appConfig.EncryptionConfig, database, systemLogger)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize encryption subsystem: %w", err)
	}

	// initialize OIDC config TODO: jwt key should be set up here
	authnRepo, err := initializeOIDC(appConfig.OIDCConfig, database, appConfig.ExternalHostname)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize OIDC subsystem: %w", err)
	}

	// initialize openfga server routine
	authzRepo, err := InitializeAuthorizationConfig(database, systemLogger)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize authorization subsystem: %w", err)
	}

	appEnv.SystemLogger = systemLogger
	appEnv.AuditLogger = auditLogger
	appEnv.TracingRepository = tracingRepo
	appEnv.EncryptionRepository = encryptionRepo
	appEnv.AuthnRepository = authnRepo
	appEnv.AuthzRepository = authzRepo

	return appEnv, nil
}

// initializeEncryptionBackend reads the configuration of the backend and chooses the appropriate decryption method.
func initializeEncryptionBackend(encryptionCfg *viper.Viper, database *db.DatabaseRepository, logger *zap.Logger) (*encryption.EncryptionRepository, error) {
	backendType := encryptionCfg.GetString("type")
	encryptionRepo := &encryption.EncryptionRepository{}
	switch backendType {
	case "vault":
		if !encryptionCfg.IsSet("endpoint") {
			return nil, errors.New("endpoint is missing")
		}
		if !encryptionCfg.IsSet("mount") {
			return nil, errors.New("mount is missing")
		}
		if !encryptionCfg.IsSet("key_name") {
			return nil, errors.New("key_name is missing")
		}
		if (!encryptionCfg.IsSet("approle_role_id") || !encryptionCfg.IsSet("secret_role_id")) && !encryptionCfg.IsSet("token") {
			return nil, errors.New("provide either approle_role_id and approle_secret_id or token, not both")
		}
		if encryptionCfg.IsSet("approle_role_id") && encryptionCfg.IsSet("secret_role_id") {
			backend, err := encryption.NewVaultBackendWithAppRole(
				encryptionCfg.GetString("endpoint"),
				encryptionCfg.GetString("mount"),
				encryptionCfg.GetString("key_name"),
				encryptionCfg.GetString("approle_role_id"),
				encryptionCfg.GetString("secret_role_id"),
				encryptionCfg.GetString("tls_ca_certificate"),
				encryptionCfg.GetBool("tls_skip_verify"),
				logger,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to create Vault encryption backend: %w", err)
			}
			encryptionRepo.Type = encryption.EncryptionBackendTypeVault
			encryptionRepo.Service = backend
		} else if encryptionCfg.IsSet("token") {
			backend, err := encryption.NewVaultBackendWithToken(
				encryptionCfg.GetString("endpoint"),
				encryptionCfg.GetString("mount"),
				encryptionCfg.GetString("key_name"),
				encryptionCfg.GetString("token"),
				encryptionCfg.GetString("tls_ca_certificate"),
				encryptionCfg.GetBool("tls_skip_verify"),
				logger,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to create Vault encryption backend: %w", err)
			}
			encryptionRepo.Type = encryption.EncryptionBackendTypeVault
			encryptionRepo.Service = backend
		} else {
			return nil, errors.New("failed to create Vault encryption backend: either approle_role_id and approle_secret_id or token must be provided")
		}
	case "pkcs11":
		if !encryptionCfg.IsSet("lib_path") {
			return nil, errors.New("lib_path is missing")
		}
		if !encryptionCfg.IsSet("pin") {
			return nil, errors.New("pin is missing")
		}
		if !encryptionCfg.IsSet("aes_encryption_key_id") {
			return nil, errors.New("aes_encryption_key_id is missing")
		}
		backend, err := encryption.NewPKCS11Backend(
			encryptionCfg.GetString("lib_path"),
			encryptionCfg.GetString("pin"),
			encryptionCfg.GetUint16("aes_encryption_key_id"),
			logger,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create PKCS11 backend: %w", err)
		}
		encryptionRepo.Type = encryption.EncryptionBackendTypePKCS11
		encryptionRepo.Service = backend
	case "none":
		encryptionRepo.Type = encryption.EncryptionBackendTypeNone
		encryptionRepo.Service = &encryption.NoEncryptionBackend{}
	default:
		return nil, errors.New("invalid encryption backend type; must be 'none', 'vault' or 'pkcs11'")
	}
	if err := encryption.SetUpEncryptionKey(database, encryptionRepo.Service, logger); err != nil {
		return nil, fmt.Errorf("failed to set up encryption key: %w", err)
	}
	return encryptionRepo, nil
}

// initializeLogger creates and configures a logger based on the provided configuration.
// cfg is the logger configuration subsection (e.g., logging.system).
// output can be "stdout", "stderr", or a file path.
func initializeLogger(cfg *viper.Viper) (*zap.Logger, error) {
	if cfg == nil {
		return nil, fmt.Errorf("logger configuration is not defined")
	}

	zapConfig := zap.NewProductionConfig()

	logLevel, err := zapcore.ParseLevel(cfg.GetString("level"))
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}
	zapConfig.Level.SetLevel(logLevel)

	output := cfg.GetString("output")
	zapConfig.OutputPaths = []string{output}

	zapConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	logger, err := zapConfig.Build()
	if err != nil {
		return nil, err
	}

	return logger, nil
}

// initializeAuditLogger creates an audit logger that always logs at INFO level, regardless of config.
// cfg is the logger configuration subsection (e.g., logging.audit).
// output can be "stdout", "stderr", or a file path.
func initializeAuditLogger(cfg *viper.Viper) (*log.AuditLogger, error) {
	if cfg == nil {
		return nil, fmt.Errorf("logger configuration is not defined")
	}

	zapConfig := zap.NewProductionConfig()
	// Force INFO level for audit logs
	zapConfig.Level.SetLevel(zapcore.InfoLevel)

	output := cfg.GetString("output")
	zapConfig.OutputPaths = []string{output}

	zapConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	logger, err := zapConfig.Build()
	if err != nil {
		return nil, err
	}
	auditLogger := log.NewAuditLogger(logger)
	return auditLogger, nil
}

// InitializeAuthorizationConfig initializes the authorization config after database creation
// This needs to be called from cmd/start.go after the database is created
func InitializeAuthorizationConfig(database *db.DatabaseRepository, logger *zap.Logger) (*authz.AuthzRepository, error) {
	ofgaConfig, err := authz.InitializeLocalOpenFGA(database, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OpenFGA: %w", err)
	}
	return ofgaConfig, nil
}

func initializeOIDC(cfg *viper.Viper, database *db.DatabaseRepository, externalHostname string) (*authentication.OIDCRepository, error) {
	if cfg == nil {
		return nil, nil
	}

	err := authentication.SetUpJWTSecret(database)
	if err != nil {
		return nil, fmt.Errorf("failed to set up JWT secret: %w", err)
	}

	oidcServer := fmt.Sprintf("https://%s/", cfg.GetString("domain"))
	clientID := cfg.GetString("client_id")
	clientSecret := cfg.GetString("client_secret")
	audience := cfg.GetString("audience")
	emailScope := cfg.GetString("email_scope_key")
	permissionsScope := cfg.GetString("permissions_scope_key")
	extraScopes := cfg.GetStringSlice("extra_scopes")

	provider, err := oidc.NewProvider(context.Background(), oidcServer)
	if err != nil {
		return nil, err
	}

	var discovery struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	_ = provider.Claims(&discovery)

	jwksURL := discovery.JWKSURI
	if jwksURL == "" {
		jwksURL = oidcServer + ".well-known/jwks.json"
	}
	keyfunc, err := keyfunc.NewDefaultCtx(context.Background(), []string{jwksURL})
	if err != nil {
		return nil, err
	}

	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  fmt.Sprintf("https://%s/api/v1/oauth/callback", externalHostname),

		Endpoint: provider.Endpoint(),

		Scopes: append([]string{oidc.ScopeOpenID, emailScope, permissionsScope}, extraScopes...),
	}

	return &authentication.OIDCRepository{
		OAuth2Config:        oauth2Config,
		Audience:            audience,
		OIDCProvider:        provider,
		Issuer:              discovery.Issuer,
		KeyFunc:             keyfunc,
		EmailClaimKey:       emailScope,
		PermissionsClaimKey: permissionsScope,
	}, nil
}

// initializeTracing creates and configures a tracer based on the configuration.
func initializeTracing(cfg *viper.Viper, logger *zap.Logger) (*tracing.TracingRepository, error) {
	if cfg == nil {
		return nil, nil
	}
	cfg.SetDefault("tracing.service_name", "notary")
	cfg.SetDefault("tracing.sampling_rate", "100%")

	if !cfg.IsSet("endpoint") {
		return nil, errors.New("`tracing.endpoint` is required when tracing is enabled")
	}
	serviceName := cfg.GetString("service_name")
	endpoint := cfg.GetString("endpoint")
	samplingRate, err := parseSamplingRate(cfg.GetString("sampling_rate"))
	if err != nil {
		return nil, fmt.Errorf("invalid sampling rate: %w", err)
	}
	tracer := otel.Tracer("notary")
	shutdownFunc, err := tracing.SetupTracing(context.Background(), endpoint, serviceName, samplingRate, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to set up tracing: %w", err)
	}
	return &tracing.TracingRepository{
		Tracer:       tracer,
		ShutdownFunc: shutdownFunc,
	}, nil
}

// parseSamplingRate converts a string sampling rate (percentage or decimal) to a float64
func parseSamplingRate(rate string) (float64, error) {
	// Try to parse as a float first
	samplingRate, err := strconv.ParseFloat(rate, 64)
	if err == nil {
		// Check if the value is between 0 and 1 inclusive
		if samplingRate < 0 || samplingRate > 1 {
			return 0, fmt.Errorf("sampling rate must be between 0 and 1, got %f", samplingRate)
		}
		return samplingRate, nil
	}

	// If parsing as float failed, check if it's a percentage string
	if len(rate) > 1 && rate[len(rate)-1] == '%' {
		// Remove % and parse as float
		percentage, err := strconv.ParseFloat(rate[:len(rate)-1], 64)
		if err != nil {
			return 0, fmt.Errorf("invalid sampling rate format: %s", rate)
		}

		// Convert percentage to decimal
		samplingRate = percentage / 100.0

		// Check if the value is between 0 and 1 inclusive
		if samplingRate < 0 || samplingRate > 1 {
			return 0, fmt.Errorf("sampling rate percentage must be between 0%% and 100%%, got %s", rate)
		}

		return samplingRate, nil
	}

	return 0, fmt.Errorf("invalid sampling rate format: %s", rate)
}

package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/canonical/notary/internal/acme"
	"github.com/canonical/notary/internal/backends/authentication"
	authz "github.com/canonical/notary/internal/backends/authorization"
	"github.com/canonical/notary/internal/backends/encryption"
	"github.com/canonical/notary/internal/backends/observability/log"
	"github.com/canonical/notary/internal/backends/observability/tracing"
	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/db"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/viper"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
)

const (
	// jwksRefreshInterval is how often the cached JWK Set is refreshed in the background.
	jwksRefreshInterval = time.Hour
	// jwksUnknownKIDRefreshInterval bounds how often a token carrying an unknown
	// `kid` may trigger an out-of-band JWKS refetch.
	jwksUnknownKIDRefreshInterval = 30 * time.Second
	// unsealRetryInterval is how often a sealed node retries its encryption
	// backend. The node unseals itself within one interval of the backend
	// becoming reachable again; no operator action is involved.
	unsealRetryInterval = 10 * time.Second
)

// InitializeAppEnvironment takes an AppConfig and database, then initializes all subsystems,
// returning an AppEnvironment with the initialized resources.
//
// clusterNode is this node's dqlite membership, or nil when clustering is
// disabled; the cluster API reports itself unavailable in that case.
//
// ctx bounds the background work the environment starts, most notably the retry
// loop of a node that could not reach its encryption backend at startup.
func InitializeAppEnvironment(ctx context.Context, appConfig *AppConfig, database *db.DatabaseRepository, clusterNode cluster.Node, acmeReconciler *acme.Reconciler) (*AppEnvironment, error) {
	appEnv := &AppEnvironment{}
	appEnv.Database = database
	appEnv.ClusterNode = clusterNode
	appEnv.ACMEReconciler = acmeReconciler

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
	encryptionRepo, err := initializeEncryptionBackend(ctx, appConfig.EncryptionConfig, appConfig.ClusterConfig, database, systemLogger)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize encryption subsystem: %w", err)
	}

	// initialize OIDC config
	authnRepo, err := initializeOIDC(appConfig.OIDCConfig, appConfig.ExternalHostname)
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
func initializeEncryptionBackend(ctx context.Context, encryptionCfg *viper.Viper, clusterCfg ClusterConfig, database *db.DatabaseRepository, logger *zap.Logger) (*encryption.EncryptionRepository, error) {
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
	encryptionRepo.SealState = startUnsealing(ctx, database, clusterCfg, encryptionRepo.Service, logger)
	return encryptionRepo, nil
}

// startUnsealing unwraps the data encryption key and loads the secrets stored
// under it. If the configured backend is unreachable the node stays sealed and
// keeps retrying in the background rather than refusing to start: a node that
// cannot reach Vault/HSM still joins Raft, replicates, and votes, and unseals
// itself the moment the backend comes back. It serves 503 on the routes that
// need plaintext key material until then.
func startUnsealing(ctx context.Context, database *db.DatabaseRepository, clusterCfg ClusterConfig, backend encryption.EncryptionService, logger *zap.Logger) *encryption.SealState {
	return encryption.StartUnsealing(ctx, unsealRetryInterval, logger, func() error {
		if err := encryption.SetUpEncryptionKey(database, backend, logger); err != nil {
			return fmt.Errorf("failed to set up encryption key: %w", err)
		}
		// The JWT secret is stored encrypted under the data encryption key, so it
		// can only be loaded once the unwrap has succeeded.
		if err := authentication.SetUpJWTSecret(database); err != nil {
			return fmt.Errorf("failed to set up JWT secret: %w", err)
		}
		// So is the cluster CA key, and for the same reason it belongs here: a
		// node that bootstrapped while its backend was unreachable would
		// otherwise never store it, and every join would fail until a restart.
		if clusterCfg.Enabled {
			if err := ensureClusterCAKey(database, clusterCfg.StateDir); err != nil {
				return fmt.Errorf("failed to store the cluster CA key: %w", err)
			}
		}
		return nil
	})
}

// ensureClusterCAKey makes the replicated database the only place the cluster CA
// key is kept.
//
// The bootstrapping node writes it to disk before any database exists, so it is
// moved across on the first start that gets far enough to encrypt it, and the
// plaintext copy is removed once the replicated write reads back. Every other
// member has no disk copy and gets the key through replication, so this is a
// no-op for them, and it is safe to run on every unseal attempt.
func ensureClusterCAKey(database *db.DatabaseRepository, stateDir string) error {
	diskKey, diskErr := cluster.LoadCAKey(stateDir)
	// Absent is the ordinary case for a member that joined. Anything else — bad
	// permissions, a truncated file — must not be mistaken for it, or the node
	// would come up reporting itself healthy while no key ever reaches the
	// cluster and every join fails.
	if diskErr != nil && !errors.Is(diskErr, os.ErrNotExist) {
		return diskErr
	}

	stored, storedErr := database.GetClusterCAKey()
	switch {
	case storedErr == nil:
		// Already replicated. Sweep up a plaintext copy left by this node's own
		// bootstrap, or by a version that kept one; anything that does not match
		// is not ours to delete.
		if diskErr == nil && bytes.Equal(stored, diskKey) {
			return cluster.RemoveCAKey(stateDir)
		}
		return nil
	case !errors.Is(storedErr, db.ErrNotFound):
		return storedErr
	case diskErr != nil:
		// Nothing stored and nothing on disk: a joined member, still waiting for
		// the row to replicate.
		return nil
	}

	if err := database.CreateClusterCAKey(diskKey); err != nil {
		return err
	}

	// Confirmed before the only other copy is destroyed.
	readBack, err := database.GetClusterCAKey()
	if err != nil {
		return fmt.Errorf("failed to read back the stored cluster CA key: %w", err)
	}
	if !bytes.Equal(readBack, diskKey) {
		return errors.New("the stored cluster CA key does not match the one on disk")
	}

	return cluster.RemoveCAKey(stateDir)
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

// initializeOIDC builds one OIDCRepository per configured provider. Any number of
// providers may be configured simultaneously, each with its own issuer, client
// credentials, claim mapping and JWKS cache.
func initializeOIDC(cfgs []*viper.Viper, externalHostname string) (authentication.OIDCProviders, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	providers := make(authentication.OIDCProviders, 0, len(cfgs))
	seenNames := make(map[string]bool, len(cfgs))
	for i, cfg := range cfgs {
		provider, err := initializeOIDCProvider(cfg, externalHostname, i)
		if err != nil {
			return nil, err
		}
		if seenNames[provider.Name] {
			return nil, fmt.Errorf("duplicate OIDC provider name %q", provider.Name)
		}
		seenNames[provider.Name] = true
		providers = append(providers, provider)
	}
	return providers, nil
}

func initializeOIDCProvider(cfg *viper.Viper, externalHostname string, index int) (*authentication.OIDCRepository, error) {
	name := cfg.GetString("name")
	if name == "" {
		name = cfg.GetString("domain")
	}
	if name == "" {
		return nil, fmt.Errorf("OIDC provider %d is missing both `name` and `domain`", index)
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
		return nil, fmt.Errorf("OIDC provider %q discovery failed: %w", name, err)
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
	// RefreshUnknownKID makes the JWKS cache fetch out-of-band when a token
	// carries a `kid` the cache doesn't know about, so an IdP key rotation that
	// lands between scheduled refreshes doesn't reject valid tokens for a full
	// refresh interval. The rate limiter bounds how often an unknown `kid` can
	// trigger a fetch, so unknown-`kid` tokens can't be used to hammer the IdP.
	keyfunc, err := keyfunc.NewDefaultOverrideCtx(context.Background(), []string{jwksURL}, keyfunc.Override{
		RefreshInterval:   jwksRefreshInterval,
		RefreshUnknownKID: rate.NewLimiter(rate.Every(jwksUnknownKIDRefreshInterval), 1),
	})
	if err != nil {
		return nil, fmt.Errorf("OIDC provider %q JWKS setup failed: %w", name, err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  fmt.Sprintf("https://%s/api/v1/oauth/callback", externalHostname),

		Endpoint: provider.Endpoint(),

		Scopes: append([]string{oidc.ScopeOpenID, emailScope, permissionsScope}, extraScopes...),
	}

	return &authentication.OIDCRepository{
		Name:                name,
		OAuth2Config:        oauth2Config,
		Audience:            audience,
		OIDCProvider:        provider,
		Issuer:              discovery.Issuer,
		KeyFunc:             keyfunc,
		EmailClaimKey:       emailScope,
		PermissionsClaimKey: permissionsScope,
		RoleMapping: authentication.RoleMapping{
			Claim:  cfg.GetString("role_mapping.claim"),
			Values: parseRoleMappingValues(cfg.GetStringMap("role_mapping.values")),
		},
	}, nil
}

// parseRoleMappingValues converts the raw `role_mapping.values` mapping into
// claim value -> role ID. Entries whose value isn't an integer are dropped
// rather than silently granting an unintended role.
func parseRoleMappingValues(raw map[string]any) map[string]int {
	if len(raw) == 0 {
		return nil
	}
	values := make(map[string]int, len(raw))
	for claimValue, roleID := range raw {
		if role, ok := roleID.(int); ok {
			values[claimValue] = role
		}
	}
	return values
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

// Package server provides a server object that represents the Notary backend
package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/canonical/notary/internal/config"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New creates an environment and an http server with handlers that Go can start listening to
func New(appCfg *config.AppConfig, appEnv *config.AppEnvironment) (*Server, error) {
	serverCerts, err := tls.X509KeyPair(appCfg.TLSCertificate, appCfg.TLSPrivateKey)
	if err != nil {
		return nil, err
	}
	stdErrLog, err := zap.NewStdLogAt(appEnv.SystemLogger, zapcore.ErrorLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger for http server: %w", err)
	}

	cfg := &HandlerDependencies{
		AppConfig:      appCfg,
		AppEnvironment: appEnv,
	}
	router := NewRouter(cfg)

	if appEnv.AuthnRepository != nil {
		cfg.StateStore = NewStateStore()

		go func() {
			ticker := time.NewTicker(1 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				cfg.StateStore.Cleanup()
				appEnv.SystemLogger.Debug("cleaned up expired OIDC states",
					zap.Int("remaining_states", cfg.StateStore.Size()))
			}
		}()

		appEnv.SystemLogger.Info("OIDC authentication enabled with state store")
	}
	if appEnv.TracingRepository != nil {
		router = otelhttp.NewHandler(
			router,
			"http_server",
			otelhttp.WithMessageEvents(otelhttp.ReadEvents, otelhttp.WriteEvents),
			otelhttp.WithSpanNameFormatter(func(operation string, r *http.Request) string {
				return fmt.Sprintf("%s %s", r.Method, r.URL.Path)
			}),
		)
	}
	s := &http.Server{
		Addr:           fmt.Sprintf(":%d", appCfg.Port),
		ErrorLog:       stdErrLog,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		Handler:        router,
		MaxHeaderBytes: 1 << 20,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCerts},
		},
	}
	return &Server{
		Server: s,
	}, err
}

func (s *Server) Start() error {
	return s.ListenAndServeTLS("", "")
}

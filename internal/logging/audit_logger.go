package logging

import (
	"fmt"

	"github.com/canonical/notary/internal/db"
	"go.uber.org/zap"
)

// AuditLogger provides structured logging for security audit events.
type AuditLogger struct {
	logger *zap.Logger
}

// NewAuditLogger creates a new audit logger with a named logger for easy filtering.
func NewAuditLogger(logger *zap.Logger) *AuditLogger {
	return &AuditLogger{
		logger: logger.Named("audit"),
	}
}

// Authentication Events

// LoginSuccess logs a successful user authentication.
func (a *AuditLogger) LoginSuccess(username string, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityInfo}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", fmt.Sprintf("authn_login_success:%s", username)),
		zap.String("username", username),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Info(fmt.Sprintf("User %s login successfully", username), fields...)
}

// LoginFailed logs a failed authentication attempt.
func (a *AuditLogger) LoginFailed(username string, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityWarn}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", fmt.Sprintf("authn_login_fail:%s", username)),
		zap.String("username", username),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Warn(fmt.Sprintf("User %s login failed", username), fields...)
}

// TokenCreated logs when a JWT authentication token is created.
func (a *AuditLogger) TokenCreated(username string, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityInfo}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", fmt.Sprintf("authn_token_created:%s", username)),
		zap.String("username", username),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Info(fmt.Sprintf("A token has been created for %s", username), fields...)
}

// PasswordChanged logs when a user's password is successfully changed.
func (a *AuditLogger) PasswordChanged(username string, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityInfo}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", fmt.Sprintf("authn_password_change:%s", username)),
		zap.String("username", username),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Info(fmt.Sprintf("User %s has successfully changed their password", username), fields...)
}

// PasswordChangeFailed logs when a password change attempt fails.
func (a *AuditLogger) PasswordChangeFailed(username string, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityCritical}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", fmt.Sprintf("authn_password_change_fail:%s", username)),
		zap.String("username", username),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Error(fmt.Sprintf("User %s failed to change their password", username), fields...)
}

// Certificate Events

// CertificateRequested logs when a certificate signing request is created.
func (a *AuditLogger) CertificateRequested(csrID string, caID int, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityInfo}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", "cert_requested"),
		zap.String("csr_id", csrID),
		zap.Int("ca_id", caID),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Info("Certificate signing request created", fields...)
}

// CertificateIssued logs when a certificate is successfully issued.
func (a *AuditLogger) CertificateIssued(csrID string, caID int, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityInfo}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", "cert_issued"),
		zap.String("csr_id", csrID),
		zap.Int("ca_id", caID),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Info("Certificate issued", fields...)
}

// CertificateRejected logs when a certificate request is rejected.
func (a *AuditLogger) CertificateRejected(csrID string, caID int, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityWarn}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", "cert_rejected"),
		zap.String("csr_id", csrID),
		zap.Int("ca_id", caID),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Warn("Certificate request rejected", fields...)
}

// Certificate Authority Events

// CACreated logs when a new certificate authority is created.
func (a *AuditLogger) CACreated(caID int, commonName string, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityInfo}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", "ca_created"),
		zap.Int("ca_id", caID),
		zap.String("common_name", commonName),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Info("Certificate Authority created", fields...)
}

// CADeleted logs when a certificate authority is deleted.
func (a *AuditLogger) CADeleted(caID int, commonName string, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityWarn}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", "ca_deleted"),
		zap.Int("ca_id", caID),
		zap.String("common_name", commonName),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Warn("Certificate Authority deleted", fields...)
}

// CAUpdated logs when a certificate authority enabled status is changed.
func (a *AuditLogger) CAUpdated(caID string, enabled bool, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityWarn}
	for _, opt := range opts {
		opt(ctx)
	}

	status := "disabled"
	if enabled {
		status = "enabled"
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", "ca_updated"),
		zap.String("ca_id", caID),
		zap.String("status", status),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Warn("Certificate Authority updated", fields...)
}

// CACertificateUploaded logs when a CA certificate chain is uploaded.
func (a *AuditLogger) CACertificateUploaded(caID string, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityInfo}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", "ca_cert_uploaded"),
		zap.String("ca_id", caID),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Info("Certificate uploaded to Certificate Authority", fields...)
}

// CACertificateRevoked logs when a CA certificate is revoked.
func (a *AuditLogger) CACertificateRevoked(caID string, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityWarn}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", "ca_cert_revoked"),
		zap.String("ca_id", caID),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Warn("Certificate Authority certificate revoked", fields...)
}

// User Management Events

// UserCreated logs when a new user account is created.
func (a *AuditLogger) UserCreated(username string, roleID int, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityWarn}
	for _, opt := range opts {
		opt(ctx)
	}

	roleName := fmt.Sprintf("role_%d", roleID)
	if roleID == int(db.RoleCertificateManager) {
		roleName = "admin"
	} else if roleID == 2 {
		roleName = "user"
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", fmt.Sprintf("user_created:%s,%s", username, roleName)),
		zap.String("username", username),
		zap.Int("role_id", roleID),
		zap.String("role_name", roleName),
	}
	fields = append(fields, ctx.toZapFields()...)

	description := fmt.Sprintf("User account %s created with role %s", username, roleName)
	if ctx.actor != "" {
		description = fmt.Sprintf("User %s created user %s with role %s", ctx.actor, username, roleName)
	}
	a.logger.Warn(description, fields...)
}

// UserDeleted logs when a user account is deleted.
func (a *AuditLogger) UserDeleted(username string, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityWarn}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", "user_deleted"),
		zap.String("username", username),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Warn("User account deleted", fields...)
}

// UserUpdated logs when a user account is updated (e.g., password changed).
func (a *AuditLogger) UserUpdated(username, updateType string, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityWarn}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", fmt.Sprintf("user_updated:%s,%s", username, updateType)),
		zap.String("username", username),
		zap.String("update_type", updateType),
	}
	fields = append(fields, ctx.toZapFields()...)

	description := fmt.Sprintf("User %s updated with %s", username, updateType)
	if ctx.actor != "" {
		description = fmt.Sprintf("User %s updated user %s with %s", ctx.actor, username, updateType)
	}
	a.logger.Warn(description, fields...)
}

// Access Control Events

// AccessDenied logs when a user is denied access to a resource.
func (a *AuditLogger) AccessDenied(username, resource, action string, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityCritical}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", fmt.Sprintf("authz_fail:%s,%s", username, resource)),
		zap.String("username", username),
		zap.String("resource", resource),
		zap.String("action", action),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Error("Access denied", fields...)
}

// UnauthorizedAccess logs when an unauthorized access attempt is detected.
func (a *AuditLogger) UnauthorizedAccess(opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityCritical}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", "authz_fail"),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Error("Unauthorized access attempt", fields...)
}

// API Action Events

// APIAction logs any action performed against the API.
func (a *AuditLogger) APIAction(action string, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityInfo}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "audit"),
		zap.String("event", "api_action"),
		zap.String("action", action),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Info("API action performed", fields...)
}

// CSR and Certificate Request lifecycle events (deletions and revocations)

// CertificateRequestDeleted logs when a CSR is deleted.
func (a *AuditLogger) CertificateRequestDeleted(csrID string, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityWarn}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", "cert_request_deleted"),
		zap.String("csr_id", csrID),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Warn("Certificate request deleted", fields...)
}

// CertificateRevoked logs when a certificate (for a CSR) is revoked.
func (a *AuditLogger) CertificateRevoked(csrID string, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityWarn}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", "cert_revoked"),
		zap.String("csr_id", csrID),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Warn("Certificate revoked", fields...)
}

// Backup Events

// BackupCreated logs when a database backup is successfully created.
func (a *AuditLogger) BackupCreated(backupPath string, opts ...AuditOption) {
	ctx := &auditContext{severity: SeverityInfo}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", "backup_created"),
		zap.String("backup_path", backupPath),
	}
	fields = append(fields, ctx.toZapFields()...)

	a.logger.Info("Database backup created", fields...)
}

// BackupRestored logs when a database backup is successfully restored.
func (a *AuditLogger) BackupRestored(backupFile string, opts ...AuditOption) {
    ctx := &auditContext{severity: SeverityInfo}
	for _, opt := range opts {
		opt(ctx)
	}

	fields := []zap.Field{
		zap.String("type", "security"),
		zap.String("event", "backup_restored"),
		zap.String("backup_file", backupFile),
	}
	fields = append(fields, ctx.toZapFields()...)

    a.logger.Info("Database backup restored", fields...)
}

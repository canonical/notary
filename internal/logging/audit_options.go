package logging

import (
	"net/http"

	"go.uber.org/zap"
)

// AuditOption is a functional option for adding context to audit log events.
type AuditOption func(*auditContext)

// SecuritySeverity represents the severity level for audit events using standard log levels
type SecuritySeverity string

const (
	SeverityDebug    SecuritySeverity = "DEBUG"
	SeverityInfo     SecuritySeverity = "INFO"
	SeverityWarn     SecuritySeverity = "WARN"
	SeverityError    SecuritySeverity = "ERROR"
	SeverityCritical SecuritySeverity = "CRITICAL"
)

// auditContext holds optional contextual information for audit events.
type auditContext struct {
	actor        string
	ipAddress    string
	reason       string
	userAgent    string
	path         string
	method       string
	resourceType string
	resourceID   string
	severity     SecuritySeverity
}

// WithActor specifies who performed the action (e.g., username, email).
func WithActor(actor string) AuditOption {
	return func(ctx *auditContext) {
		ctx.actor = actor
	}
}

// WithReason specifies the reason for an action (typically used for failures).
func WithReason(reason string) AuditOption {
	return func(ctx *auditContext) {
		ctx.reason = reason
	}
}

// WithResourceType specifies the type of resource being acted upon (e.g., "certificate", "user", "ca").
func WithResourceType(resourceType string) AuditOption {
	return func(ctx *auditContext) {
		ctx.resourceType = resourceType
	}
}

// WithResourceID specifies the ID of the resource being acted upon.
func WithResourceID(id string) AuditOption {
	return func(ctx *auditContext) {
		ctx.resourceID = id
	}
}

// WithRequest is a convenience function that extracts multiple fields from an HTTP request.
// It captures: remote IP, user agent, path, and method. Kept simple by design.
func WithRequest(r *http.Request) AuditOption {
	return func(ctx *auditContext) {
		ctx.ipAddress = r.RemoteAddr
		ctx.userAgent = r.UserAgent()
		ctx.path = r.URL.Path
		ctx.method = r.Method
	}
}

// toZapFields converts the audit context into zap fields.
// Only non-empty fields are included in the output.
func (ctx *auditContext) toZapFields() []zap.Field {
	fields := []zap.Field{}

	if ctx.actor != "" {
		fields = append(fields, zap.String("actor", ctx.actor))
	}
	if ctx.ipAddress != "" {
		fields = append(fields, zap.String("ip_address", ctx.ipAddress))
	}
	if ctx.reason != "" {
		fields = append(fields, zap.String("reason", ctx.reason))
	}
	if ctx.userAgent != "" {
		fields = append(fields, zap.String("user_agent", ctx.userAgent))
	}
	if ctx.path != "" {
		fields = append(fields, zap.String("path", ctx.path))
	}
	if ctx.method != "" {
		fields = append(fields, zap.String("method", ctx.method))
	}
	if ctx.resourceType != "" {
		fields = append(fields, zap.String("resource_type", ctx.resourceType))
	}
	if ctx.resourceID != "" {
		fields = append(fields, zap.String("resource_id", ctx.resourceID))
	}
	if ctx.severity != "" {
		fields = append(fields, zap.String("severity", string(ctx.severity)))
	}

	return fields
}

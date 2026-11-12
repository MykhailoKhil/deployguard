package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	gh "github.com/deployguard/deployguard/internal/github"
)

// secretKeyParts mark attribute names whose values must never be logged, as a
// backstop in case a future call site passes one by mistake.
var secretKeyParts = []string{"secret", "token", "password", "key", "authorization", "pem", "cookie"}

// newLogger returns a JSON logger that redacts secret-looking attributes.
// DEPLOYGUARD_LOG_LEVEL accepts debug, info (default), warn or error.
func newLogger(getenv func(string) string, out io.Writer) (*slog.Logger, error) {
	var level slog.Level
	switch strings.ToLower(strings.TrimSpace(getenv("DEPLOYGUARD_LOG_LEVEL"))) {
	case "", "info":
		level = slog.LevelInfo
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, fmt.Errorf("DEPLOYGUARD_LOG_LEVEL must be debug, info, warn or error")
	}
	return slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			name := strings.ToLower(attr.Key)
			for _, part := range secretKeyParts {
				if strings.Contains(name, part) {
					return slog.String(attr.Key, "[REDACTED]")
				}
			}
			return attr
		},
	})), nil
}

// slogAuditor writes webhook audit events as structured log lines. The events
// carry identifiers and outcomes only, never request bodies or plan values.
type slogAuditor struct{ logger *slog.Logger }

// Record logs one audit event: rejections as warnings, accepted and ignored deliveries as info.
func (a slogAuditor) Record(ctx context.Context, event gh.AuditEvent) {
	level := slog.LevelInfo
	if event.Outcome != gh.AuditAccepted && event.Outcome != gh.AuditIgnored && event.Outcome != gh.AuditDuplicate {
		level = slog.LevelWarn
	}
	a.logger.LogAttrs(ctx, level, "webhook audit",
		slog.String("outcome", string(event.Outcome)), slog.String("event_type", event.EventType),
		slog.Int64("installation_id", event.InstallationID), slog.Int64("repository_id", event.RepositoryID))
}

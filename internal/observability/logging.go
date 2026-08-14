package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const LevelTrace = slog.Level(-8)

type Config struct {
	Logger  *slog.Logger
	TraceID string
}

func New(output io.Writer, levelName string) (Config, error) {
	level, err := ParseLevel(levelName)
	if err != nil {
		return Config{}, err
	}
	traceID, err := randomHex(16)
	if err != nil {
		return Config{}, fmt.Errorf("generate diagnostic trace ID: %w", err)
	}
	handler := slog.NewTextHandler(output, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(_ []string, attribute slog.Attr) slog.Attr {
			if attribute.Key == slog.LevelKey && attribute.Value.Any().(slog.Level) == LevelTrace {
				attribute.Value = slog.StringValue("TRACE")
			}
			return attribute
		},
	})
	return Config{Logger: slog.New(handler).With("trace_id", traceID), TraceID: traceID}, nil
}

func ParseLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "trace":
		return LevelTrace, nil
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning", "":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, errors.New("--log-level must be one of trace, debug, info, warn, or error")
	}
}

func LogDuration(logger *slog.Logger, level slog.Level, phase string, startedAt time.Time, attributes ...any) {
	logger.Log(context.Background(), level, "phase.complete", append([]any{"phase", phase, "duration_ms", time.Since(startedAt).Milliseconds()}, attributes...)...)
}

type Transport struct {
	Base    http.RoundTripper
	Logger  *slog.Logger
	TraceID string
}

func (t Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	spanID, err := randomHex(8)
	if err != nil {
		return nil, fmt.Errorf("generate HTTP diagnostic span ID: %w", err)
	}
	outbound := request.Clone(request.Context())
	outbound.Header = request.Header.Clone()
	if outbound.Header.Get("traceparent") == "" {
		outbound.Header.Set("traceparent", "00-"+t.TraceID+"-"+spanID+"-01")
	}
	outbound.Header.Set("x-correlation-id", t.TraceID)
	startedAt := time.Now()
	t.Logger.Log(request.Context(), LevelTrace, "http.request", "method", request.Method, "host", request.URL.Host, "path", request.URL.Path)
	response, err := base.RoundTrip(outbound)
	attributes := []any{
		"method", request.Method,
		"host", request.URL.Host,
		"path", request.URL.Path,
		"duration_ms", time.Since(startedAt).Milliseconds(),
	}
	if err != nil {
		t.Logger.Debug("http.complete", append(attributes, "result", "error", "error", err.Error())...)
		return nil, err
	}
	t.Logger.Debug("http.complete", append(attributes,
		"result", "ok",
		"status", response.StatusCode,
		"request_id", response.Header.Get("request-id"),
	)...)
	return response, nil
}

func randomHex(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

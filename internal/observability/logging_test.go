package observability

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestTransportCorrelatesAndRedactsHTTPDiagnostics(t *testing.T) {
	// [spec: cli/cli-diagnostics]
	var output bytes.Buffer
	config, err := New(&output, "debug")
	if err != nil {
		t.Fatal(err)
	}
	transport := Transport{
		Logger: config.Logger, TraceID: config.TraceID,
		Base: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if !strings.Contains(request.Header.Get("traceparent"), config.TraceID) {
				t.Fatalf("traceparent = %q", request.Header.Get("traceparent"))
			}
			if request.Header.Get("x-correlation-id") != config.TraceID {
				t.Fatalf("x-correlation-id = %q", request.Header.Get("x-correlation-id"))
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Request-Id": []string{"worker-request"}},
				Body:       io.NopCloser(strings.NewReader("ok")),
				Request:    request,
			}, nil
		}),
	}
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com/items?token=secret", nil)
	request.Header.Set("authorization", "Bearer secret")
	if _, err := transport.RoundTrip(request); err != nil {
		t.Fatal(err)
	}
	log := output.String()
	for _, expected := range []string{"level=DEBUG", "msg=http.complete", "host=example.com", "path=/items", "request_id=worker-request"} {
		if !strings.Contains(log, expected) {
			t.Fatalf("log omitted %q: %s", expected, log)
		}
	}
	for _, secret := range []string{"token=secret", "Bearer secret"} {
		if strings.Contains(log, secret) {
			t.Fatalf("log exposed %q: %s", secret, log)
		}
	}
}

func TestNewRejectsUnknownLogLevel(t *testing.T) {
	if _, err := New(io.Discard, "verbose"); err == nil || !strings.Contains(err.Error(), "--log-level") {
		t.Fatalf("error = %v", err)
	}
}

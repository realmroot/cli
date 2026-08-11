package agent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	restish "github.com/saltbo/restish/v2"
)

func TestEmbeddedRuntimeOpensAndPollsProfiledResource(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/budget-requests":
			writer.Header().Set("Link", "<"+interactiveResourceProfile+">; rel=\"profile\"")
			writer.Header().Set("Retry-After", "1")
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"id": "request-1", "status": "pending",
				"interaction": map[string]any{
					"type": "user-approval", "status": "pending",
					"url": server.URL + "/approve#token=secret", "expiresAt": time.Now().Add(time.Minute),
				},
				"links": map[string]any{"self": server.URL + "/budget-requests/request-1"},
			})
		case request.Method == http.MethodGet && request.URL.Path == "/budget-requests/request-1":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"id": "request-1", "status": "approved",
				"interaction": map[string]any{"type": "user-approval", "status": "completed"},
				"links":       map[string]any{"self": server.URL + "/budget-requests/request-1"},
			})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	runtime := restish.New()
	runtime.Stdout, runtime.Stderr = &stdout, &stderr
	runtime.SetSignalHandling(false)
	runtime.SetDefaultConfig(&restish.Config{APIs: map[string]*restish.APIConfig{
		"wallet": {BaseURL: server.URL},
	}})
	runtime.SetCommandSurface(restish.CommandSurface{
		HTTPMethods: []string{"post"}, IgnoreUserConfig: true, DisablePlugins: true, HideInternalFlags: true,
	})
	browser := &browserRecorder{}
	runtime.AddResponseMiddleware(NewInteractiveResponseMiddleware(runtime, browser.Open, &stderr, false, "default"))

	err := runtime.Run([]string{
		"realmroot toolbox", "post", server.URL + "/budget-requests", "{}",
		"--rsh-output-format", "json", "--rsh-print", "b",
	})
	if err != nil {
		t.Fatal(err)
	}
	if browser.uri != server.URL+"/approve#token=secret" {
		t.Fatalf("opened %q", browser.uri)
	}
	if !strings.Contains(stderr.String(), "Waiting for controller approval") {
		t.Fatalf("diagnostics = %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), `"status":"approved"`) || !strings.Contains(stdout.String(), `"status":"completed"`) {
		t.Fatalf("output = %s", stdout.String())
	}
	t.Logf("opened approval page: %s", browser.uri)
	t.Logf("diagnostics: %s", strings.TrimSpace(stderr.String()))
	t.Logf("final response: %s", strings.TrimSpace(stdout.String()))
}

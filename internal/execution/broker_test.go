package execution

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/realmroot/toolbox/internal/catalog"
	restish "github.com/saltbo/restish/v2"
)

func TestNativeResourceToolUsesEphemeralDPoPBroker(t *testing.T) {
	t.Parallel()
	var authorization, proof string
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		authorization = request.Header.Get("Authorization")
		proof = request.Header.Get("DPoP")
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	source := &fakeSource{resource: upstream.URL}
	broker, err := NewBroker(upstream.URL, "rrcs_reference", []string{"resource:read"}, source, upstream.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	base, err := broker.StartTCP(func(request *http.Request) (string, error) { return request.URL.RequestURI(), nil }, func(request *http.Request) bool {
		return request.Header.Get("Authorization") == "Bearer "+broker.SessionToken()
	})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, base+"/items/1", nil)
	request.Header.Set("Authorization", "Bearer "+broker.SessionToken())
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d: %s", response.StatusCode, body)
	}
	if authorization != "DPoP resource-token" || proof == "" {
		t.Fatalf("upstream auth = %q, proof present = %t", authorization, proof != "")
	}
	if source.scopes != "resource:read" {
		t.Fatalf("issued scopes = %q", source.scopes)
	}
}

func TestNativeResourceToolRejectsUnadvertisedExecutables(t *testing.T) {
	t.Parallel()
	_, _, err := selectIntegration([]catalog.ToolIntegration{{ID: "git", Executables: []string{"git"}, Protocol: "git-smart-http"}}, []string{"curl"})
	if err == nil || !strings.Contains(err.Error(), "does not advertise") {
		t.Fatalf("error = %v", err)
	}
}

func TestCloudflareNativeToolEnvironmentRemovesProviderCredentials(t *testing.T) {
	t.Parallel()
	values := cleanEnvironment([]string{"PATH=/bin", "CLOUDFLARE_API_TOKEN=secret", "CF_API_KEY=secret", "SAFE=value"}, providerCredentialNames("wrangler"))
	joined := strings.Join(values, "\n")
	if strings.Contains(joined, "secret") || !strings.Contains(joined, "SAFE=value") {
		t.Fatalf("environment = %q", joined)
	}
}

type fakeSource struct {
	resource string
	scopes   string
}

func (s *fakeSource) Describe(_ context.Context, _, _, _, _ string, scopes []string) (restish.DPoPCredentialDescription, error) {
	s.scopes = strings.Join(scopes, " ")
	return restish.DPoPCredentialDescription{ProofMethod: http.MethodPost, ProofURI: "https://issuer.example/credential", Resource: s.resource, Scopes: scopes}, nil
}

func (s *fakeSource) Issue(_ context.Context, _, _, _, _, _ string, scopes []string) (restish.DPoPIssuedCredential, error) {
	return restish.DPoPIssuedCredential{AccessToken: "resource-token", TokenType: "DPoP", ExpiresAt: time.Now().Add(time.Hour), Resource: s.resource, Scopes: scopes}, nil
}

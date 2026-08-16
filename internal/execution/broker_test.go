package execution

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/realmroot/cli/internal/catalog"
	restish "github.com/saltbo/restish/v2"
)

func TestNativeResourceToolReportsUnresolvedScopeAlternatives(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("WWW-Authenticate", `DPoP error="insufficient_scope", scope="contents:write workflows:write"`)
		response.WriteHeader(http.StatusForbidden)
	}))
	defer upstream.Close()
	broker, err := NewBroker(
		upstream.URL,
		"rrcs_reference",
		[]string{"contents:read"},
		&fakeSource{resource: upstream.URL},
		func(string, [][]string) ([]string, error) { return nil, os.ErrNotExist },
		upstream.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	base, err := broker.StartTCP(func(request *http.Request) (string, error) { return request.URL.RequestURI(), nil }, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Get(base + "/repository")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()

	alternatives := broker.UnresolvedScopeAlternatives()
	if len(alternatives) != 1 || strings.Join(alternatives[0], " ") != "contents:write workflows:write" {
		t.Fatalf("alternatives = %#v", alternatives)
	}
}

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
	broker, err := NewBroker(upstream.URL, "rrcs_reference", []string{"resource:read"}, source, nil, upstream.Client())
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

func TestNativeResourceToolRetriesAnInsufficientScopeChallengeWithExistingAuthority(t *testing.T) {
	t.Parallel()
	var requests int
	var bodies []string
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		body, _ := io.ReadAll(request.Body)
		bodies = append(bodies, string(body))
		if requests == 1 {
			response.Header().Set("WWW-Authenticate", `DPoP error="insufficient_scope", scope="resource:write"`)
			response.WriteHeader(http.StatusForbidden)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	source := &fakeSource{resource: upstream.URL}
	broker, err := NewBroker(
		upstream.URL,
		"rrcs_reference",
		[]string{"resource:read"},
		source,
		func(reference string, alternatives [][]string) ([]string, error) {
			if reference != "rrcs_reference" || len(alternatives) != 1 || strings.Join(alternatives[0], " ") != "resource:write" {
				t.Fatalf("resolution = %q %#v", reference, alternatives)
			}
			return []string{"resource:write"}, nil
		},
		upstream.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	base, err := broker.StartTCP(func(request *http.Request) (string, error) { return request.URL.RequestURI(), nil }, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Post(base+"/items", "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent || requests != 2 {
		t.Fatalf("status = %d, requests = %d", response.StatusCode, requests)
	}
	if len(bodies) != 2 || bodies[0] != "payload" || bodies[1] != "payload" {
		t.Fatalf("bodies = %#v", bodies)
	}
	if source.scopes != "resource:write" {
		t.Fatalf("issued scopes = %q", source.scopes)
	}
}

func TestCloudflareBrokerUsesCapturedAssetUploadCredentialOnlyForItsSession(t *testing.T) {
	t.Parallel()
	var adapterRequests, providerRequests int
	adapter := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		adapterRequests++
		if request.Header.Get("Authorization") != "DPoP resource-token" || request.Header.Get("DPoP") == "" {
			t.Fatalf("adapter request did not use the Agent credential")
		}
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Content-Encoding", "gzip")
		compressed := gzip.NewWriter(response)
		_, _ = compressed.Write([]byte(`{"result":{"jwt":"asset-session"}}`))
		_ = compressed.Close()
	}))
	defer adapter.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		providerRequests++
		if request.URL.Path != "/client/v4/accounts/account-1/workers/assets/upload" || request.URL.RawQuery != "base64=true" {
			t.Fatalf("provider target = %s", request.URL.String())
		}
		if request.Header.Get("Authorization") != "Bearer asset-session" {
			t.Fatalf("provider auth = %q", request.Header.Get("Authorization"))
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer provider.Close()
	source := &fakeSource{resource: adapter.URL}
	broker, err := NewBroker(adapter.URL, "rrcs_reference", []string{"workers-scripts.write"}, source, nil, adapter.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	base, err := broker.StartCloudflareAPIBase(provider.URL + "/client/v4")
	if err != nil {
		t.Fatal(err)
	}

	sessionRequest, _ := http.NewRequest(http.MethodPost, base+"/client/v4/accounts/account-1/workers/scripts/wallet/assets-upload-session", nil)
	sessionRequest.Header.Set("Authorization", "Bearer "+broker.SessionToken())
	sessionResponse, err := http.DefaultClient.Do(sessionRequest)
	if err != nil {
		t.Fatal(err)
	}
	sessionResponse.Body.Close()

	uploadRequest, _ := http.NewRequest(http.MethodPost, base+"/client/v4/accounts/account-1/workers/assets/upload?base64=true", strings.NewReader("asset"))
	uploadRequest.Header.Set("Authorization", "Bearer asset-session")
	uploadResponse, err := http.DefaultClient.Do(uploadRequest)
	if err != nil {
		t.Fatal(err)
	}
	uploadResponse.Body.Close()
	if uploadResponse.StatusCode != http.StatusNoContent || adapterRequests != 1 || providerRequests != 1 {
		t.Fatalf("status = %d, adapter requests = %d, provider requests = %d", uploadResponse.StatusCode, adapterRequests, providerRequests)
	}

	wrongPath, _ := http.NewRequest(http.MethodGet, base+"/client/v4/accounts/account-1/workers/scripts", nil)
	wrongPath.Header.Set("Authorization", "Bearer asset-session")
	wrongResponse, err := http.DefaultClient.Do(wrongPath)
	if err != nil {
		t.Fatal(err)
	}
	wrongResponse.Body.Close()
	if wrongResponse.StatusCode != http.StatusUnauthorized || adapterRequests != 1 || providerRequests != 1 {
		t.Fatalf("wrong-path status = %d, adapter requests = %d, provider requests = %d", wrongResponse.StatusCode, adapterRequests, providerRequests)
	}
}

func TestNativeResourceToolRejectsUnadvertisedExecutables(t *testing.T) {
	t.Parallel()
	_, _, err := selectIntegration([]catalog.ToolIntegration{{ID: "git", Executables: []string{"git"}, Protocol: "git-smart-http"}}, []string{"curl"})
	if err == nil || !strings.Contains(err.Error(), "does not advertise") {
		t.Fatalf("error = %v", err)
	}
}

func TestNativeCommandsDescribeWrappedWranglerExecutables(t *testing.T) {
	t.Parallel()
	commands := NativeCommands([]catalog.ToolIntegration{
		{ID: "git", Executables: []string{"git"}, Protocol: "git-smart-http"},
		{ID: "wrangler", Executables: []string{"wrangler", "npx", "pnpm"}, Protocol: "cloudflare-api-base"},
	})
	if got := strings.Join(commands, ", "); got != "git, wrangler, npx wrangler, pnpm wrangler" {
		t.Fatalf("commands = %q", got)
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

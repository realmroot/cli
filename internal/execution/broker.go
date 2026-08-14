package execution

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	restish "github.com/saltbo/restish/v2"
)

type credentialSource interface {
	Describe(context.Context, string, string, string, string, []string) (restish.DPoPCredentialDescription, error)
	Issue(context.Context, string, string, string, string, string, []string) (restish.DPoPIssuedCredential, error)
}

type scopeResolver func(reference string, alternatives [][]string) ([]string, error)

type Broker struct {
	resource           string
	reference          string
	scopes             []string
	auth               restish.AuthHandler
	store              *memoryTokenStore
	client             *http.Client
	server             *http.Server
	listener           net.Listener
	temporaryDirectory string
	sessionToken       string
	resolveScopes      scopeResolver
	unresolvedScopes   [][]string
	scopeMu            sync.RWMutex
	cloudflareSession  cloudflareAssetSession
	cloudflareMu       sync.RWMutex
}

type cloudflareAssetSession struct {
	account string
	token   string
}

func NewBroker(resource, reference string, scopes []string, source credentialSource, resolveScopes scopeResolver, client *http.Client) (*Broker, error) {
	if _, err := url.ParseRequestURI(resource); err != nil {
		return nil, fmt.Errorf("invalid Resource Server URL: %w", err)
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Minute}
	}
	return &Broker{
		resource: strings.TrimSuffix(resource, "/"), reference: reference, scopes: append([]string(nil), scopes...),
		auth: restish.NewDPoPAuthHandler(source), store: newMemoryTokenStore(), client: client,
		sessionToken: hex.EncodeToString(token), resolveScopes: resolveScopes,
	}, nil
}

func (b *Broker) StartTCP(mapPath func(*http.Request) (string, error), authorize func(*http.Request) bool) (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	b.listener = listener
	b.serve(http.HandlerFunc(b.handler(mapPath, authorize)))
	return "http://" + listener.Addr().String(), nil
}

func (b *Broker) StartCloudflareAPIBase(providerBase string) (string, error) {
	provider, err := url.ParseRequestURI(providerBase)
	if err != nil || provider.Scheme == "" || provider.Host == "" || provider.RawQuery != "" || provider.Fragment != "" {
		return "", errors.New("invalid Cloudflare provider API base URL")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	b.listener = listener
	b.serve(http.HandlerFunc(b.cloudflareHandler(strings.TrimSuffix(providerBase, "/"))))
	return "http://" + listener.Addr().String(), nil
}

func (b *Broker) StartGitHubSocket() (string, error) {
	directory, err := os.MkdirTemp("", "realmroot-exec-gh-*")
	if err != nil {
		return "", err
	}
	b.temporaryDirectory = directory
	if err := os.Chmod(directory, 0o700); err != nil {
		b.Close()
		return "", err
	}
	socket := filepath.Join(directory, "api.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		b.Close()
		return "", err
	}
	b.listener = listener
	b.serve(http.HandlerFunc(b.handler(func(request *http.Request) (string, error) {
		return request.URL.RequestURI(), nil
	}, func(request *http.Request) bool {
		value := strings.TrimPrefix(request.Header.Get("Authorization"), "token ")
		if value == request.Header.Get("Authorization") {
			value = strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
		}
		return value == b.sessionToken
	})))
	return socket, nil
}

func (b *Broker) SessionToken() string { return b.sessionToken }

func (b *Broker) Close() error {
	var result error
	if b.server != nil {
		result = b.server.Close()
	}
	if b.listener != nil {
		_ = b.listener.Close()
	}
	if b.temporaryDirectory != "" {
		_ = os.RemoveAll(b.temporaryDirectory)
	}
	return result
}

func (b *Broker) serve(handler http.Handler, listeners ...net.Listener) {
	b.server = &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	listener := b.listener
	if len(listeners) == 1 {
		listener = listeners[0]
	}
	go func() { _ = b.server.Serve(listener) }()
}

func (b *Broker) handler(mapPath func(*http.Request) (string, error), authorize func(*http.Request) bool) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		if !authorize(request) {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		path, err := mapPath(request)
		if err != nil {
			http.Error(response, err.Error(), http.StatusBadRequest)
			return
		}
		target, err := url.Parse(b.resource + path)
		if err != nil {
			http.Error(response, "invalid upstream target", http.StatusBadGateway)
			return
		}
		result, err := b.realmrootRequest(request, target.String())
		if err != nil {
			http.Error(response, err.Error(), http.StatusBadGateway)
			return
		}
		defer result.Body.Close()
		writeResponse(response, result)
	}
}

func (b *Broker) cloudflareHandler(providerBase string) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		if !strings.HasPrefix(request.URL.Path, "/client/v4/") {
			http.Error(response, "Wrangler request is outside Cloudflare API v4", http.StatusBadRequest)
			return
		}
		path := strings.TrimPrefix(request.URL.RequestURI(), "/client/v4")
		authorization := request.Header.Get("Authorization")
		if authorization == "Bearer "+b.sessionToken {
			result, err := b.realmrootRequest(request, b.resource+path)
			if err != nil {
				http.Error(response, err.Error(), http.StatusBadGateway)
				return
			}
			defer result.Body.Close()
			account, capturesAssetSession := cloudflareAssetSessionAccount(request.URL.Path)
			if capturesAssetSession && result.StatusCode >= 200 && result.StatusCode < 300 {
				body, err := io.ReadAll(io.LimitReader(result.Body, 1<<20+1))
				if err != nil || len(body) > 1<<20 {
					http.Error(response, "invalid Cloudflare asset upload session response", http.StatusBadGateway)
					return
				}
				var document struct {
					Result struct {
						JWT string `json:"jwt"`
					} `json:"result"`
				}
				if json.Unmarshal(body, &document) != nil || document.Result.JWT == "" {
					http.Error(response, "invalid Cloudflare asset upload session response", http.StatusBadGateway)
					return
				}
				b.cloudflareMu.Lock()
				b.cloudflareSession = cloudflareAssetSession{account: account, token: document.Result.JWT}
				b.cloudflareMu.Unlock()
				writeResponseBytes(response, result, body)
				return
			}
			writeResponse(response, result)
			return
		}

		account, isAssetUpload := cloudflareAssetUploadAccount(request.URL.Path)
		b.cloudflareMu.RLock()
		session := b.cloudflareSession
		b.cloudflareMu.RUnlock()
		if !isAssetUpload || account != session.account || authorization != "Bearer "+session.token {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		result, err := b.providerRequest(request, providerBase+path, authorization)
		if err != nil {
			http.Error(response, err.Error(), http.StatusBadGateway)
			return
		}
		defer result.Body.Close()
		writeResponse(response, result)
	}
}

func (b *Broker) realmrootRequest(request *http.Request, target string) (*http.Response, error) {
	body, cleanup, err := replayableRequestBody(request)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	result, err := b.authenticatedRequest(request, target, b.scopes, body)
	if err != nil || result.StatusCode != http.StatusForbidden || b.resolveScopes == nil {
		return result, err
	}
	alternatives := insufficientScopeAlternatives(result.Header)
	if len(alternatives) == 0 {
		return result, nil
	}
	scopes, err := b.resolveScopes(b.reference, alternatives)
	if errors.Is(err, os.ErrNotExist) || sameStringSet(scopes, b.scopes) {
		b.scopeMu.Lock()
		b.unresolvedScopes = cloneScopeAlternatives(alternatives)
		b.scopeMu.Unlock()
		return result, nil
	}
	if err != nil {
		result.Body.Close()
		return nil, err
	}
	result.Body.Close()
	return b.authenticatedRequest(request, target, scopes, body)
}

func (b *Broker) UnresolvedScopeAlternatives() [][]string {
	b.scopeMu.RLock()
	defer b.scopeMu.RUnlock()
	return cloneScopeAlternatives(b.unresolvedScopes)
}

func cloneScopeAlternatives(values [][]string) [][]string {
	result := make([][]string, len(values))
	for index, value := range values {
		result[index] = append([]string(nil), value...)
	}
	return result
}

func (b *Broker) authenticatedRequest(request *http.Request, target string, scopes []string, body func() (io.ReadCloser, error)) (*http.Response, error) {
	content, err := body()
	if err != nil {
		return nil, err
	}
	upstream, err := http.NewRequestWithContext(request.Context(), request.Method, target, content)
	if err != nil {
		content.Close()
		return nil, errors.New("invalid upstream request")
	}
	upstream.ContentLength = request.ContentLength
	upstream.Header = forwardedHeaders(request.Header)
	if err := b.auth.Authenticate(request.Context(), upstream, restish.AuthContext{
		APIName: "exec", ProfileName: "default", BaseURL: b.resource, CacheKey: "exec:" + b.reference + ":" + strings.Join(scopes, " "),
		Params:     map[string]string{"source": "realmroot", "reference": b.reference, "scopes": strings.Join(scopes, " ")},
		TokenStore: b.store, HTTPClient: b.client, Stderr: io.Discard,
	}); err != nil {
		content.Close()
		return nil, err
	}
	return b.client.Do(upstream)
}

func replayableRequestBody(request *http.Request) (func() (io.ReadCloser, error), func(), error) {
	if request.Body == nil || request.Body == http.NoBody {
		return func() (io.ReadCloser, error) { return http.NoBody, nil }, func() {}, nil
	}
	file, err := os.CreateTemp("", "realmroot-exec-request-*")
	if err != nil {
		return nil, nil, err
	}
	path := file.Name()
	cleanup := func() { _ = os.Remove(path) }
	if _, err := io.Copy(file, request.Body); err != nil {
		file.Close()
		cleanup()
		return nil, nil, err
	}
	if err := request.Body.Close(); err != nil {
		file.Close()
		cleanup()
		return nil, nil, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return nil, nil, err
	}
	return func() (io.ReadCloser, error) { return os.Open(path) }, cleanup, nil
}

func insufficientScopeAlternatives(headers http.Header) [][]string {
	var alternatives [][]string
	for _, header := range headers.Values("WWW-Authenticate") {
		remaining := header
		for {
			start := strings.Index(strings.ToLower(remaining), "dpop ")
			if start < 0 {
				break
			}
			challenge := remaining[start+len("dpop "):]
			next := strings.Index(strings.ToLower(challenge), ", dpop ")
			if next >= 0 {
				remaining = challenge[next+2:]
				challenge = challenge[:next]
			} else {
				remaining = ""
			}
			if authenticateParameter(challenge, "error") == "insufficient_scope" {
				if scopes := strings.Fields(authenticateParameter(challenge, "scope")); len(scopes) > 0 {
					alternatives = append(alternatives, scopes)
				}
			}
			if remaining == "" {
				break
			}
		}
	}
	return alternatives
}

func authenticateParameter(challenge, expected string) string {
	for _, parameter := range strings.Split(challenge, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
		if ok && strings.EqualFold(name, expected) {
			return strings.Trim(strings.TrimSpace(value), `"`)
		}
	}
	return ""
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	seen := make(map[string]bool, len(left))
	for _, value := range left {
		seen[value] = true
	}
	for _, value := range right {
		if !seen[value] {
			return false
		}
	}
	return true
}

func (b *Broker) providerRequest(request *http.Request, target, authorization string) (*http.Response, error) {
	upstream, err := http.NewRequestWithContext(request.Context(), request.Method, target, request.Body)
	if err != nil {
		return nil, errors.New("invalid provider request")
	}
	upstream.Header = forwardedHeaders(request.Header)
	upstream.Header.Set("Authorization", authorization)
	return b.client.Do(upstream)
}

func cloudflareAssetSessionAccount(path string) (string, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 8 && parts[0] == "client" && parts[1] == "v4" && parts[2] == "accounts" && parts[4] == "workers" && parts[5] == "scripts" && parts[7] == "assets-upload-session" {
		return parts[3], parts[3] != "" && parts[6] != ""
	}
	return "", false
}

func cloudflareAssetUploadAccount(path string) (string, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if (len(parts) == 7 || len(parts) == 8) && parts[0] == "client" && parts[1] == "v4" && parts[2] == "accounts" && parts[4] == "workers" && parts[5] == "assets" && parts[6] == "upload" {
		return parts[3], parts[3] != "" && (len(parts) == 7 || parts[7] != "")
	}
	return "", false
}

func writeResponse(response http.ResponseWriter, result *http.Response) {
	copyResponseHeaders(response, result)
	response.WriteHeader(result.StatusCode)
	_, _ = io.Copy(response, result.Body)
}

func writeResponseBytes(response http.ResponseWriter, result *http.Response, body []byte) {
	copyResponseHeaders(response, result)
	response.WriteHeader(result.StatusCode)
	_, _ = response.Write(body)
}

func copyResponseHeaders(response http.ResponseWriter, result *http.Response) {
	for name, values := range result.Header {
		for _, value := range values {
			response.Header().Add(name, value)
		}
	}
}

func forwardedHeaders(source http.Header) http.Header {
	result := source.Clone()
	for _, name := range []string{"Authorization", "Dpop", "Host", "Connection", "Proxy-Connection", "Keep-Alive", "Transfer-Encoding", "Upgrade", "Cookie", "Accept-Encoding"} {
		result.Del(name)
	}
	return result
}

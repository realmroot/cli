package execution

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	restish "github.com/saltbo/restish/v2"
)

type credentialSource interface {
	Describe(context.Context, string, string, string, string, []string) (restish.DPoPCredentialDescription, error)
	Issue(context.Context, string, string, string, string, string, []string) (restish.DPoPIssuedCredential, error)
}

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
}

func NewBroker(resource, reference string, scopes []string, source credentialSource, client *http.Client) (*Broker, error) {
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
		sessionToken: hex.EncodeToString(token),
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
		upstream, err := http.NewRequestWithContext(request.Context(), request.Method, target.String(), request.Body)
		if err != nil {
			http.Error(response, "invalid upstream request", http.StatusBadGateway)
			return
		}
		upstream.Header = forwardedHeaders(request.Header)
		err = b.auth.Authenticate(request.Context(), upstream, restish.AuthContext{
			APIName: "exec", ProfileName: "default", BaseURL: b.resource, CacheKey: "exec:" + b.reference,
			Params:     map[string]string{"source": "realmroot", "reference": b.reference, "scopes": strings.Join(b.scopes, " ")},
			TokenStore: b.store, HTTPClient: b.client, Stderr: io.Discard,
		})
		if err != nil {
			http.Error(response, err.Error(), http.StatusBadGateway)
			return
		}
		result, err := b.client.Do(upstream)
		if err != nil {
			http.Error(response, err.Error(), http.StatusBadGateway)
			return
		}
		defer result.Body.Close()
		for name, values := range result.Header {
			for _, value := range values {
				response.Header().Add(name, value)
			}
		}
		response.WriteHeader(result.StatusCode)
		_, _ = io.Copy(response, result.Body)
	}
}

func forwardedHeaders(source http.Header) http.Header {
	result := source.Clone()
	for _, name := range []string{"Authorization", "Dpop", "Host", "Connection", "Proxy-Connection", "Keep-Alive", "Transfer-Encoding", "Upgrade", "Cookie"} {
		result.Del(name)
	}
	return result
}

package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileStateStoreProtectsAndValidatesAgentKeys(t *testing.T) {
	store := &fileStateStore{root: t.TempDir()}
	target := agentTarget{
		API:     "realmroot-local",
		Profile: "default",
		Runtime: "codex",
		Origin:  "https://auth.example.com",
		Issuer:  "https://auth.example.com/api/auth",
	}
	_, agentPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state := agentState{
		Version:                  agentStateVersion,
		Origin:                   target.Origin,
		Name:                     "Build Agent",
		AgentID:                  "agent-123",
		HostID:                   "host-123",
		AgentKeyID:               "agent-key",
		AgentPrivateKey:          encodePrivateKey(agentPrivateKey),
		EnrollmentIdempotencyKey: "enroll_test",
	}

	path, err := store.Create(target, state)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state permissions = %o", info.Mode().Perm())
	}
	alias := target
	alias.API = "realmroot-alias"
	alias.Profile = "work"
	alias.Origin = "https://realmroot-gateway.example.com"
	loaded, err := store.Load(alias)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AgentID != state.AgentID || loaded.HostID != state.HostID {
		t.Fatalf("loaded unexpected state: %#v", loaded)
	}
	if loaded.Origin != alias.Origin {
		t.Fatalf("loaded origin = %q", loaded.Origin)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(target); err == nil {
		t.Fatal("expected permissive state file to be rejected")
	}
}

func TestFileStateStoreSharesProtectedHostByIssuer(t *testing.T) {
	store := &fileStateStore{root: t.TempDir()}
	target := agentTarget{Runtime: "codex", Issuer: "https://auth.example.com/api/auth"}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path, err := store.CreateHost(target, hostState{
		HostID: "host-123", HostKeyID: "host-key", HostPrivateKey: encodePrivateKey(privateKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("Host state permissions = %o", info.Mode().Perm())
	}
	otherRuntime := target
	otherRuntime.Runtime = "claude"
	loaded, err := store.LoadHost(otherRuntime)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.HostID != "host-123" || loaded.HostPrivateKey != encodePrivateKey(privateKey) {
		t.Fatalf("loaded unexpected Host state: %#v", loaded)
	}
	otherIssuer := target
	otherIssuer.Issuer = "https://staging-auth.example.com/api/auth"
	if _, err := store.LoadHost(otherIssuer); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("different issuer reused Host state: %v", err)
	}
}

func TestFileStateStoreRejectsUnsupportedCredentialCacheVersion(t *testing.T) {
	store := &fileStateStore{root: t.TempDir()}
	target := agentTarget{
		API:     "realmroot-local",
		Profile: "default",
		Runtime: "codex",
		Origin:  "https://auth.example.com",
		Issuer:  "https://auth.example.com/api/auth",
	}
	_, agentPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	legacy := map[string]any{
		"version": 6, "origin": target.Origin, "issuer": target.Issuer, "runtime": target.Runtime,
		"name": "Build Agent", "agent_id": "agent-123", "host_id": "host-123",
		"agent_key_id": "agent-key", "host_key_id": "host-key",
		"agent_private_key": encodePrivateKey(agentPrivateKey), "host_private_key": encodePrivateKey(hostPrivateKey),
		"credential_cache": map[string]any{"credential-old": map[string]any{
			"resource_id": "resource-1", "resource_url": "https://api.example.com",
		}},
	}
	legacyPath := store.path(target)
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Load(target); err == nil || !strings.Contains(err.Error(), "unsupported Agent state version") {
		t.Fatalf("legacy Agent state was not rejected: %v", err)
	}
}

func TestFileStateStoreRejectsLegacyProtocolCredential(t *testing.T) {
	store := &fileStateStore{root: t.TempDir()}
	target := agentTarget{
		API:     "realmroot-local",
		Profile: "default",
		Runtime: "codex",
		Origin:  "https://auth.example.com",
		Issuer:  "https://auth.example.com/api/auth",
	}
	_, agentPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	protocolPrivateKey, err := newDPoPPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(time.Minute)
	legacy := map[string]any{
		"version": 8, "origin": target.Origin, "issuer": target.Issuer, "runtime": target.Runtime,
		"name": "Build Agent", "agent_id": "agent-123", "host_id": "host-123",
		"agent_key_id": "agent-key", "host_key_id": "host-key",
		"agent_private_key": encodePrivateKey(agentPrivateKey), "host_private_key": encodePrivateKey(hostPrivateKey),
		"platform_credential": map[string]any{
			"resource_href": "https://auth.example.com/api", "resource_indicator": "https://auth.example.com/api",
			"credential_endpoint": "https://auth.example.com/api/auth/oauth2/token",
			"proof_target":        "https://auth.example.com/api/auth/oauth2/token",
			"private_key":         protocolPrivateKey,
			"access_token":        "protocol-token",
			"expires_at":          expiresAt,
		},
	}
	path := store.path(target)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Load(target); err == nil || !strings.Contains(err.Error(), "unsupported Agent state version") {
		t.Fatalf("legacy Agent state was not rejected: %v", err)
	}
}

func TestFileStateStoreRejectsPreviousStateVersionsWithoutMigration(t *testing.T) {
	store := &fileStateStore{root: t.TempDir()}
	target := agentTarget{
		Runtime: defaultAgentRuntime, Origin: "https://auth.example.com", Issuer: "https://auth.example.com/api/auth",
	}
	state := newCredentialState(t, testCredential(t, "", time.Time{})).state
	state.Version = 16
	path := store.path(target)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Load(target); err == nil || !strings.Contains(err.Error(), "unsupported Agent state version 16") {
		t.Fatalf("previous Agent state was not rejected: %v", err)
	}
}

func TestFileStateStoreRejectsUnknownCurrentStateFields(t *testing.T) {
	store := &fileStateStore{root: t.TempDir()}
	target := agentTarget{
		Runtime: defaultAgentRuntime, Origin: "https://auth.example.com", Issuer: "https://auth.example.com/api/auth",
	}
	state := newCredentialState(t, testCredential(t, "", time.Time{})).state
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	document["platform_credential"] = map[string]any{"access_token": "obsolete"}
	encoded, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := store.path(target)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Load(target); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown Agent state field was not rejected: %v", err)
	}
}

func TestFileStateStoreFindsCredentialOfferByOpaqueReference(t *testing.T) {
	store := &fileStateStore{root: t.TempDir()}
	target := agentTarget{
		API:     "realmroot",
		Profile: "local",
		Runtime: "codex",
		Origin:  "https://auth.example.com",
		Issuer:  "https://auth.example.com/api/auth",
	}
	_, agentPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credential := testCredential(t, "", time.Time{})
	state := agentState{
		Version:                  agentStateVersion,
		Origin:                   target.Origin,
		Issuer:                   target.Issuer,
		Runtime:                  target.Runtime,
		Name:                     "Build Agent",
		AgentID:                  "agent-123",
		HostID:                   "host-123",
		AgentKeyID:               "agent-key",
		AgentPrivateKey:          encodePrivateKey(agentPrivateKey),
		EnrollmentIdempotencyKey: "enroll_test",
		CredentialSources: map[string]credentialSource{
			testCredentialSourceReference: {
				ResourceIndicator: credential.ResourceIndicator, AuthorizationDetails: credential.AuthorizationDetails,
				Credential: &credential,
			},
		},
	}
	path := store.path(target)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	reference, err := store.FindCredential(testCredentialSourceReference, target.Runtime, credential.Scopes)
	if err != nil {
		t.Fatal(err)
	}
	if reference.credential.ResourceIndicator != credential.ResourceIndicator ||
		!sameAuthorizationDetails(reference.credential.AuthorizationDetails, credential.AuthorizationDetails) {
		t.Fatalf("credential = %#v", reference.credential)
	}
}

func TestFileStateStoreUpdatesTheCurrentCredential(t *testing.T) {
	store := &fileStateStore{root: t.TempDir()}
	target := agentTarget{
		Runtime: defaultAgentRuntime, Origin: "https://auth.example.com", Issuer: "https://auth.example.com/api/auth",
	}
	credential := testCredential(t, "", time.Time{})
	state := newCredentialState(t, credential).state
	path := store.path(target)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	reference, err := store.FindCredential(testCredentialSourceReference, target.Runtime, credential.Scopes)
	if err != nil {
		t.Fatal(err)
	}
	latest, err := store.Load(target)
	if err != nil {
		t.Fatal(err)
	}
	latest.Name = "Updated concurrently"
	if err := store.Update(target, latest); err != nil {
		t.Fatal(err)
	}
	updated := credential
	updated.Scopes = []string{"files:read", "files:write"}
	if err := store.UpdateCredential(reference, updated); err != nil {
		t.Fatal(err)
	}

	source, err := store.FindCredentialSource(testCredentialSourceReference, target.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	if source.source.ResourceIndicator != credential.ResourceIndicator ||
		!sameAuthorizationDetails(source.source.AuthorizationDetails, credential.AuthorizationDetails) ||
		source.source.Credential == nil || !sameStringSet(source.source.Credential.Scopes, updated.Scopes) {
		t.Fatalf("updated source = %#v", source.source)
	}
	if source.state.Name != "Updated concurrently" {
		t.Fatalf("credential update overwrote newer Agent state: %#v", source.state)
	}
	if _, err := store.Load(target); err != nil {
		t.Fatalf("updated credential source is invalid: %v", err)
	}
}

func TestFileStateStoreReturnsTheOneCurrentCredentialThatCoversRequestedScopes(t *testing.T) {
	store := &fileStateStore{root: t.TempDir()}
	target := agentTarget{
		Runtime: defaultAgentRuntime, Origin: "https://auth.example.com", Issuer: "https://auth.example.com/api/auth",
	}
	broad := testCredential(t, "", time.Time{})
	broad.Scopes = []string{"files:read", "files:write"}
	broad.CredentialEndpoint = "https://auth.example.com/api/access-requests/broad/credentials"
	state := newCredentialState(t, broad).state
	source := state.CredentialSources[testCredentialSourceReference]
	source.Credential = &broad
	state.CredentialSources[testCredentialSourceReference] = source
	path := store.path(target)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	reference, err := store.FindCredential(
		testCredentialSourceReference,
		target.Runtime,
		[]string{"files:read"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if reference.credential.CredentialEndpoint != broad.CredentialEndpoint || !sameStringSet(reference.credential.Scopes, broad.Scopes) {
		t.Fatalf("current credential = %#v", reference.credential)
	}
}

func TestAgentStateRejectsResourceURLAsCredentialSourceReference(t *testing.T) {
	credential := testCredential(t, "", time.Time{})
	state := newCredentialState(t, credential).state
	state.CredentialSources = map[string]credentialSource{
		credential.ResourceIndicator: {
			ResourceIndicator: credential.ResourceIndicator, AuthorizationDetails: credential.AuthorizationDetails,
			Credential: &credential,
		},
	}

	err := validateAgentStateCredentials(state)
	if err == nil || !strings.Contains(err.Error(), "invalid DPoP credential metadata") {
		t.Fatalf("error = %v", err)
	}
}

func TestFileStateStoreRejectsSymlink(t *testing.T) {
	store := &fileStateStore{root: t.TempDir()}
	target := agentTarget{
		API:     "api",
		Profile: "default",
		Runtime: "codex",
		Origin:  "https://auth.example.com",
		Issuer:  "https://auth.example.com/api/auth",
	}
	path := store.path(target)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(target); err == nil {
		t.Fatal("expected symlink state to be rejected")
	}
}

func TestFileStateStoreKeysIdentityByIssuerAndRuntime(t *testing.T) {
	t.Run("[spec: agent-identity/agent-runtime-identity-continuity]", func(t *testing.T) {
		store := &fileStateStore{root: t.TempDir()}
		first := agentTarget{
			API:     "realmroot-primary",
			Profile: "default",
			Runtime: "codex",
			Origin:  "https://auth.example.com",
			Issuer:  "https://auth.example.com/api/auth",
		}
		alias := first
		alias.API = "realmroot-alias"
		alias.Profile = "work"
		otherRuntime := first
		otherRuntime.Runtime = "claude"
		otherEnvironment := first
		otherEnvironment.Origin = "https://staging-auth.example.com"
		otherEnvironment.Issuer = "https://staging-auth.example.com/api/auth"

		if store.path(first) != store.path(alias) {
			t.Fatal("Restish API alias or profile changed the Agent identity path")
		}
		if store.path(first) == store.path(otherRuntime) {
			t.Fatal("different runtimes shared an Agent identity path")
		}
		if store.path(first) == store.path(otherEnvironment) {
			t.Fatal("different Realmroot issuers shared an Agent identity path")
		}
		if store.hostPath(first) != store.hostPath(otherRuntime) {
			t.Fatal("runtimes on one issuer did not share a Host state path")
		}
		if store.hostPath(first) == store.hostPath(otherEnvironment) {
			t.Fatal("different Realmroot issuers shared a Host state path")
		}
	})
}

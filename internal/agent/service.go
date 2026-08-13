package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	restish "github.com/saltbo/restish/v2"
)

const DefaultOrigin = "https://id.realmroot.dev"

var agentUsernamePattern = regexp.MustCompile(`^[a-z0-9_.-]{3,64}$`)

type Identity struct {
	ID       string `json:"id"`
	Issuer   string `json:"issuer"`
	Subject  string `json:"subject"`
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Runtime  string `json:"runtime"`
}

type ExecutionIdentity struct {
	Name  string
	Email string
}

type AccessOffer struct {
	AgentID              string
	Scopes               []string
	ResourceIndicator    string
	AuthorizationDetails []map[string]any
	Endpoint             string
	ProofAlgorithm       string
	ProofMethod          string
	ProofURI             string
}

type CredentialBinding struct {
	Reference string
	Scopes    []string
}

type AuthorizationContext struct {
	AuthorizationDetails []map[string]any `json:"authorizationDetails"`
	Scopes               []string         `json:"scopes"`
	Active               bool             `json:"active"`
}

var ErrAuthorizationContextAmbiguous = errors.New("multiple authorization contexts can satisfy the operation")

type resourceCredentialSource struct {
	reference string
	source    credentialSource
}

type Service struct {
	origin string
	client *http.Client
	states *fileStateStore
	opener browserOpener
}

func NewService(origin string, client *http.Client) (*Service, error) {
	origin = strings.TrimSuffix(strings.TrimSpace(origin), "/")
	parsed, err := validatedAbsoluteURL(origin)
	if err != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("Realmroot origin must be an HTTPS origin or loopback development origin")
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Service{origin: origin, client: client, states: newFileStateStore(), opener: systemBrowserOpener{}}, nil
}

func (s *Service) Origin() string { return s.origin }

func (s *Service) Runtime() (string, error) { return agentRuntime() }

func (s *Service) APIBaseURL() string { return s.origin + "/api" }

func (s *Service) HTTPClient() *http.Client { return s.client }

func (s *Service) OpenApproval(rawURL string) error { return s.opener.Open(rawURL) }

func (s *Service) Enroll(ctx context.Context, username, nickname string) (Identity, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if !agentUsernamePattern.MatchString(username) {
		return Identity{}, errors.New("Agent username must contain 3 to 64 letters, numbers, underscores, periods, or hyphens")
	}
	configuration, target, err := s.configurationAndTarget(ctx)
	if err != nil {
		return Identity{}, err
	}
	nickname = strings.TrimSpace(nickname)
	if nickname == "" {
		nickname = target.Runtime
	}
	state, err := ensureApprovedAgentRegistration(ctx, s.states, s.client, systemPromptWriter{}, target, configuration, nickname)
	if err != nil {
		return Identity{}, fmt.Errorf("enroll Agent: %w", err)
	}
	if state.Identity != nil && state.Identity.Username != "" && state.Identity.Username != username {
		return Identity{}, errors.New("Agent username is immutable")
	}
	if state.Identity == nil || state.Identity.Username == "" {
		assertion, err := signAgentJWT(state, configuration.Issuer, time.Now())
		if err != nil {
			return Identity{}, err
		}
		var enrollment enrollmentResponse
		if err := requestJSONHeaders(ctx, s.client, http.MethodPost, configuration.AgentEnrollmentEndpoint, map[string]string{
			"Authorization":   "Bearer " + assertion,
			"Idempotency-Key": state.EnrollmentIdempotencyKey,
		}, map[string]any{
			"kind": "new_identity", "username": username, "nickname": nickname, "runtime": state.Runtime,
		}, &enrollment); err != nil {
			return Identity{}, fmt.Errorf("create Agent enrollment: %w", err)
		}
		if enrollment.Kind != "new_identity" || enrollment.Status != "approved" {
			return Identity{}, fmt.Errorf("Agent enrollment returned %s/%s", enrollment.Kind, enrollment.Status)
		}
		if err := completeAgentEnrollment(ctx, s.states, s.client, target, state, configuration); err != nil {
			return Identity{}, fmt.Errorf("complete Agent enrollment: %w", err)
		}
		state, err = s.states.Load(target)
		if err != nil {
			return Identity{}, err
		}
	}
	return publicIdentity(state.Identity), nil
}

func (s *Service) WhoAmI(ctx context.Context) (Identity, error) {
	_, target, err := s.configurationAndTarget(ctx)
	if err != nil {
		return Identity{}, err
	}
	state, err := loadAgentRegistration(s.states, target)
	if err != nil {
		return Identity{}, err
	}
	if state.Identity == nil {
		return Identity{}, errors.New("Realmroot Agent enrollment is incomplete; run `realmroot agent enroll --username <username>`")
	}
	if state.Identity.Username == "" {
		return Identity{}, errors.New("Agent username is not assigned; run `realmroot agent enroll --username <username>`")
	}
	return publicIdentity(state.Identity), nil
}

func (s *Service) ExecutionIdentity(ctx context.Context) (ExecutionIdentity, error) {
	_, target, err := s.configurationAndTarget(ctx)
	if err != nil {
		return ExecutionIdentity{}, err
	}
	state, err := loadAgentRegistration(s.states, target)
	if err != nil {
		return ExecutionIdentity{}, err
	}
	if state.Identity == nil {
		return ExecutionIdentity{}, errors.New("Realmroot Agent enrollment is incomplete; run `realmroot agent enroll --username <username>`")
	}
	if state.Identity.Username == "" {
		return ExecutionIdentity{}, errors.New("Agent username is not assigned; run `realmroot agent enroll --username <username>`")
	}
	return ExecutionIdentity{Name: state.Identity.Username, Email: state.Identity.Username + "@agents.realmroot.dev"}, nil
}

func publicIdentity(identity *stableIdentity) Identity {
	return Identity{
		ID: identity.ID, Issuer: identity.Issuer, Subject: identity.Subject, Username: identity.Username,
		Nickname: identity.Nickname, Runtime: identity.Runtime,
	}
}

func (s *Service) RequestEditor(scopes ...string) restishRequestEditor {
	required := append([]string(nil), scopes...)
	return func(ctx context.Context, request *http.Request) error {
		configuration, target, err := s.configurationAndTarget(ctx)
		if err != nil {
			return err
		}
		state, err := loadAgentRegistration(s.states, target)
		if err != nil {
			return err
		}
		state, credential, err := ensureProtocolCredential(ctx, s.states, s.client, target, state, configuration, required)
		if err != nil {
			return err
		}
		_ = state
		proof, err := signDPoPProof(credential.PrivateKey, request.Method, request.URL.String(), credential.AccessToken, time.Now())
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "DPoP "+credential.AccessToken)
		request.Header.Set("DPoP", proof)
		return nil
	}
}

func (s *Service) Authenticate(ctx context.Context, request *http.Request, scopes []string) error {
	return s.RequestEditor(scopes...)(ctx, request)
}

type restishRequestEditor func(context.Context, *http.Request) error

func (s *Service) AcceptAccessOffer(offer AccessOffer) (CredentialBinding, error) {
	resource := interactiveResponse{AgentID: offer.AgentID, Scopes: append([]string(nil), offer.Scopes...)}
	credential := credentialOffer{
		Type: "dpop", ResourceIndicator: offer.ResourceIndicator,
		AuthorizationDetails: append([]map[string]any(nil), offer.AuthorizationDetails...),
		Endpoint:             offer.Endpoint,
	}
	credential.Proof.Algorithm = offer.ProofAlgorithm
	credential.Proof.Method = offer.ProofMethod
	credential.Proof.URI = offer.ProofURI
	_, reference, err := acceptCredentialOfferWithReference(resource, credential, s.origin, s.states, newCredentialSourceReference)
	if err != nil {
		return CredentialBinding{}, err
	}
	if reference == "" {
		return CredentialBinding{}, errors.New("stored credential source reference is missing")
	}
	return CredentialBinding{Reference: reference, Scopes: append([]string(nil), offer.Scopes...)}, nil
}

type selectedContexts struct {
	Version int                         `json:"version"`
	Items   map[string][]map[string]any `json:"items"`
}

func (s *Service) SelectedContext(resourceIndicator string) ([]map[string]any, error) {
	data, err := os.ReadFile(filepath.Join(s.states.root, "contexts.json"))
	if err != nil {
		return nil, err
	}
	var contexts selectedContexts
	if err := json.Unmarshal(data, &contexts); err != nil {
		return nil, fmt.Errorf("decode selected Resource Server contexts: %w", err)
	}
	if contexts.Version != 1 {
		return nil, errors.New("selected Resource Server contexts have an unsupported version")
	}
	details := contexts.Items[resourceIndicator]
	if len(details) == 0 {
		return nil, os.ErrNotExist
	}
	return cloneAuthorizationDetails(details), nil
}

func (s *Service) StoreContext(resourceIndicator string, details []map[string]any) error {
	path := filepath.Join(s.states.root, "contexts.json")
	contexts := selectedContexts{Version: 1, Items: map[string][]map[string]any{}}
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &contexts); err != nil {
			return fmt.Errorf("decode selected Resource Server contexts: %w", err)
		}
		if contexts.Version != 1 {
			return errors.New("selected Resource Server contexts have an unsupported version")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if contexts.Items == nil {
		contexts.Items = make(map[string][]map[string]any)
	}
	if len(details) == 0 {
		delete(contexts.Items, resourceIndicator)
	} else {
		contexts.Items[resourceIndicator] = cloneAuthorizationDetails(details)
	}
	data, err := json.MarshalIndent(contexts, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".contexts-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func (s *Service) ClearContext(resourceIndicator string) error {
	return s.StoreContext(resourceIndicator, nil)
}

func (s *Service) BindingForResource(resourceIndicator string) (CredentialBinding, error) {
	sources, err := s.credentialSourcesForResource(resourceIndicator)
	if err != nil {
		return CredentialBinding{}, err
	}
	active, activeErr := s.activeBinding(resourceIndicator)
	if activeErr != nil && !errors.Is(activeErr, os.ErrNotExist) {
		return CredentialBinding{}, activeErr
	}
	for _, source := range sources {
		if source.reference == active.Reference {
			return bindingForSource(source), nil
		}
	}
	if len(sources) == 0 {
		return CredentialBinding{}, os.ErrNotExist
	}
	if len(sources) > 1 {
		return CredentialBinding{}, fmt.Errorf("%w for Resource Server %q", ErrAuthorizationContextAmbiguous, resourceIndicator)
	}
	binding := bindingForSource(sources[0])
	if err := s.storeActiveBinding(resourceIndicator, binding); err != nil {
		return CredentialBinding{}, err
	}
	return binding, nil
}

func (s *Service) ActiveBindingForResource(resourceIndicator string) (CredentialBinding, error) {
	active, err := s.activeBinding(resourceIndicator)
	if err != nil {
		return CredentialBinding{}, err
	}
	sources, err := s.credentialSourcesForResource(resourceIndicator)
	if err != nil {
		return CredentialBinding{}, err
	}
	for _, source := range sources {
		if source.reference != active.Reference {
			continue
		}
		if len(active.Scopes) > 0 {
			offer, ok := leastPrivilegeOffer(source.source.Offers, [][]string{active.Scopes})
			if !ok {
				return CredentialBinding{}, os.ErrNotExist
			}
			return CredentialBinding{Reference: source.reference, Scopes: normalizedBindingScopes(offer.Scopes)}, nil
		}
		if len(source.source.Offers) == 1 {
			return CredentialBinding{
				Reference: source.reference,
				Scopes:    normalizedBindingScopes(source.source.Offers[0].Scopes),
			}, nil
		}
		return CredentialBinding{}, errors.New("active Resource Server authority does not identify one credential offer")
	}
	return CredentialBinding{}, os.ErrNotExist
}

func (s *Service) ExecutionBinding(resourceIndicator string, details []map[string]any) (CredentialBinding, error) {
	if len(details) > 0 {
		binding, _, err := s.BindingForAuthorizationContext(resourceIndicator, details)
		return binding, err
	}

	sources, err := s.credentialSourcesForResource(resourceIndicator)
	if err != nil {
		return CredentialBinding{}, err
	}
	active, activeErr := s.activeBinding(resourceIndicator)
	if activeErr != nil && !errors.Is(activeErr, os.ErrNotExist) {
		return CredentialBinding{}, activeErr
	}
	for _, source := range sources {
		if source.reference != active.Reference {
			continue
		}
		binding, ok := leastPrivilegeSourceBinding(source)
		if !ok {
			return CredentialBinding{}, os.ErrNotExist
		}
		return binding, nil
	}
	if len(sources) == 0 {
		return CredentialBinding{}, os.ErrNotExist
	}
	if len(sources) > 1 {
		return CredentialBinding{}, fmt.Errorf("%w for Resource Server %q", ErrAuthorizationContextAmbiguous, resourceIndicator)
	}
	binding, ok := leastPrivilegeSourceBinding(sources[0])
	if !ok {
		return CredentialBinding{}, os.ErrNotExist
	}
	if err := s.storeActiveBinding(resourceIndicator, binding); err != nil {
		return CredentialBinding{}, err
	}
	return binding, nil
}

func (s *Service) AuthorizationContexts(resourceIndicator string) ([]AuthorizationContext, error) {
	sources, err := s.credentialSourcesForResource(resourceIndicator)
	if err != nil {
		return nil, err
	}
	active, activeErr := s.activeBinding(resourceIndicator)
	if activeErr != nil && !errors.Is(activeErr, os.ErrNotExist) {
		return nil, activeErr
	}
	contexts := make([]AuthorizationContext, 0, len(sources))
	for _, source := range sources {
		contexts = append(contexts, AuthorizationContext{
			AuthorizationDetails: cloneAuthorizationDetails(source.source.AuthorizationDetails),
			Scopes:               bindingForSource(source).Scopes,
			Active:               source.reference == active.Reference,
		})
	}
	return contexts, nil
}

func (s *Service) SelectAuthorizationContext(resourceIndicator string, details []map[string]any) (AuthorizationContext, error) {
	binding, context, err := s.BindingForAuthorizationContext(resourceIndicator, details)
	if err != nil {
		return AuthorizationContext{}, err
	}
	if err := s.storeActiveBinding(resourceIndicator, binding); err != nil {
		return AuthorizationContext{}, err
	}
	context.Active = true
	return context, nil
}

func (s *Service) BindingForAuthorizationContext(resourceIndicator string, details []map[string]any) (CredentialBinding, AuthorizationContext, error) {
	sources, err := s.credentialSourcesForResource(resourceIndicator)
	if err != nil {
		return CredentialBinding{}, AuthorizationContext{}, err
	}
	for _, source := range sources {
		if !sameAuthorizationDetails(source.source.AuthorizationDetails, details) {
			continue
		}
		binding, ok := leastPrivilegeSourceBinding(source)
		if !ok {
			return CredentialBinding{}, AuthorizationContext{}, os.ErrNotExist
		}
		return binding, AuthorizationContext{
			AuthorizationDetails: cloneAuthorizationDetails(source.source.AuthorizationDetails),
			Scopes:               bindingForSource(source).Scopes,
		}, nil
	}
	return CredentialBinding{}, AuthorizationContext{}, os.ErrNotExist
}

func (s *Service) BindingForAuthorizationContextAllAuthority(resourceIndicator string, details []map[string]any) (CredentialBinding, error) {
	sources, err := s.credentialSourcesForResource(resourceIndicator)
	if err != nil {
		return CredentialBinding{}, err
	}
	for _, source := range sources {
		if sameAuthorizationDetails(source.source.AuthorizationDetails, details) {
			return bindingForSource(source), nil
		}
	}
	return CredentialBinding{}, os.ErrNotExist
}

func (s *Service) BindingForAuthorizationContextScopeAlternatives(resourceIndicator string, details []map[string]any, alternatives [][]string) (CredentialBinding, error) {
	sources, err := s.credentialSourcesForResource(resourceIndicator)
	if err != nil {
		return CredentialBinding{}, err
	}
	for _, source := range sources {
		if !sameAuthorizationDetails(source.source.AuthorizationDetails, details) {
			continue
		}
		offer, ok := leastPrivilegeOffer(source.source.Offers, alternatives)
		if !ok {
			return CredentialBinding{}, os.ErrNotExist
		}
		return CredentialBinding{Reference: source.reference, Scopes: normalizedBindingScopes(offer.Scopes)}, nil
	}
	return CredentialBinding{}, os.ErrNotExist
}

func (s *Service) BindingForReferenceScopeAlternatives(resourceIndicator, reference string, alternatives [][]string) (CredentialBinding, error) {
	sources, err := s.credentialSourcesForResource(resourceIndicator)
	if err != nil {
		return CredentialBinding{}, err
	}
	for _, source := range sources {
		if source.reference != reference {
			continue
		}
		offer, ok := leastPrivilegeOffer(source.source.Offers, alternatives)
		if !ok {
			return CredentialBinding{}, os.ErrNotExist
		}
		return CredentialBinding{Reference: reference, Scopes: normalizedBindingScopes(offer.Scopes)}, nil
	}
	return CredentialBinding{}, os.ErrNotExist
}

func (s *Service) BindingForScopeAlternatives(resourceIndicator string, alternatives [][]string) (CredentialBinding, error) {
	sources, err := s.credentialSourcesForResource(resourceIndicator)
	if err != nil {
		return CredentialBinding{}, err
	}
	candidates := make([]CredentialBinding, 0, len(sources))
	for _, source := range sources {
		offer, ok := leastPrivilegeOffer(source.source.Offers, alternatives)
		if ok {
			candidates = append(candidates, CredentialBinding{
				Reference: source.reference,
				Scopes:    normalizedBindingScopes(offer.Scopes),
			})
		}
	}
	if len(candidates) == 0 {
		return CredentialBinding{}, os.ErrNotExist
	}
	active, activeErr := s.activeBinding(resourceIndicator)
	if activeErr != nil && !errors.Is(activeErr, os.ErrNotExist) {
		return CredentialBinding{}, activeErr
	}
	for _, candidate := range candidates {
		if candidate.Reference == active.Reference {
			if !sameStringSet(candidate.Scopes, active.Scopes) {
				if err := s.storeActiveBinding(resourceIndicator, candidate); err != nil {
					return CredentialBinding{}, err
				}
			}
			return candidate, nil
		}
	}
	if len(candidates) > 1 {
		return CredentialBinding{}, fmt.Errorf("%w for Resource Server %q", ErrAuthorizationContextAmbiguous, resourceIndicator)
	}
	if err := s.storeActiveBinding(resourceIndicator, candidates[0]); err != nil {
		return CredentialBinding{}, err
	}
	return candidates[0], nil
}

func (s *Service) credentialSourcesForResource(resourceIndicator string) ([]resourceCredentialSource, error) {
	runtimeName, err := agentRuntime()
	if err != nil {
		return nil, err
	}
	sources := make([]resourceCredentialSource, 0)
	err = s.states.walkStates(func(_ string, state agentState) error {
		if state.Runtime != runtimeName || state.Origin != s.origin {
			return nil
		}
		for reference, source := range state.CredentialSources {
			if source.ResourceIndicator == resourceIndicator && len(source.Offers) > 0 {
				sources = append(sources, resourceCredentialSource{reference: reference, source: source})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(sources, func(left, right int) bool { return sources[left].reference < sources[right].reference })
	return sources, nil
}

func bindingForSource(source resourceCredentialSource) CredentialBinding {
	scopes := make([]string, 0)
	for _, offer := range source.source.Offers {
		scopes = append(scopes, offer.Scopes...)
	}
	return CredentialBinding{Reference: source.reference, Scopes: normalizedBindingScopes(scopes)}
}

func leastPrivilegeSourceBinding(source resourceCredentialSource) (CredentialBinding, bool) {
	if len(source.source.Offers) == 0 {
		return CredentialBinding{}, false
	}
	selected := normalizedBindingScopes(source.source.Offers[0].Scopes)
	for _, offer := range source.source.Offers[1:] {
		candidate := normalizedBindingScopes(offer.Scopes)
		if len(candidate) < len(selected) || (len(candidate) == len(selected) && strings.Join(candidate, "\x00") < strings.Join(selected, "\x00")) {
			selected = candidate
		}
	}
	return CredentialBinding{Reference: source.reference, Scopes: selected}, true
}

func cloneAuthorizationDetails(details []map[string]any) []map[string]any {
	cloned := make([]map[string]any, 0, len(details))
	for _, detail := range details {
		copy := make(map[string]any, len(detail))
		for name, value := range detail {
			copy[name] = value
		}
		cloned = append(cloned, copy)
	}
	return cloned
}

func leastPrivilegeOffer(offers []dpopCredential, alternatives [][]string) (dpopCredential, bool) {
	var selected *dpopCredential
	for index := range offers {
		for _, scopes := range alternatives {
			if len(scopes) == 0 || !scopesContain(offers[index].Scopes, scopes) {
				continue
			}
			if selected == nil || len(offers[index].Scopes) < len(selected.Scopes) {
				candidate := offers[index]
				selected = &candidate
			}
		}
	}
	if selected == nil {
		return dpopCredential{}, false
	}
	return *selected, true
}

func normalizedBindingScopes(scopes []string) []string {
	result := uniqueStrings(scopes)
	sort.Strings(result)
	return result
}

type activeBindings struct {
	Version int                                `json:"version"`
	Items   map[string]activeCredentialBinding `json:"items"`
}

type activeCredentialBinding struct {
	Reference string   `json:"reference"`
	Scopes    []string `json:"scopes"`
}

func (s *Service) activeBinding(resourceIndicator string) (CredentialBinding, error) {
	data, err := os.ReadFile(filepath.Join(s.states.root, "bindings.json"))
	if err != nil {
		return CredentialBinding{}, err
	}
	var bindings activeBindings
	if err := json.Unmarshal(data, &bindings); err == nil && bindings.Version == 2 {
		binding := bindings.Items[resourceIndicator]
		if binding.Reference == "" {
			return CredentialBinding{}, os.ErrNotExist
		}
		return CredentialBinding{Reference: binding.Reference, Scopes: append([]string(nil), binding.Scopes...)}, nil
	}
	var legacy struct {
		Version int               `json:"version"`
		Items   map[string]string `json:"items"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return CredentialBinding{}, fmt.Errorf("decode active credential bindings: %w", err)
	}
	if legacy.Version != 1 {
		return CredentialBinding{}, errors.New("active credential bindings have an unsupported version")
	}
	reference := legacy.Items[resourceIndicator]
	if reference == "" {
		return CredentialBinding{}, os.ErrNotExist
	}
	return CredentialBinding{Reference: reference}, nil
}

func (s *Service) storeActiveBinding(resourceIndicator string, binding CredentialBinding) error {
	path := filepath.Join(s.states.root, "bindings.json")
	bindings := activeBindings{Version: 2, Items: map[string]activeCredentialBinding{}}
	if data, err := os.ReadFile(path); err == nil {
		var stored struct {
			Version int `json:"version"`
		}
		if err := json.Unmarshal(data, &stored); err != nil {
			return fmt.Errorf("decode active credential bindings: %w", err)
		}
		if stored.Version == 2 {
			if err := json.Unmarshal(data, &bindings); err != nil {
				return fmt.Errorf("decode active credential bindings: %w", err)
			}
		} else if stored.Version == 1 {
			var legacy struct {
				Items map[string]string `json:"items"`
			}
			if err := json.Unmarshal(data, &legacy); err != nil {
				return fmt.Errorf("decode active credential bindings: %w", err)
			}
			for resource, reference := range legacy.Items {
				bindings.Items[resource] = activeCredentialBinding{Reference: reference}
			}
		} else {
			return errors.New("active credential bindings have an unsupported version")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	bindings.Version = 2
	if bindings.Items == nil {
		bindings.Items = make(map[string]activeCredentialBinding)
	}
	bindings.Items[resourceIndicator] = activeCredentialBinding{Reference: binding.Reference, Scopes: normalizedBindingScopes(binding.Scopes)}
	data, err := json.MarshalIndent(bindings, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".bindings-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func (s *Service) configurationAndTarget(ctx context.Context) (agentConfiguration, agentTarget, error) {
	configuration, err := resolveAgentConfiguration(ctx, s.client, configurationCache(s.states), s.origin)
	if err != nil {
		return agentConfiguration{}, agentTarget{}, err
	}
	runtimeName, err := agentRuntime()
	if err != nil {
		return agentConfiguration{}, agentTarget{}, err
	}
	return configuration, agentTarget{Runtime: runtimeName, Origin: s.origin, Issuer: configuration.AgentIdentityIssuer}, nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

type CredentialSource struct {
	service *Service
}

func (s *Service) CredentialSource() *CredentialSource { return &CredentialSource{service: s} }

func (source *CredentialSource) Describe(ctx context.Context, _, _, _, reference string, scopes []string) (restish.DPoPCredentialDescription, error) {
	output, err := handleCredentialSource(ctx, credentialSourceInput{Action: "describe", Reference: reference, Scopes: scopes}, source.service.states, source.service.client)
	if err != nil {
		return restish.DPoPCredentialDescription{}, err
	}
	return restish.DPoPCredentialDescription{
		ProofMethod: output.Description.ProofMethod,
		ProofURI:    output.Description.ProofURI,
		Resource:    output.Description.Resource,
		Scopes:      append([]string(nil), output.Description.Scopes...),
	}, nil
}

func (source *CredentialSource) Issue(ctx context.Context, _, _, _, reference, proof string, scopes []string) (restish.DPoPIssuedCredential, error) {
	output, err := handleCredentialSource(ctx, credentialSourceInput{Action: "issue", Reference: reference, Scopes: scopes, Proof: proof}, source.service.states, source.service.client)
	if err != nil {
		return restish.DPoPIssuedCredential{}, err
	}
	if output.Challenge != nil {
		return restish.DPoPIssuedCredential{}, &restish.DPoPNonceChallenge{Nonce: output.Challenge.Nonce}
	}
	if output.Credential == nil {
		return restish.DPoPIssuedCredential{}, errors.New("Realmroot credential source returned no credential")
	}
	return restish.DPoPIssuedCredential{
		AccessToken: output.Credential.AccessToken,
		TokenType:   output.Credential.TokenType,
		ExpiresAt:   output.Credential.ExpiresAt,
		Resource:    output.Credential.Resource,
		Scopes:      append([]string(nil), output.Credential.Scopes...),
		Nonce:       output.Credential.Nonce,
	}, nil
}

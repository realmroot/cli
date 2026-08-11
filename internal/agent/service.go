package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	restish "github.com/rest-sh/restish/v2"
)

const DefaultOrigin = "https://id.realmroot.dev"

type Identity struct {
	ID      string `json:"id"`
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
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

func (s *Service) APIBaseURL() string { return s.origin + "/api" }

func (s *Service) OpenApproval(rawURL string) error { return s.opener.Open(rawURL) }

func (s *Service) Enroll(ctx context.Context) (Identity, error) {
	configuration, target, err := s.configurationAndTarget(ctx)
	if err != nil {
		return Identity{}, err
	}
	state, err := ensureApprovedAgentRegistration(ctx, s.states, s.client, systemPromptWriter{}, target, configuration)
	if err != nil {
		return Identity{}, fmt.Errorf("enroll Agent: %w", err)
	}
	if state.Identity == nil {
		assertion, err := signAgentJWT(state, configuration.Issuer, time.Now())
		if err != nil {
			return Identity{}, err
		}
		var enrollment enrollmentResponse
		if err := requestJSONHeaders(ctx, s.client, http.MethodPost, configuration.AgentEnrollmentEndpoint, map[string]string{
			"Authorization":   "Bearer " + assertion,
			"Idempotency-Key": state.EnrollmentIdempotencyKey,
		}, map[string]any{"kind": "new_identity", "name": state.Name}, &enrollment); err != nil {
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
		return Identity{}, errors.New("Realmroot Agent enrollment is incomplete; run `realmroot agent enroll`")
	}
	return publicIdentity(state.Identity), nil
}

func publicIdentity(identity *stableIdentity) Identity {
	return Identity{ID: identity.ID, Issuer: identity.Issuer, Subject: identity.Subject}
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
	output, err := acceptCredentialOffer(resource, credential, s.origin, s.states, newCredentialSourceReference)
	if err != nil {
		return CredentialBinding{}, err
	}
	body, ok := output.Response.Body.(map[string]any)
	if !ok {
		return CredentialBinding{}, errors.New("stored credential receipt is invalid")
	}
	source, ok := body["credentialSource"].(map[string]any)
	if !ok {
		return CredentialBinding{}, errors.New("stored credential source is invalid")
	}
	reference, _ := source["reference"].(string)
	if reference == "" {
		return CredentialBinding{}, errors.New("stored credential source reference is missing")
	}
	if err := s.storeActiveBinding(offer.ResourceIndicator, reference); err != nil {
		return CredentialBinding{}, err
	}
	return CredentialBinding{Reference: reference, Scopes: append([]string(nil), offer.Scopes...)}, nil
}

func (s *Service) BindingForResource(resourceIndicator string) (CredentialBinding, error) {
	runtimeName, err := agentRuntime()
	if err != nil {
		return CredentialBinding{}, err
	}
	var binding *CredentialBinding
	activeReference, activeErr := s.activeBinding(resourceIndicator)
	if activeErr != nil && !errors.Is(activeErr, os.ErrNotExist) {
		return CredentialBinding{}, activeErr
	}
	err = s.states.walkStates(func(_ string, state agentState) error {
		if state.Runtime != runtimeName || state.Origin != s.origin {
			return nil
		}
		for reference, source := range state.CredentialSources {
			if source.ResourceIndicator != resourceIndicator {
				continue
			}
			if activeReference != "" && reference != activeReference {
				continue
			}
			if len(source.Offers) == 0 {
				continue
			}
			if binding != nil && binding.Reference != reference {
				return errors.New("multiple authorization contexts exist for this Resource Server")
			}
			scopes := make([]string, 0)
			for _, offer := range source.Offers {
				scopes = append(scopes, offer.Scopes...)
			}
			binding = &CredentialBinding{Reference: reference, Scopes: uniqueStrings(scopes)}
		}
		return nil
	})
	if err != nil {
		return CredentialBinding{}, err
	}
	if binding == nil {
		return CredentialBinding{}, os.ErrNotExist
	}
	if activeReference == "" {
		if err := s.storeActiveBinding(resourceIndicator, binding.Reference); err != nil {
			return CredentialBinding{}, err
		}
	}
	return *binding, nil
}

type activeBindings struct {
	Version int               `json:"version"`
	Items   map[string]string `json:"items"`
}

func (s *Service) activeBinding(resourceIndicator string) (string, error) {
	data, err := os.ReadFile(filepath.Join(s.states.root, "bindings.json"))
	if err != nil {
		return "", err
	}
	var bindings activeBindings
	if err := json.Unmarshal(data, &bindings); err != nil {
		return "", fmt.Errorf("decode active credential bindings: %w", err)
	}
	if bindings.Version != 1 {
		return "", errors.New("active credential bindings have an unsupported version")
	}
	reference := bindings.Items[resourceIndicator]
	if reference == "" {
		return "", os.ErrNotExist
	}
	return reference, nil
}

func (s *Service) storeActiveBinding(resourceIndicator, reference string) error {
	path := filepath.Join(s.states.root, "bindings.json")
	bindings := activeBindings{Version: 1, Items: map[string]string{}}
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &bindings); err != nil {
			return fmt.Errorf("decode active credential bindings: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	bindings.Version = 1
	if bindings.Items == nil {
		bindings.Items = make(map[string]string)
	}
	bindings.Items[resourceIndicator] = reference
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

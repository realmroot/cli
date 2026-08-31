package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type credentialSourceInput struct {
	Action    string   `cbor:"action" json:"action"`
	Reference string   `cbor:"reference" json:"reference"`
	Scopes    []string `cbor:"scopes,omitempty" json:"scopes,omitempty"`
	Proof     string   `cbor:"proof,omitempty" json:"proof,omitempty"`
}

type credentialSourceDescription struct {
	ProofMethod string   `cbor:"proof_method" json:"proofMethod"`
	ProofURI    string   `cbor:"proof_uri" json:"proofUri"`
	Resource    string   `cbor:"resource" json:"resource"`
	Scopes      []string `cbor:"scopes,omitempty" json:"scopes,omitempty"`
}

type credentialSourceCredential struct {
	AccessToken string    `cbor:"access_token" json:"accessToken"`
	TokenType   string    `cbor:"token_type" json:"tokenType"`
	ExpiresAt   time.Time `cbor:"expires_at" json:"expiresAt"`
	Resource    string    `cbor:"resource" json:"resource"`
	Scopes      []string  `cbor:"scopes,omitempty" json:"scopes,omitempty"`
	Nonce       string    `cbor:"nonce,omitempty" json:"nonce,omitempty"`
}

type credentialSourceChallenge struct {
	Type  string `cbor:"type" json:"type"`
	Nonce string `cbor:"nonce" json:"nonce"`
}

type credentialSourceOutput struct {
	Description *credentialSourceDescription `cbor:"description,omitempty" json:"description,omitempty"`
	Credential  *credentialSourceCredential  `cbor:"credential,omitempty" json:"credential,omitempty"`
	Challenge   *credentialSourceChallenge   `cbor:"challenge,omitempty" json:"challenge,omitempty"`
}

type dpopNonceChallenge struct{ nonce string }

type targetCredentialIssueError struct{ err error }

func (e *targetCredentialIssueError) Error() string {
	var responseErr *httpResponseError
	if errors.As(e.err, &responseErr) {
		var problem struct {
			Detail           string `json:"detail"`
			ErrorDescription string `json:"error_description"`
			Error            struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal([]byte(responseErr.Body), &problem) == nil {
			detail := problem.Detail
			if detail == "" {
				detail = problem.ErrorDescription
			}
			if detail == "" {
				detail = problem.Error.Message
			}
			if detail != "" {
				return fmt.Sprintf("Realmroot credential HTTP %d: %s", responseErr.StatusCode, detail)
			}
		}
		body := strings.TrimSpace(responseErr.Body)
		if len(body) > 40 {
			body = body[:40] + "…"
		}
		return fmt.Sprintf("Realmroot credential HTTP %d: %s", responseErr.StatusCode, body)
	}
	return "issue target API access token: " + e.err.Error()
}
func (e *targetCredentialIssueError) Unwrap() error { return e.err }

func (e *dpopNonceChallenge) Error() string {
	return "Realmroot requires a nonce in the target DPoP proof"
}

func handleCredentialSource(
	ctx context.Context,
	input credentialSourceInput,
	states credentialStore,
	client httpDoer,
) (credentialSourceOutput, error) {
	if input.Reference == "" {
		return credentialSourceOutput{}, errors.New("Realmroot credential source reference is required")
	}
	runtime, err := agentRuntime()
	if err != nil {
		return credentialSourceOutput{}, err
	}
	switch input.Action {
	case "describe":
		if input.Proof != "" {
			return credentialSourceOutput{}, errors.New("Realmroot credential describe must not include a proof")
		}
		bootstrap, err := resolveBootstrapCredentialSource(ctx, client, states, input.Reference, runtime, input.Scopes)
		if err != nil {
			return credentialSourceOutput{}, err
		}
		if bootstrap != nil {
			return credentialSourceOutput{Description: &credentialSourceDescription{
				ProofMethod: http.MethodPost,
				ProofURI:    bootstrap.configuration.AgentTokenEndpoint,
				Resource:    bootstrap.reference.source.ResourceIndicator,
				Scopes:      append([]string(nil), input.Scopes...),
			}}, nil
		}
		reference, err := states.FindCredential(input.Reference, runtime, input.Scopes)
		if errors.Is(err, os.ErrNotExist) {
			return credentialSourceOutput{}, fmt.Errorf(
				"Realmroot credential source %q does not currently authorize scopes %q; request additional Resource access before retrying",
				input.Reference,
				input.Scopes,
			)
		}
		if err != nil {
			return credentialSourceOutput{}, err
		}
		offer := reference.credential
		return credentialSourceOutput{Description: &credentialSourceDescription{
			ProofMethod: http.MethodPost,
			ProofURI:    offer.ProofTarget,
			Resource:    offer.ResourceIndicator,
			Scopes:      append([]string(nil), offer.Scopes...),
		}}, nil
	case "issue":
		if strings.TrimSpace(input.Proof) == "" {
			return credentialSourceOutput{}, errors.New("Realmroot credential issue requires a DPoP proof")
		}
		bootstrap, err := resolveBootstrapCredentialSource(ctx, client, states, input.Reference, runtime, input.Scopes)
		if err != nil {
			return credentialSourceOutput{}, err
		}
		if bootstrap != nil {
			credential, err := issueBootstrapCredential(
				ctx, client, states, bootstrap.reference, bootstrap.configuration, input.Scopes, input.Proof,
			)
			if err != nil {
				var challenge *dpopNonceChallenge
				if errors.As(err, &challenge) {
					return credentialSourceOutput{Challenge: &credentialSourceChallenge{
						Type: "dpop-nonce", Nonce: challenge.nonce,
					}}, nil
				}
				return credentialSourceOutput{}, err
			}
			return credentialSourceOutput{Credential: &credential}, nil
		}
		reference, err := states.FindCredential(input.Reference, runtime, input.Scopes)
		if err != nil {
			return credentialSourceOutput{}, err
		}
		token, err := issueTargetCredential(ctx, client, states, reference, reference.credential, input.Proof)
		if err != nil {
			var challenge *dpopNonceChallenge
			if errors.As(err, &challenge) {
				return credentialSourceOutput{Challenge: &credentialSourceChallenge{
					Type: "dpop-nonce", Nonce: challenge.nonce,
				}}, nil
			}
			return credentialSourceOutput{}, err
		}
		updated := reference.credential
		updated.Scopes = append([]string(nil), token.Scopes...)
		if err := states.UpdateCredential(reference, updated); err != nil {
			return credentialSourceOutput{}, fmt.Errorf("update current Resource credential: %w", err)
		}
		return credentialSourceOutput{Credential: &credentialSourceCredential{
			AccessToken: token.AccessToken,
			TokenType:   token.TokenType,
			ExpiresAt:   token.ExpiresAt,
			Resource:    token.ResourceIndicator,
			Scopes:      append([]string(nil), token.Scopes...),
			Nonce:       token.DPoPNonce,
		}}, nil
	default:
		return credentialSourceOutput{}, fmt.Errorf("unsupported Realmroot credential source action %q", input.Action)
	}
}

type bootstrapCredentialSource struct {
	reference     credentialSourceStateReference
	configuration agentConfiguration
}

func resolveBootstrapCredentialSource(
	ctx context.Context,
	client httpDoer,
	states credentialStore,
	reference string,
	runtime string,
	scopes []string,
) (*bootstrapCredentialSource, error) {
	stored, err := states.FindCredentialSource(reference, runtime)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if stored.source.ResourceIndicator != strings.TrimSuffix(stored.state.Origin, "/")+"/api" || len(scopes) == 0 {
		return nil, nil
	}
	configuration, err := resolveAgentConfiguration(ctx, client, configurationCache(states), stored.state.Origin)
	if err != nil {
		return nil, err
	}
	if !scopesContain(configuration.AgentBootstrapScopes, scopes) {
		return nil, nil
	}
	if stored.state.Identity == nil {
		return nil, errors.New("Realmroot Agent enrollment is incomplete; rerun `realmroot agent enroll --username <username>`")
	}
	return &bootstrapCredentialSource{reference: stored, configuration: configuration}, nil
}

func issueBootstrapCredential(
	ctx context.Context,
	client httpDoer,
	states credentialStore,
	reference credentialSourceStateReference,
	configuration agentConfiguration,
	scopes []string,
	targetProof string,
) (credentialSourceCredential, error) {
	if _, err := ensureInternalProtocolCredential(
		ctx, client, states, reference, configuration, scopes,
	); err != nil {
		return credentialSourceCredential{}, err
	}
	var response struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	headers, err := requestFormHeadersResponse(
		ctx,
		client,
		configuration.AgentTokenEndpoint,
		map[string]string{"DPoP": targetProof},
		url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
			"assertion":  {mustAgentJWT(reference.state, configuration.Issuer)},
			"resource":   {reference.source.ResourceIndicator},
			"scope":      {strings.Join(scopes, " ")},
		},
		&response,
	)
	if err != nil {
		if challenge, ok := realmrootDPoPNonceChallenge(err); ok {
			return credentialSourceCredential{}, challenge
		}
		return credentialSourceCredential{}, fmt.Errorf("obtain Realmroot Agent bootstrap OAuth credential: %w", err)
	}
	issuedScopes := strings.Fields(response.Scope)
	if response.TokenType != "DPoP" || response.AccessToken == "" || response.ExpiresIn <= 0 ||
		!sameStringSet(issuedScopes, scopes) {
		return credentialSourceCredential{}, errors.New("Realmroot returned an invalid Agent bootstrap OAuth credential")
	}
	nonce, err := responseDPoPNonce(headers)
	if err != nil {
		return credentialSourceCredential{}, fmt.Errorf("obtain Realmroot Agent bootstrap OAuth credential: %w", err)
	}
	return credentialSourceCredential{
		AccessToken: response.AccessToken,
		TokenType:   response.TokenType,
		ExpiresAt:   time.Now().Add(time.Duration(response.ExpiresIn) * time.Second),
		Resource:    reference.source.ResourceIndicator,
		Scopes:      append([]string(nil), scopes...),
		Nonce:       nonce,
	}, nil
}

func ensureInternalProtocolCredential(
	ctx context.Context,
	client httpDoer,
	states credentialStore,
	reference credentialSourceStateReference,
	configuration agentConfiguration,
	requiredScopes []string,
) (dpopCredential, error) {
	credential := reference.state.ProtocolCredential
	if credential == nil {
		privateKey, err := newDPoPPrivateKey()
		if err != nil {
			return dpopCredential{}, err
		}
		credential = &dpopCredential{
			ResourceIndicator:  strings.TrimSuffix(reference.state.Origin, "/") + "/api",
			CredentialEndpoint: configuration.AgentTokenEndpoint,
			ProofTarget:        configuration.AgentTokenEndpoint,
			PrivateKey:         privateKey,
		}
	}
	if credential.AccessToken == "" || credential.ExpiresAt == nil ||
		!time.Now().Add(5*time.Second).Before(*credential.ExpiresAt) ||
		!scopesContain(credential.Scopes, requiredScopes) ||
		!credentialMatchesAgentSession(reference.state, *credential) {
		requestedScopes := retainedBootstrapScopes(credential.Scopes, requiredScopes, configuration.AgentBootstrapScopes)
		updated, err := requestProtocolToken(
			ctx, client, reference.state, *credential, configuration, requestedScopes,
		)
		if err != nil {
			return dpopCredential{}, err
		}
		credential = &updated
	}
	reference.state.ProtocolCredential = credential
	if err := states.UpdateCredentialSourceState(reference); err != nil {
		return dpopCredential{}, err
	}
	return *credential, nil
}

func issueTargetCredential(
	ctx context.Context,
	client httpDoer,
	states credentialStore,
	reference resourceCredentialReference,
	offer dpopCredential,
	targetProof string,
) (targetTokenResponse, error) {
	if offer.CredentialEndpoint == "" || offer.ProofTarget == "" {
		return targetTokenResponse{}, errors.New("stored Resource credential is incomplete")
	}
	if !sameOrigin(offer.CredentialEndpoint, reference.state.Origin) {
		return targetTokenResponse{}, errors.New("stored Resource credential endpoint does not belong to its issuer")
	}
	credentialEndpointScopes := []string{"access-requests:read", "access-requests:write"}
	protocol, ok := reusableInternalProtocolCredential(reference.state, credentialEndpointScopes)
	if !ok {
		configuration, err := resolveAgentConfiguration(
			ctx, client, configurationCache(states), reference.state.Origin,
		)
		if err != nil {
			return targetTokenResponse{}, err
		}
		source := reference.state.CredentialSources[reference.reference]
		protocol, err = ensureInternalProtocolCredential(
			ctx,
			client,
			states,
			credentialSourceStateReference{
				path: reference.path, state: reference.state, reference: reference.reference, source: source,
			},
			configuration,
			credentialEndpointScopes,
		)
		if err != nil {
			return targetTokenResponse{}, err
		}
	}
	token, responseHeaders, err := requestTargetCredential(ctx, client, protocol, offer, targetProof)
	if err != nil {
		if challenge, ok := realmrootDPoPNonceChallenge(err); ok {
			return targetTokenResponse{}, challenge
		}
		return targetTokenResponse{}, &targetCredentialIssueError{err: err}
	}
	nonce, err := responseDPoPNonce(responseHeaders)
	if err != nil {
		return targetTokenResponse{}, fmt.Errorf("issue target API access token: %w", err)
	}
	token.DPoPNonce = nonce
	if token.TokenType != "DPoP" || token.AccessToken == "" || token.ResourceIndicator != offer.ResourceIndicator ||
		!sameAuthorizationDetails(token.AuthorizationDetails, offer.AuthorizationDetails) || !token.ExpiresAt.After(time.Now()) ||
		len(token.Scopes) == 0 {
		return targetTokenResponse{}, errors.New("Realmroot returned an invalid target API access token")
	}
	return token, nil
}

func requestTargetCredential(
	ctx context.Context,
	client httpDoer,
	protocol dpopCredential,
	offer dpopCredential,
	targetProof string,
) (targetTokenResponse, http.Header, error) {
	for attempt := 0; ; attempt++ {
		requestProof, err := signDPoPProof(
			protocol.PrivateKey,
			http.MethodPost,
			offer.CredentialEndpoint,
			protocol.AccessToken,
			time.Now(),
		)
		if err != nil {
			return targetTokenResponse{}, nil, err
		}
		var token targetTokenResponse
		responseHeaders, err := requestJSONHeadersResponse(
			ctx,
			client,
			http.MethodPost,
			offer.CredentialEndpoint,
			map[string]string{
				"Authorization": "DPoP " + protocol.AccessToken,
				"DPoP":          requestProof,
			},
			map[string]any{"proof": map[string]any{"type": "dpop+jwt", "value": targetProof}},
			&token,
		)
		if err == nil {
			return token, responseHeaders, nil
		}
		if attempt >= 2 || !providerRefreshInProgress(err) {
			return targetTokenResponse{}, nil, err
		}
		if err := waitForCredentialRetry(ctx, time.Second); err != nil {
			return targetTokenResponse{}, nil, err
		}
	}
}

func providerRefreshInProgress(err error) bool {
	var responseErr *httpResponseError
	if !errors.As(err, &responseErr) || responseErr.StatusCode != http.StatusServiceUnavailable {
		return false
	}
	var body struct {
		Error string `json:"error"`
	}
	return json.Unmarshal([]byte(responseErr.Body), &body) == nil && body.Error == "temporarily_unavailable"
}

func waitForCredentialRetry(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func reusableInternalProtocolCredential(state agentState, requiredScopes []string) (dpopCredential, bool) {
	if state.ProtocolCredential == nil {
		return dpopCredential{}, false
	}
	credential := *state.ProtocolCredential
	return credential, credential.AccessToken != "" && credential.ExpiresAt != nil &&
		time.Now().Add(5*time.Second).Before(*credential.ExpiresAt) && scopesContain(credential.Scopes, requiredScopes) &&
		credentialMatchesAgentSession(state, credential)
}

func realmrootDPoPNonceChallenge(err error) (*dpopNonceChallenge, bool) {
	var responseErr *httpResponseError
	if !errors.As(err, &responseErr) || responseErr.StatusCode != http.StatusBadRequest {
		return nil, false
	}
	var body struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(responseErr.Body), &body) != nil || body.Error != "use_dpop_nonce" {
		return nil, false
	}
	nonce, nonceErr := responseDPoPNonce(responseErr.Header)
	if nonceErr != nil || nonce == "" {
		return nil, false
	}
	return &dpopNonceChallenge{nonce: nonce}, true
}

func responseDPoPNonce(headers http.Header) (string, error) {
	values := headers.Values("DPoP-Nonce")
	if len(values) == 0 {
		return "", nil
	}
	if len(values) != 1 || !validDPoPNonce(values[0]) {
		return "", errors.New("Realmroot returned an invalid DPoP nonce")
	}
	return values[0], nil
}

func validDPoPNonce(value string) bool {
	if value == "" || len(value) > 4096 {
		return false
	}
	for _, char := range []byte(value) {
		if char != 0x21 && (char < 0x23 || char > 0x5b) && (char < 0x5d || char > 0x7e) {
			return false
		}
	}
	return true
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	values := make(map[string]int, len(left))
	for _, value := range left {
		values[value]++
	}
	for _, value := range right {
		values[value]--
		if values[value] < 0 {
			return false
		}
	}
	return true
}

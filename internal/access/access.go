package access

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/realmroot/toolbox/internal/agent"
	"github.com/realmroot/toolbox/internal/catalog"
	"github.com/realmroot/toolbox/internal/realmrootapi"
)

type Receipt struct {
	Status            string   `json:"status"`
	ResourceServer    string   `json:"resourceServer"`
	ResourceIndicator string   `json:"resourceIndicator,omitempty"`
	Scopes            []string `json:"scopes"`
	ApprovalURL       string   `json:"approvalUrl,omitempty"`
}

type RequestOptions struct {
	Wait bool
}

type Service struct {
	agent *agent.Service
	api   realmrootClient
}

type realmrootClient interface {
	CreateAgentAuthorizationRequestWithResponse(context.Context, realmrootapi.CreateAgentAuthorizationRequestJSONRequestBody, ...realmrootapi.RequestEditorFn) (*realmrootapi.CreateAgentAuthorizationRequestResponse, error)
	GetAgentAuthorizationRequestWithResponse(context.Context, string, ...realmrootapi.RequestEditorFn) (*realmrootapi.GetAgentAuthorizationRequestResponse, error)
}

func New(agentService *agent.Service, httpClient realmrootapi.HttpRequestDoer) (*Service, error) {
	api, err := realmrootapi.NewClientWithResponses(
		agentService.APIBaseURL(),
		realmrootapi.WithHTTPClient(httpClient),
	)
	if err != nil {
		return nil, err
	}
	return &Service{agent: agentService, api: api}, nil
}

func (s *Service) Request(ctx context.Context, server catalog.ResourceServer, scopes []string, authorizationDetails []map[string]any, reason string, options RequestOptions) (Receipt, error) {
	scopes = normalizedScopes(scopes)
	if len(scopes) == 0 {
		return Receipt{}, errors.New("at least one exact Resource Server scope is required")
	}
	if reason = strings.TrimSpace(reason); reason == "" {
		reason = "Perform the requested operation on the selected Resource Server"
	}
	details, err := accessDetails(authorizationDetails)
	if err != nil {
		return Receipt{}, err
	}
	body := realmrootapi.CreateAgentAuthorizationRequestJSONRequestBody{
		ResourceServerId: server.ID, Scopes: scopes, Reason: &reason,
	}
	if len(details) > 0 {
		body.AuthorizationDetails = &details
	}
	response, err := s.api.CreateAgentAuthorizationRequestWithResponse(ctx, body, s.editor("access-requests:read", "access-requests:write"))
	if err != nil {
		return Receipt{}, fmt.Errorf("create Agent access request: %w", err)
	}
	if response.JSON201 == nil {
		return Receipt{}, apiError("create Agent access request", response.StatusCode(), response.Body)
	}
	requestID := response.JSON201.Id
	status := string(response.JSON201.Interaction.Status)
	approvalURL := response.JSON201.Interaction.Url
	expiresAt := response.JSON201.Interaction.ExpiresAt
	if status == "pending" && approvalURL != "" {
		if !options.Wait {
			return Receipt{Status: "pending", ResourceServer: server.CommandName, Scopes: scopes, ApprovalURL: approvalURL}, nil
		}
		if err := s.agent.OpenApproval(approvalURL); err != nil {
			return Receipt{}, err
		}
	}
	current := response.JSON201
	for status == "pending" {
		if !expiresAt.IsZero() && !time.Now().Before(expiresAt) {
			return Receipt{}, errors.New("controller access interaction expired; invoke `realmroot agent request` again")
		}
		if err := wait(ctx, 2*time.Second); err != nil {
			return Receipt{}, err
		}
		polled, err := s.api.GetAgentAuthorizationRequestWithResponse(ctx, requestID, s.editor("access-requests:read"))
		if err != nil {
			return Receipt{}, fmt.Errorf("poll Agent access request: %w", err)
		}
		if polled.JSON200 == nil {
			return Receipt{}, apiError("poll Agent access request", polled.StatusCode(), polled.Body)
		}
		status = string(polled.JSON200.Interaction.Status)
		expiresAt = polled.JSON200.Interaction.ExpiresAt
		if status == "completed" {
			if polled.JSON200.CredentialOffer.ResourceIndicator == "" {
				return Receipt{}, errors.New("approved access request has no credential offer")
			}
			offer := polled.JSON200.CredentialOffer
			authorization := mapsFromGetOffer(offer.AuthorizationDetails)
			_, err := s.agent.AcceptAccessOffer(agent.AccessOffer{
				AgentID: polled.JSON200.AgentId, Scopes: polled.JSON200.Scopes,
				ResourceIndicator: offer.ResourceIndicator, AuthorizationDetails: authorization,
				Endpoint: offer.Endpoint, ProofAlgorithm: string(offer.Proof.Algorithm),
				ProofMethod: string(offer.Proof.Method), ProofURI: offer.Proof.Uri,
			})
			if err != nil {
				return Receipt{}, fmt.Errorf("store approved credential offer: %w", err)
			}
			return receipt(server, offer.ResourceIndicator, polled.JSON200.Scopes), nil
		}
		if status != "pending" {
			return Receipt{}, fmt.Errorf("controller access interaction %s", status)
		}
	}
	if status != "completed" || current.CredentialOffer.ResourceIndicator == "" {
		return Receipt{}, fmt.Errorf("controller access interaction %s", status)
	}
	offer := current.CredentialOffer
	authorization := mapsFromCreateOffer(offer.AuthorizationDetails)
	_, err = s.agent.AcceptAccessOffer(agent.AccessOffer{
		AgentID: current.AgentId, Scopes: current.Scopes, ResourceIndicator: offer.ResourceIndicator,
		AuthorizationDetails: authorization, Endpoint: offer.Endpoint,
		ProofAlgorithm: string(offer.Proof.Algorithm), ProofMethod: string(offer.Proof.Method), ProofURI: offer.Proof.Uri,
	})
	if err != nil {
		return Receipt{}, fmt.Errorf("store approved credential offer: %w", err)
	}
	return receipt(server, offer.ResourceIndicator, current.Scopes), nil
}

func (s *Service) editor(scopes ...string) realmrootapi.RequestEditorFn {
	return func(ctx context.Context, request *http.Request) error {
		return s.agent.Authenticate(ctx, request, scopes)
	}
}

func accessDetails(values []map[string]any) ([]realmrootapi.CreateAgentAuthorizationRequestJSONBody_AuthorizationDetails_Item, error) {
	result := make([]realmrootapi.CreateAgentAuthorizationRequestJSONBody_AuthorizationDetails_Item, 0, len(values))
	for _, value := range values {
		typeName, properties, err := detail(value)
		if err != nil {
			return nil, err
		}
		result = append(result, realmrootapi.CreateAgentAuthorizationRequestJSONBody_AuthorizationDetails_Item{Type: typeName, AdditionalProperties: properties})
	}
	return result, nil
}

func detail(value map[string]any) (string, map[string]string, error) {
	typeName, _ := value["type"].(string)
	if typeName == "" {
		return "", nil, errors.New("authorization detail requires a string type")
	}
	properties := make(map[string]string)
	for name, raw := range value {
		if name == "type" {
			continue
		}
		text, ok := raw.(string)
		if !ok {
			return "", nil, fmt.Errorf("authorization detail %s must be a string", name)
		}
		properties[name] = text
	}
	return typeName, properties, nil
}

func mapsFromCreateOffer(values []realmrootapi.CreateAgentAuthorizationRequest201JSONResponseBody_CredentialOffer_AuthorizationDetails_Item) []map[string]any {
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		result = append(result, detailMap(value.Type, value.AdditionalProperties))
	}
	return result
}

func mapsFromGetOffer(values []realmrootapi.GetAgentAuthorizationRequest200JSONResponseBody_CredentialOffer_AuthorizationDetails_Item) []map[string]any {
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		result = append(result, detailMap(value.Type, value.AdditionalProperties))
	}
	return result
}

func detailMap(typeName string, properties map[string]string) map[string]any {
	result := map[string]any{"type": typeName}
	for name, value := range properties {
		result[name] = value
	}
	return result
}

func normalizedScopes(scopes []string) []string {
	seen := make(map[string]bool, len(scopes))
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope = strings.TrimSpace(scope); scope != "" && !seen[scope] {
			seen[scope] = true
			result = append(result, scope)
		}
	}
	sort.Strings(result)
	return result
}

func wait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func receipt(server catalog.ResourceServer, resource string, scopes []string) Receipt {
	return Receipt{Status: "ready", ResourceServer: server.CommandName, ResourceIndicator: resource, Scopes: scopes}
}

func apiError(operation string, status int, body []byte) error {
	return fmt.Errorf("%s: HTTP %d: %s", operation, status, strings.TrimSpace(string(body)))
}

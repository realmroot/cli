package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/realmroot/toolbox/internal/agent"
	"github.com/realmroot/toolbox/internal/realmrootapi"
	restish "github.com/saltbo/restish/v2"
)

var reservedNames = map[string]bool{
	"platform": true, "get": true, "head": true, "post": true,
	"put": true, "patch": true, "delete": true, "help": true,
	"completion": true, "version": true, "exec": true,
}

type Scope struct {
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}

type ResourceServer struct {
	ID               string   `json:"id"`
	CommandName      string   `json:"commandName"`
	Identifier       string   `json:"identifier"`
	Name             string   `json:"name"`
	Description      string   `json:"description,omitempty"`
	ResourceURL      string   `json:"resourceUrl"`
	Available        bool     `json:"available"`
	ConnectionStatus string   `json:"connectionStatus"`
	ConnectionScopes []string `json:"connectionScopes,omitempty"`
	Scopes           []Scope  `json:"scopes"`
}

type AuthorizationDetail struct {
	Name                       string            `json:"name"`
	Description                string            `json:"description,omitempty"`
	AuthorizationDetail        map[string]any    `json:"authorizationDetail"`
	AccountAuthorizationStatus string            `json:"accountAuthorizationStatus"`
	AuthorizedScopes           []string          `json:"authorizedScopes"`
	RequestableScopes          []string          `json:"requestableScopes"`
	Metadata                   map[string]string `json:"metadata"`
}

type ToolIntegration struct {
	ID          string   `json:"id"`
	Executables []string `json:"executables"`
	Protocol    string   `json:"protocol"`
}

type Client struct {
	api   *realmrootapi.ClientWithResponses
	agent *agent.Service
}

func New(service *agent.Service, httpClient realmrootapi.HttpRequestDoer) (*Client, error) {
	api, err := realmrootapi.NewClientWithResponses(service.APIBaseURL(), realmrootapi.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}
	return &Client{api: api, agent: service}, nil
}

func (c *Client) List(ctx context.Context) ([]ResourceServer, error) {
	limit, offset := 100, 0
	result := make([]ResourceServer, 0)
	for {
		response, err := c.api.ListResourceServersWithResponse(ctx, &realmrootapi.ListResourceServersParams{Limit: &limit, Offset: &offset}, c.editor("resource-servers:read"))
		if err != nil {
			return nil, fmt.Errorf("list Resource Servers: %w", err)
		}
		if response.JSON200 == nil {
			return nil, responseError("list Resource Servers", response.StatusCode(), response.Body)
		}
		for _, item := range response.JSON200.Items {
			commandName, err := resourceServerCommandName(item.Identifier)
			if err != nil {
				return nil, err
			}
			server := ResourceServer{
				ID: item.Id, CommandName: commandName, Identifier: item.Identifier, Name: item.Name,
				ResourceURL: item.ResourceUrl, Available: string(item.Availability.Status) == "available",
				ConnectionStatus: "not_required",
			}
			server.Description = item.Description
			if item.Connection.Status != "" {
				server.ConnectionStatus = string(item.Connection.Status)
				server.ConnectionScopes = append([]string(nil), item.Connection.AuthorizedScopes...)
			}
			for _, scope := range item.Scopes {
				description := ""
				description = scope.Description
				server.Scopes = append(server.Scopes, Scope{Value: scope.Value, Description: description})
			}
			if item.AvailableToAgents && item.Enabled {
				result = append(result, server)
			}
		}
		if !response.JSON200.Pagination.HasMore {
			break
		}
		offset = response.JSON200.Pagination.NextOffset
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CommandName < result[j].CommandName })
	return result, nil
}

func resourceServerCommandName(identifier string) (string, error) {
	if identifier == "realmroot" {
		return "platform", nil
	}
	if reservedNames[identifier] {
		return "", fmt.Errorf("Resource Server identifier %q conflicts with a reserved Toolbox command name", identifier)
	}
	return identifier, nil
}

func (c *Client) Find(ctx context.Context, commandName string) (ResourceServer, error) {
	servers, err := c.List(ctx)
	if err != nil {
		return ResourceServer{}, err
	}
	for _, server := range servers {
		if server.CommandName == commandName {
			return server, nil
		}
	}
	return ResourceServer{}, fmt.Errorf("Resource Server %q is not available", commandName)
}

func (c *Client) AuthorizationDetails(ctx context.Context, server ResourceServer) ([]AuthorizationDetail, error) {
	limit, offset := 100, 0
	result := make([]AuthorizationDetail, 0)
	for {
		response, err := c.api.ListResourceServerAuthorizationDetailsWithResponse(ctx, server.ID,
			&realmrootapi.ListResourceServerAuthorizationDetailsParams{Limit: &limit, Offset: &offset}, c.editor("authorization-details:read"))
		if err != nil {
			return nil, fmt.Errorf("list Resource Server authorization details: %w", err)
		}
		if response.JSON200 == nil {
			return nil, responseError("list Resource Server authorization details", response.StatusCode(), response.Body)
		}
		for _, item := range response.JSON200.Items {
			detail := map[string]any{"type": item.AuthorizationDetail.Type}
			for name, value := range item.AuthorizationDetail.AdditionalProperties {
				detail[name] = value
			}
			description := ""
			description = item.Description
			result = append(result, AuthorizationDetail{
				Name: item.Name, Description: description, AuthorizationDetail: detail,
				AccountAuthorizationStatus: string(item.AccountAuthorizationStatus),
				AuthorizedScopes:           append([]string(nil), item.AuthorizedScopes...),
				RequestableScopes:          append([]string(nil), item.RequestableScopes...), Metadata: item.Metadata,
			})
		}
		if !response.JSON200.Pagination.HasMore {
			break
		}
		offset = response.JSON200.Pagination.NextOffset
	}
	return result, nil
}

func (c *Client) ToolIntegrations(ctx context.Context, server ResourceServer) ([]ToolIntegration, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.ResourceURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := c.agent.HTTPClient().Do(request)
	if err != nil {
		return nil, fmt.Errorf("read %s native tool integrations: %w", server.CommandName, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("read %s native tool integrations: HTTP %d", server.CommandName, response.StatusCode)
	}
	var document struct {
		ToolIntegrations []ToolIntegration `json:"toolIntegrations"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		return nil, fmt.Errorf("decode %s native tool integrations: %w", server.CommandName, err)
	}
	if len(document.ToolIntegrations) == 0 {
		return nil, fmt.Errorf("Resource Server %q does not advertise native tool integrations", server.CommandName)
	}
	for _, integration := range document.ToolIntegrations {
		if integration.ID == "" || integration.Protocol == "" || len(integration.Executables) == 0 {
			return nil, fmt.Errorf("Resource Server %q advertises an invalid native tool integration", server.CommandName)
		}
	}
	return document.ToolIntegrations, nil
}

func (c *Client) RestishConfig(ctx context.Context) (*restish.Config, []ResourceServer, error) {
	servers, err := c.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	config := &restish.Config{APIs: make(map[string]*restish.APIConfig, len(servers))}
	for _, server := range servers {
		api := &restish.APIConfig{BaseURL: server.ResourceURL, CommandLayout: "tags", UnauthenticatedSpec: true}
		if server.Identifier == "realmroot" {
			api.BaseURL = c.agent.APIBaseURL()
			api.SpecURL = c.agent.APIBaseURL() + "/openapi.json"
			api.ShowHiddenOperations = true
			api.ExcludedOperationIDs = []string{
				"createAgentEnrollment", "getAgentEnrollment", "getAgentStatus",
				"createConnectionRequest", "getConnectionRequest",
				"createAgentAuthorizationRequest", "getAgentAuthorizationRequest",
				"createAgentAccessRequestCredential",
			}
		}
		if binding, bindErr := c.agent.BindingForResource(server.ResourceURL); bindErr == nil {
			api.Profiles = map[string]*restish.ProfileConfig{"default": {Auth: &restish.AuthConfig{
				Type: "dpop", Params: map[string]string{"source": "realmroot", "reference": binding.Reference},
			}}}
		} else if !errors.Is(bindErr, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("load credential binding for %s: %w", server.CommandName, bindErr)
		}
		config.APIs[server.CommandName] = api
	}
	return config, servers, nil
}

func (c *Client) editor(scopes ...string) realmrootapi.RequestEditorFn {
	return func(ctx context.Context, request *http.Request) error {
		return c.agent.Authenticate(ctx, request, scopes)
	}
}

func responseError(operation string, status int, body []byte) error {
	return fmt.Errorf("%s: HTTP %d: %s", operation, status, strings.TrimSpace(string(body)))
}

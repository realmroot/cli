package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/realmroot/cli/internal/agent"
	"github.com/realmroot/cli/internal/realmrootapi"
	restish "github.com/saltbo/restish/v2"
)

var reservedNames = reservedResourceServerNames()

type Scope struct {
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}

type ResourceServer struct {
	ID                   string           `json:"id"`
	CommandName          string           `json:"commandName"`
	Identifier           string           `json:"identifier"`
	Name                 string           `json:"name"`
	Description          string           `json:"description,omitempty"`
	ResourceURL          string           `json:"resourceUrl"`
	Available            bool             `json:"available"`
	ConnectionStatus     string           `json:"connectionStatus"`
	ConnectionScopes     []string         `json:"connectionScopes,omitempty"`
	AuthorizationDetails []map[string]any `json:"authorizationDetails,omitempty"`
	Scopes               []Scope          `json:"scopes"`
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

var ErrNoToolIntegrations = errors.New("Resource Server does not advertise native tool integrations")
var ErrNoAgentSkills = errors.New("Resource Server does not publish an Agent Skills index")

const agentSkillsSchema = "https://schemas.agentskills.io/discovery/0.2.0/schema.json"

var skillNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
var skillDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type AgentSkill struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Digest      string `json:"digest"`
}

type AgentSkillsIndex struct {
	URL    string       `json:"url"`
	Skills []AgentSkill `json:"skills"`
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
	page, pageSize := 1, 100
	result := make([]ResourceServer, 0)
	for {
		response, err := c.api.ListResourceServersWithResponse(ctx, &realmrootapi.ListResourceServersParams{Page: &page, PageSize: &pageSize}, c.editor("resource-servers:read"))
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
			for _, detail := range item.AuthorizationDetails {
				value := map[string]any{"type": detail.Type}
				for name, property := range detail.AdditionalProperties {
					value[name] = property
				}
				server.AuthorizationDetails = append(server.AuthorizationDetails, value)
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
		if response.JSON200.Pagination.Page >= response.JSON200.Pagination.TotalPages {
			break
		}
		page = response.JSON200.Pagination.Page + 1
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
	page, pageSize := 1, 100
	result := make([]AuthorizationDetail, 0)
	for {
		response, err := c.api.ListResourceServerAuthorizationDetailsWithResponse(ctx, server.ID,
			&realmrootapi.ListResourceServerAuthorizationDetailsParams{Page: &page, PageSize: &pageSize}, c.editor("authorization-details:read"))
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
		if response.JSON200.Pagination.Page >= response.JSON200.Pagination.TotalPages {
			break
		}
		page = response.JSON200.Pagination.Page + 1
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
	if contentType := response.Header.Get("Content-Type"); contentType != "" {
		mediaType, _, parseErr := mime.ParseMediaType(contentType)
		if parseErr != nil {
			return nil, fmt.Errorf("read %s native tool integrations content type: %w", server.CommandName, parseErr)
		}
		if mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json") {
			return nil, fmt.Errorf("%w: %q", ErrNoToolIntegrations, server.CommandName)
		}
	}
	var document struct {
		ToolIntegrations []ToolIntegration `json:"toolIntegrations"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		return nil, fmt.Errorf("decode %s native tool integrations: %w", server.CommandName, err)
	}
	if len(document.ToolIntegrations) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrNoToolIntegrations, server.CommandName)
	}
	for _, integration := range document.ToolIntegrations {
		if integration.ID == "" || integration.Protocol == "" || len(integration.Executables) == 0 {
			return nil, fmt.Errorf("Resource Server %q advertises an invalid native tool integration", server.CommandName)
		}
	}
	return document.ToolIntegrations, nil
}

func (c *Client) AgentSkills(ctx context.Context, server ResourceServer) (AgentSkillsIndex, error) {
	resourceURL, err := url.Parse(server.ResourceURL)
	if err != nil || resourceURL.Scheme == "" || resourceURL.Host == "" {
		return AgentSkillsIndex{}, fmt.Errorf("resolve %s Agent Skills origin: invalid Resource URL", server.CommandName)
	}
	indexURL := &url.URL{Scheme: resourceURL.Scheme, Host: resourceURL.Host, Path: "/.well-known/agent-skills/index.json"}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, indexURL.String(), nil)
	if err != nil {
		return AgentSkillsIndex{}, err
	}
	response, err := c.agent.HTTPClient().Do(request)
	if err != nil {
		return AgentSkillsIndex{}, fmt.Errorf("read %s Agent Skills index: %w", server.CommandName, err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return AgentSkillsIndex{}, fmt.Errorf("%w: %q", ErrNoAgentSkills, server.CommandName)
	}
	if response.StatusCode != http.StatusOK {
		return AgentSkillsIndex{}, fmt.Errorf("read %s Agent Skills index: HTTP %d", server.CommandName, response.StatusCode)
	}
	if contentType := response.Header.Get("Content-Type"); contentType != "" {
		mediaType, _, parseErr := mime.ParseMediaType(contentType)
		if parseErr != nil {
			return AgentSkillsIndex{}, fmt.Errorf("read %s Agent Skills index content type: %w", server.CommandName, parseErr)
		}
		if mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json") {
			return AgentSkillsIndex{}, fmt.Errorf("%w: %q returned %s", ErrNoAgentSkills, server.CommandName, mediaType)
		}
	}
	const maxIndexBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, maxIndexBytes+1))
	if err != nil {
		return AgentSkillsIndex{}, fmt.Errorf("read %s Agent Skills index body: %w", server.CommandName, err)
	}
	if len(body) > maxIndexBytes {
		return AgentSkillsIndex{}, fmt.Errorf("read %s Agent Skills index: response exceeds %d bytes", server.CommandName, maxIndexBytes)
	}
	var document struct {
		Schema string        `json:"$schema"`
		Skills *[]AgentSkill `json:"skills"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return AgentSkillsIndex{}, fmt.Errorf("decode %s Agent Skills index: %w", server.CommandName, err)
	}
	if document.Schema != agentSkillsSchema {
		return AgentSkillsIndex{}, fmt.Errorf("read %s Agent Skills index: unsupported schema %q", server.CommandName, document.Schema)
	}
	if document.Skills == nil {
		return AgentSkillsIndex{}, fmt.Errorf("read %s Agent Skills index: skills array is required", server.CommandName)
	}
	skills := *document.Skills
	seenNames := make(map[string]bool, len(skills))
	for index := range skills {
		skill := &skills[index]
		if !skillNamePattern.MatchString(skill.Name) || strings.Contains(skill.Name, "--") {
			return AgentSkillsIndex{}, fmt.Errorf("read %s Agent Skills index: invalid skill name %q", server.CommandName, skill.Name)
		}
		if seenNames[skill.Name] {
			return AgentSkillsIndex{}, fmt.Errorf("read %s Agent Skills index: duplicate skill name %q", server.CommandName, skill.Name)
		}
		seenNames[skill.Name] = true
		if skill.Type != "skill-md" && skill.Type != "archive" {
			return AgentSkillsIndex{}, fmt.Errorf("read %s Agent Skills index: invalid type %q for %s", server.CommandName, skill.Type, skill.Name)
		}
		if strings.TrimSpace(skill.Description) == "" || utf8.RuneCountInString(skill.Description) > 1024 {
			return AgentSkillsIndex{}, fmt.Errorf("read %s Agent Skills index: invalid description for %s", server.CommandName, skill.Name)
		}
		if !skillDigestPattern.MatchString(skill.Digest) {
			return AgentSkillsIndex{}, fmt.Errorf("read %s Agent Skills index: invalid digest for %s", server.CommandName, skill.Name)
		}
		if skill.URL == "" {
			return AgentSkillsIndex{}, fmt.Errorf("read %s Agent Skills index: URL is required for %s", server.CommandName, skill.Name)
		}
		artifactURL, parseErr := url.Parse(skill.URL)
		if parseErr != nil {
			return AgentSkillsIndex{}, fmt.Errorf("read %s Agent Skills index: invalid URL for %s", server.CommandName, skill.Name)
		}
		resolved := indexURL.ResolveReference(artifactURL)
		if (resolved.Scheme != "http" && resolved.Scheme != "https") || resolved.Host == "" {
			return AgentSkillsIndex{}, fmt.Errorf("read %s Agent Skills index: unsupported URL for %s", server.CommandName, skill.Name)
		}
		skill.URL = resolved.String()
	}
	return AgentSkillsIndex{URL: indexURL.String(), Skills: skills}, nil
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

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/realmroot/cli/internal/agent"
	"github.com/realmroot/cli/internal/catalog"
	"github.com/spf13/pflag"
)

type contextSummary struct {
	ID                         string            `json:"id,omitempty"`
	Name                       string            `json:"name"`
	Description                string            `json:"description,omitempty"`
	Metadata                   map[string]string `json:"metadata,omitempty"`
	AccountAuthorizationStatus string            `json:"accountAuthorizationStatus"`
	AuthorizedScopes           []string          `json:"authorizedScopes,omitempty"`
	RequestableScopes          []string          `json:"requestableScopes,omitempty"`
	Current                    bool              `json:"current"`
}

type contextListItem struct {
	Type                       string      `json:"type"`
	AuthorizedScopes           []string    `json:"authorizedScopes"`
	RequestableScopes          []string    `json:"requestableScopes"`
	UnavailableScopes          []string    `json:"unavailableScopes"`
	ID                         string      `json:"id,omitempty"`
	Name                       string      `json:"name"`
	AccountAuthorizationStatus string      `json:"accountAuthorizationStatus"`
	Current                    bool        `json:"current"`
	AuthorizedScopeCount       int         `json:"authorizedScopeCount"`
	RequestableScopeCount      int         `json:"requestableScopeCount"`
	Match                      *scopeMatch `json:"match,omitempty"`
}

type contextResult struct {
	ResourceServer  string            `json:"resourceServer"`
	Contexts        []contextListItem `json:"contexts"`
	RequestedScopes []string          `json:"requestedScopes,omitempty"`
}

type contextSelectionResult struct {
	ResourceServer string `json:"resourceServer"`
	ContextID      string `json:"contextId,omitempty"`
	Name           string `json:"name,omitempty"`
	Current        bool   `json:"current"`
}

type contextUnavailableError struct{ id string }

func (e contextUnavailableError) Error() string {
	return fmt.Sprintf("Context ID %q is not available", e.id)
}

func listContexts(details []catalog.AuthorizationDetail, selected []map[string]any, scopes ...catalog.Scope) []contextListItem {
	result := make([]contextListItem, 0, len(details))
	for _, detail := range details {
		kind := "resource"
		if detail.AuthorizationDetail["type"] == "realmroot_authority" {
			kind, _ = detail.AuthorizationDetail["authority"].(string)
		}
		unavailable := []string{}
		for _, scope := range scopes {
			if !slices.Contains(detail.AuthorizedScopes, scope.Value) && !slices.Contains(detail.RequestableScopes, scope.Value) {
				unavailable = append(unavailable, scope.Value)
			}
		}
		result = append(result, contextListItem{
			Type: kind, AuthorizedScopes: append([]string{}, detail.AuthorizedScopes...), RequestableScopes: append([]string{}, detail.RequestableScopes...), UnavailableScopes: unavailable,
			ID: detail.ID, Name: detail.Name, AccountAuthorizationStatus: detail.AccountAuthorizationStatus,
			Current:              sameDetails(detail.AuthorizationDetail, selected),
			AuthorizedScopeCount: len(detail.AuthorizedScopes), RequestableScopeCount: len(detail.RequestableScopes),
		})
	}
	return result
}

func summarizeContexts(details []catalog.AuthorizationDetail, selected []map[string]any) []contextSummary {
	result := make([]contextSummary, 0, len(details))
	for _, detail := range details {
		result = append(result, contextSummary{
			ID: detail.ID, Name: detail.Name, Description: detail.Description, Metadata: detail.Metadata,
			AccountAuthorizationStatus: detail.AccountAuthorizationStatus,
			AuthorizedScopes:           append([]string(nil), detail.AuthorizedScopes...),
			RequestableScopes:          append([]string(nil), detail.RequestableScopes...),
			Current:                    sameDetails(detail.AuthorizationDetail, selected),
		})
	}
	return result
}

func (a *App) contextCommand(ctx context.Context, service *agent.Service, client *catalog.Client, serverName string, args []string) error {
	flags := pflag.NewFlagSet("context", pflag.ContinueOnError)
	flags.SetOutput(a.stderr)
	scopes := flags.StringArray("scope", nil, "show permission matches without filtering Contexts (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	args = flags.Args()
	*scopes = requestedScopes(*scopes)
	if len(*scopes) > 0 && len(args) > 0 {
		return errors.New("--scope applies only to the Context list")
	}
	server, err := client.Find(ctx, serverName)
	if err != nil {
		return err
	}
	if len(args) == 1 && args[0] == "clear" {
		if err := service.ClearContext(server.ResourceURL); err != nil {
			return err
		}
		result := contextSelectionResult{ResourceServer: server.CommandName, Current: false}
		if a.json {
			return a.printJSON(result)
		}
		fmt.Fprintf(a.stdout, "Cleared the current Context for %s.\n", result.ResourceServer)
		return nil
	}
	details, err := client.AuthorizationDetails(ctx, server)
	if err != nil {
		return err
	}
	selected, selectedErr := service.SelectedContext(server.ResourceURL)
	if selectedErr != nil && !errors.Is(selectedErr, os.ErrNotExist) {
		return selectedErr
	}
	if len(args) == 0 {
		items := listContexts(details, selected, server.Scopes...)
		if len(*scopes) > 0 {
			items = contextMatches(details, selected, *scopes, server.Scopes...)
		}
		return a.printContexts(contextResult{ResourceServer: server.CommandName, Contexts: items, RequestedScopes: *scopes})
	}
	if len(args) != 2 || (args[0] != "show" && args[0] != "use") {
		return fmt.Errorf("usage: realmroot toolbox %s context [show|use] <context-id> | clear", server.CommandName)
	}
	detail, err := contextBySelector(details, args[1])
	if err != nil {
		return err
	}
	if args[0] == "use" {
		if err := service.StoreContext(server.ResourceURL, []map[string]any{detail.AuthorizationDetail}); err != nil {
			return err
		}
		result := contextSelectionResult{ResourceServer: server.CommandName, ContextID: detail.ID, Name: detail.Name, Current: true}
		if a.json {
			return a.printJSON(result)
		}
		fmt.Fprintf(a.stdout, "Current Context for %s: %s (%s)\n", result.ResourceServer, result.Name, result.ContextID)
		return nil
	}
	summary := summarizeContexts([]catalog.AuthorizationDetail{detail}, selected)[0]
	if a.json {
		return a.printJSON(summary)
	}
	return a.printContext(server.CommandName, summary)
}

func (a *App) resolveContext(service *agent.Service, server catalog.ResourceServer, details []catalog.AuthorizationDetail, contextID string) ([]map[string]any, error) {
	selected, _, err := a.resolveContextSelection(service, server, details, contextID)
	return selected, err
}

func (a *App) resolveContextSelection(service *agent.Service, server catalog.ResourceServer, details []catalog.AuthorizationDetail, contextID string) ([]map[string]any, string, error) {
	if contextID != "" {
		detail, err := contextBySelector(details, contextID)
		if err != nil {
			var unavailable contextUnavailableError
			if errors.As(err, &unavailable) {
				return nil, "", fmt.Errorf("%w; connect or update it in Realmroot Connections: %s/connections", err, service.Origin())
			}
			return nil, "", err
		}
		return []map[string]any{detail.AuthorizationDetail}, "command_line", nil
	}
	selected, err := service.SelectedContext(server.ResourceURL)
	if err == nil {
		for _, detail := range details {
			if sameDetails(detail.AuthorizationDetail, selected) {
				return selected, "saved_default", nil
			}
		}
		if len(details) == 0 {
			if err := service.ClearContext(server.ResourceURL); err != nil {
				return nil, "", err
			}
			return disconnectedAuthorizationDetails(server), "resource_default", nil
		}
		return nil, "", fmt.Errorf("the selected %s Context is no longer available; run `realmroot toolbox %s context`", server.CommandName, server.CommandName)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	switch len(details) {
	case 0:
		return disconnectedAuthorizationDetails(server), "resource_default", nil
	case 1:
		return []map[string]any{details[0].AuthorizationDetail}, "only_available", nil
	default:
		return nil, "", fmt.Errorf("Resource Server %q has multiple Contexts; select one with `realmroot toolbox %s context use <context-id>` or pass --context <context-id>", server.CommandName, server.CommandName)
	}
}

func disconnectedAuthorizationDetails(server catalog.ResourceServer) []map[string]any {
	if server.ConnectionStatus != "not_connected" {
		return nil
	}
	return server.AuthorizationDetails
}

func contextBySelector(details []catalog.AuthorizationDetail, selector string) (catalog.AuthorizationDetail, error) {
	for _, detail := range details {
		if detail.ID != "" && detail.ID == selector {
			return detail, nil
		}
	}
	var legacyMatches []catalog.AuthorizationDetail
	for _, detail := range details {
		if detail.ID == "" && strings.EqualFold(detail.Name, selector) {
			legacyMatches = append(legacyMatches, detail)
		}
	}
	if len(legacyMatches) == 1 {
		return legacyMatches[0], nil
	}
	if len(legacyMatches) > 1 {
		return catalog.AuthorizationDetail{}, fmt.Errorf("legacy Context name %q is ambiguous", selector)
	}
	return catalog.AuthorizationDetail{}, contextUnavailableError{id: selector}
}

func sameDetails(detail map[string]any, selected []map[string]any) bool {
	if len(selected) != 1 {
		return false
	}
	left, leftErr := json.Marshal(detail)
	right, rightErr := json.Marshal(selected[0])
	return leftErr == nil && rightErr == nil && string(left) == string(right)
}

func (a *App) printContexts(result contextResult) error {
	if a.json {
		return a.printJSON(result)
	}
	if len(result.Contexts) == 0 {
		fmt.Fprintf(a.stdout, "Resource Server %q does not define Contexts.\n", result.ResourceServer)
		return nil
	}
	if len(result.RequestedScopes) > 0 {
		fmt.Fprintf(a.stdout, "Requested scopes: %s\n", strings.Join(result.RequestedScopes, ", "))
	}
	return printContextRows(a.stdout, result.Contexts)
}

func (a *App) printContext(resourceServer string, item contextSummary) error {
	fmt.Fprintf(a.stdout, "Context: %s\n", item.Name)
	if item.ID != "" {
		fmt.Fprintf(a.stdout, "Context ID: %s\n", item.ID)
	}
	fmt.Fprintf(a.stdout, "Resource Server: %s\nAccount: %s\n", resourceServer, item.AccountAuthorizationStatus)
	if item.Description != "" {
		fmt.Fprintf(a.stdout, "Description: %s\n", item.Description)
	}
	metadataNames := make([]string, 0, len(item.Metadata))
	for name := range item.Metadata {
		metadataNames = append(metadataNames, name)
	}
	sort.Strings(metadataNames)
	for _, name := range metadataNames {
		value := item.Metadata[name]
		fmt.Fprintf(a.stdout, "%s: %s\n", name, value)
	}
	if len(item.AuthorizedScopes) > 0 {
		fmt.Fprintf(a.stdout, "Authorized scopes: %s\n", strings.Join(item.AuthorizedScopes, ", "))
	}
	if len(item.RequestableScopes) > 0 {
		fmt.Fprintf(a.stdout, "Requestable scopes: %s\n", strings.Join(item.RequestableScopes, ", "))
	}
	if item.Current {
		fmt.Fprintln(a.stdout, "Current: yes")
	}
	return nil
}

func scopeNames(scopes []string) string {
	if len(scopes) == 0 {
		return "-"
	}
	return strings.Join(scopes, ", ")
}

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/realmroot/toolbox/internal/agent"
	"github.com/realmroot/toolbox/internal/catalog"
)

type contextSummary struct {
	Name                       string            `json:"name"`
	Description                string            `json:"description,omitempty"`
	Metadata                   map[string]string `json:"metadata,omitempty"`
	AccountAuthorizationStatus string            `json:"accountAuthorizationStatus"`
	AuthorizedScopes           []string          `json:"authorizedScopes,omitempty"`
	RequestableScopes          []string          `json:"requestableScopes,omitempty"`
	Current                    bool              `json:"current"`
}

type contextListItem struct {
	Name                       string `json:"name"`
	AccountAuthorizationStatus string `json:"accountAuthorizationStatus"`
	Current                    bool   `json:"current"`
}

type contextResult struct {
	ResourceServer string            `json:"resourceServer"`
	Contexts       []contextListItem `json:"contexts"`
}

type contextSelectionResult struct {
	ResourceServer string `json:"resourceServer"`
	Context        string `json:"context"`
	Current        bool   `json:"current"`
}

func listContexts(details []catalog.AuthorizationDetail, selected []map[string]any) []contextListItem {
	result := make([]contextListItem, 0, len(details))
	for _, detail := range details {
		result = append(result, contextListItem{
			Name: detail.Name, AccountAuthorizationStatus: detail.AccountAuthorizationStatus,
			Current: sameDetails(detail.AuthorizationDetail, selected),
		})
	}
	return result
}

func summarizeContexts(details []catalog.AuthorizationDetail, selected []map[string]any) []contextSummary {
	result := make([]contextSummary, 0, len(details))
	for _, detail := range details {
		result = append(result, contextSummary{
			Name: detail.Name, Description: detail.Description, Metadata: detail.Metadata,
			AccountAuthorizationStatus: detail.AccountAuthorizationStatus,
			AuthorizedScopes:           append([]string(nil), detail.AuthorizedScopes...),
			RequestableScopes:          append([]string(nil), detail.RequestableScopes...),
			Current:                    sameDetails(detail.AuthorizationDetail, selected),
		})
	}
	return result
}

func (a *App) contextCommand(ctx context.Context, service *agent.Service, client *catalog.Client, serverName string, args []string) error {
	server, err := client.Find(ctx, serverName)
	if err != nil {
		return err
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
		return a.printContexts(contextResult{ResourceServer: server.CommandName, Contexts: listContexts(details, selected)})
	}
	if len(args) != 2 || (args[0] != "show" && args[0] != "use") {
		return fmt.Errorf("usage: realmroot toolbox %s context [show|use] <name>", server.CommandName)
	}
	detail, err := namedContext(details, args[1])
	if err != nil {
		return err
	}
	if args[0] == "use" {
		if err := service.StoreContext(server.ResourceURL, []map[string]any{detail.AuthorizationDetail}); err != nil {
			return err
		}
		result := contextSelectionResult{ResourceServer: server.CommandName, Context: detail.Name, Current: true}
		if a.json {
			return a.printJSON(result)
		}
		fmt.Fprintf(a.stdout, "Current Context for %s: %s\n", result.ResourceServer, result.Context)
		return nil
	}
	summary := summarizeContexts([]catalog.AuthorizationDetail{detail}, selected)[0]
	if a.json {
		return a.printJSON(summary)
	}
	return a.printContext(server.CommandName, summary)
}

func (a *App) resolveContext(service *agent.Service, server catalog.ResourceServer, details []catalog.AuthorizationDetail, name string) ([]map[string]any, error) {
	if name != "" {
		detail, err := namedContext(details, name)
		if err != nil {
			return nil, err
		}
		return []map[string]any{detail.AuthorizationDetail}, nil
	}
	selected, err := service.SelectedContext(server.ResourceURL)
	if err == nil {
		for _, detail := range details {
			if sameDetails(detail.AuthorizationDetail, selected) {
				return selected, nil
			}
		}
		return nil, fmt.Errorf("the selected %s Context is no longer available; run `realmroot toolbox %s context`", server.CommandName, server.CommandName)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	switch len(details) {
	case 0:
		return nil, nil
	case 1:
		return []map[string]any{details[0].AuthorizationDetail}, nil
	default:
		return nil, fmt.Errorf("Resource Server %q has multiple Contexts; select one with `realmroot toolbox %s context use <name>` or pass --context <name>", server.CommandName, server.CommandName)
	}
}

func namedContext(details []catalog.AuthorizationDetail, name string) (catalog.AuthorizationDetail, error) {
	var matches []catalog.AuthorizationDetail
	for _, detail := range details {
		if detail.Name == name {
			matches = append(matches, detail)
		}
	}
	if len(matches) == 0 {
		return catalog.AuthorizationDetail{}, fmt.Errorf("Context %q is not available", name)
	}
	if len(matches) > 1 {
		return catalog.AuthorizationDetail{}, fmt.Errorf("Context name %q is ambiguous", name)
	}
	return matches[0], nil
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
	w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "CURRENT\tNAME\tACCOUNT")
	for _, item := range result.Contexts {
		current := ""
		if item.Current {
			current = "*"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", current, item.Name, item.AccountAuthorizationStatus)
	}
	return w.Flush()
}

func (a *App) printContext(resourceServer string, item contextSummary) error {
	fmt.Fprintf(a.stdout, "Context: %s\nResource Server: %s\nAccount: %s\n", item.Name, resourceServer, item.AccountAuthorizationStatus)
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

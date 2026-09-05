package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/realmroot/cli/internal/access"
	"github.com/realmroot/cli/internal/catalog"
)

type scopeMatch struct {
	Status      string   `json:"status"`
	Authorized  []string `json:"authorizedScopes"`
	Requestable []string `json:"requestableScopes"`
	Unavailable []string `json:"unavailableScopes"`
}

type selectedContextSummary struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	Type   string `json:"type,omitempty"`
	Source string `json:"source"`
}

type accessRequestResult struct {
	access.Receipt
	Context         selectedContextSummary `json:"context"`
	RequestedScopes []string               `json:"requestedScopes"`
	Contexts        []contextListItem      `json:"contexts"`
	Error           json.RawMessage        `json:"-"`
}

type resourceAccessRequester interface {
	Request(context.Context, catalog.ResourceServer, []string, []map[string]any, string, access.RequestOptions) (access.Receipt, error)
}

func requestedScopes(scopes []string) []string {
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope = strings.TrimSpace(scope); scope != "" {
			result = append(result, scope)
		}
	}
	slices.Sort(result)
	return slices.Compact(result)
}

func contextIdentity(detail catalog.AuthorizationDetail) (string, string) {
	if detail.AuthorizationDetail["type"] == "realmroot_authority" {
		id := detail.ID
		kind, _ := detail.AuthorizationDetail["authority"].(string)
		return id, kind
	}
	return detail.ID, "resource"
}

func matchContextScopes(detail catalog.AuthorizationDetail, scopes []string) scopeMatch {
	match := scopeMatch{Status: "authorized", Authorized: []string{}, Requestable: []string{}, Unavailable: []string{}}
	for _, scope := range requestedScopes(scopes) {
		switch {
		case slices.Contains(detail.AuthorizedScopes, scope):
			match.Authorized = append(match.Authorized, scope)
		case slices.Contains(detail.RequestableScopes, scope):
			match.Requestable = append(match.Requestable, scope)
		default:
			match.Unavailable = append(match.Unavailable, scope)
		}
	}
	if len(match.Requestable) > 0 {
		match.Status = "requestable"
	}
	if len(match.Unavailable) > 0 {
		match.Status = "unavailable"
		// An external account can be connected or expanded through approval.
		if detail.AccountAuthorizationStatus != "not_required" {
			match.Status = "account_authorization_required"
		}
	}
	return match
}

func contextMatches(details []catalog.AuthorizationDetail, selected []map[string]any, scopes []string) []contextListItem {
	items := listContexts(details, selected)
	for index, detail := range details {
		match := matchContextScopes(detail, scopes)
		items[index].Match = &match
	}
	return items
}

func summarizeAccessRequest(server catalog.ResourceServer, scopes []string, details []catalog.AuthorizationDetail, selected []map[string]any, source string) accessRequestResult {
	scopes = requestedScopes(scopes)
	result := accessRequestResult{
		Receipt:         access.Receipt{ResourceServer: server.CommandName},
		Context:         selectedContextSummary{Source: source},
		RequestedScopes: scopes,
		Contexts:        contextMatches(details, selected, scopes),
	}
	for _, detail := range details {
		if !sameDetails(detail.AuthorizationDetail, selected) {
			continue
		}
		id, kind := contextIdentity(detail)
		result.Context = selectedContextSummary{ID: id, Name: detail.Name, Type: kind, Source: source}

	}
	return result
}

func (a *App) requestAccess(ctx context.Context, service resourceAccessRequester, server catalog.ResourceServer, scopes []string, details []catalog.AuthorizationDetail, selected []map[string]any, source, reason string, options access.RequestOptions) (accessRequestResult, error) {
	result := summarizeAccessRequest(server, scopes, details, selected, source)
	if printErr := printAccessContext(a.stderr, result); printErr != nil {
		return result, printErr
	}
	var err error
	result.Receipt, err = service.Request(ctx, server, result.RequestedScopes, selected, reason, options)
	if err != nil {
		var responseError *access.ResponseError
		if errors.As(err, &responseError) && json.Valid(responseError.Body) {
			result.Error = append(json.RawMessage(nil), responseError.Body...)
		}
	}
	return result, err
}

func printAccessContext(w io.Writer, result accessRequestResult) error {
	if _, err := fmt.Fprintf(w, "Resource Server: %s\nSelection source: %s\nRequested scopes: %s\n",
		result.ResourceServer, result.Context.Source, strings.Join(result.RequestedScopes, ", ")); err != nil {
		return err
	}
	if result.Context.Name != "" {
		if _, err := fmt.Fprintf(w, "Context: %s (%s)\n", result.Context.Name, result.Context.Type); err != nil {
			return err
		}
	}
	if result.Context.ID != "" {
		if _, err := fmt.Fprintf(w, "Context ID: %s\n", result.Context.ID); err != nil {
			return err
		}
	}
	if len(result.Contexts) == 0 {
		return nil
	}
	return printContextRows(w, result.Contexts)
}

func printContextRows(w io.Writer, items []contextListItem) error {
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "CURRENT\tID\tNAME\tTYPE\tACCOUNT\tAUTHORIZED\tREQUESTABLE\tMATCH")
	for _, item := range items {
		current, match := "", ""
		if item.Current {
			current = "*"
		}
		if item.Match != nil {
			match = item.Match.Status
			if len(item.Match.Unavailable) > 0 {
				match += ": " + strings.Join(item.Match.Unavailable, ", ")
			}
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\n", current, item.ID, item.Name, item.Type, item.AccountAuthorizationStatus, item.AuthorizedScopeCount, item.RequestableScopeCount, match)
	}
	return table.Flush()
}

package cli

import (
	"sort"
	"strings"
	"unicode"

	"github.com/realmroot/toolbox/internal/catalog"
	restish "github.com/saltbo/restish/v2"
)

const (
	maxExpandedOperations    = 50
	maxExpandedScopes        = 30
	maxExpandedAuthorization = 30
	maxExpandedRows          = 150
	maxDiscoveryResults      = 50
	maxDiscoveryOutputBytes  = 16_000
	overviewModeExpanded     = "expanded"
	overviewModeCompact      = "compact"
	overviewModeFiltered     = "filtered"
)

type discoveryOptions struct {
	Search string
	Scope  string
	All    bool
}

func (o discoveryOptions) active() bool {
	return o.Search != "" || o.Scope != "" || o.All
}

type resourceServerSummary struct {
	ID               string   `json:"id"`
	CommandName      string   `json:"commandName"`
	Identifier       string   `json:"identifier"`
	Name             string   `json:"name"`
	Description      string   `json:"description,omitempty"`
	ResourceURL      string   `json:"resourceUrl"`
	Available        bool     `json:"available"`
	ConnectionStatus string   `json:"connectionStatus"`
	AuthorizedScopes []string `json:"authorizedScopes,omitempty"`
	ScopeCount       int      `json:"scopeCount"`
}

type resourceServerOverview struct {
	ResourceServer           resourceServerSummary         `json:"resourceServer"`
	Mode                     string                        `json:"mode"`
	ScopeCount               int                           `json:"-"`
	AuthorizationDetailCount int                           `json:"authorizationDetailCount"`
	OperationCount           int                           `json:"operationCount"`
	Search                   string                        `json:"search,omitempty"`
	Scope                    string                        `json:"scope,omitempty"`
	MatchCount               int                           `json:"matchCount,omitempty"`
	Truncated                bool                          `json:"truncated,omitempty"`
	Scopes                   []catalog.Scope               `json:"scopes,omitempty"`
	AuthorizationDetails     []catalog.AuthorizationDetail `json:"authorizationDetails,omitempty"`
	Operations               []restish.OperationInspection `json:"operations,omitempty"`
}

func summarizeResourceServers(servers []catalog.ResourceServer) []resourceServerSummary {
	result := make([]resourceServerSummary, 0, len(servers))
	for _, server := range servers {
		result = append(result, summarizeResourceServer(server))
	}
	return result
}

func summarizeResourceServer(server catalog.ResourceServer) resourceServerSummary {
	return resourceServerSummary{
		ID: server.ID, CommandName: server.CommandName, Identifier: server.Identifier, Name: server.Name,
		Description: server.Description, ResourceURL: server.ResourceURL, Available: server.Available,
		ConnectionStatus: server.ConnectionStatus, AuthorizedScopes: append([]string(nil), server.ConnectionScopes...),
		ScopeCount: len(server.Scopes),
	}
}

func buildResourceServerOverview(server catalog.ResourceServer, details []catalog.AuthorizationDetail, operations []restish.OperationInspection, options discoveryOptions) resourceServerOverview {
	overview := resourceServerOverview{
		ResourceServer: summarizeResourceServer(server), ScopeCount: len(server.Scopes),
		AuthorizationDetailCount: len(details), OperationCount: len(operations), Search: options.Search, Scope: options.Scope,
	}
	if options.Search != "" || options.Scope != "" {
		overview.Mode = overviewModeFiltered
		matched := filterOperations(operations, options)
		overview.MatchCount = len(matched)
		if !options.All {
			matched, overview.Truncated = limitDiscoveryOperations(matched)
		}
		overview.Operations = matched
		return overview
	}
	if !options.All && resourceServerInventoryIsLarge(server, details, operations) {
		overview.Mode = overviewModeCompact
		return overview
	}
	overview.Mode = overviewModeExpanded
	overview.Scopes = append([]catalog.Scope(nil), server.Scopes...)
	overview.AuthorizationDetails = append([]catalog.AuthorizationDetail(nil), details...)
	overview.Operations = append([]restish.OperationInspection(nil), operations...)
	return overview
}

func resourceServerInventoryIsLarge(server catalog.ResourceServer, details []catalog.AuthorizationDetail, operations []restish.OperationInspection) bool {
	estimatedRows := 12 + len(server.Scopes) + 4*len(details) + len(operations)
	return len(operations) > maxExpandedOperations || len(server.Scopes) > maxExpandedScopes ||
		len(details) > maxExpandedAuthorization || estimatedRows > maxExpandedRows
}

func filterOperations(operations []restish.OperationInspection, options discoveryOptions) []restish.OperationInspection {
	tokens := strings.Fields(strings.ToLower(options.Search))
	result := make([]restish.OperationInspection, 0)
	for _, operation := range operations {
		if options.Scope != "" && !operationRequiresScope(operation, options.Scope) {
			continue
		}
		if operationMatchesSearch(operation, tokens) {
			result = append(result, operation)
		}
	}
	if len(tokens) > 0 {
		sort.SliceStable(result, func(left, right int) bool {
			return operationSearchScore(result[left], tokens) > operationSearchScore(result[right], tokens)
		})
	}
	return result
}

func operationSearchScore(operation restish.OperationInspection, tokens []string) int {
	query := normalizeDiscoveryText(strings.Join(tokens, " "))
	fields := []struct {
		value string
		base  int
	}{
		{operation.Summary, 500},
		{strings.Join(operation.Command, " "), 400},
		{operation.ID, 300},
		{operation.Path, 200},
		{operation.Method, 100},
	}
	best := 0
	for _, field := range fields {
		normalized := normalizeDiscoveryText(field.value)
		score := 0
		switch {
		case normalized == query:
			score = field.base + 30
		case strings.Contains(normalized, query):
			score = field.base + 20
		default:
			matched := true
			for _, token := range tokens {
				if !strings.Contains(normalized, normalizeDiscoveryText(token)) {
					matched = false
					break
				}
			}
			if matched {
				score = field.base + 10
			}
		}
		if score > best {
			best = score
		}
	}
	return best
}

func operationMatchesSearch(operation restish.OperationInspection, tokens []string) bool {
	if len(tokens) == 0 {
		return true
	}
	fields := []string{operation.ID, strings.Join(operation.Command, " "), operation.Method, operation.Path, operation.Summary}
	for _, field := range fields {
		normalized := normalizeDiscoveryText(field)
		matched := true
		for _, token := range tokens {
			if !strings.Contains(normalized, normalizeDiscoveryText(token)) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func normalizeDiscoveryText(value string) string {
	return strings.Join(strings.Fields(strings.Map(func(character rune) rune {
		if unicode.IsLetter(character) || unicode.IsNumber(character) {
			return unicode.ToLower(character)
		}
		return ' '
	}, value)), " ")
}

func limitDiscoveryOperations(operations []restish.OperationInspection) ([]restish.OperationInspection, bool) {
	used := 0
	for index, operation := range operations {
		size := len(operation.ID) + len(strings.Join(operation.Command, " ")) + len(operation.Method) +
			len(operation.Path) + len(operation.Summary) + len(operationScopeSummary(operation))
		if index >= maxDiscoveryResults || (index > 0 && used+size > maxDiscoveryOutputBytes) {
			return operations[:index], true
		}
		used += size
	}
	return operations, false
}

func operationRequiresScope(operation restish.OperationInspection, scope string) bool {
	for _, alternative := range operation.CredentialAlternatives {
		for _, requirement := range alternative {
			for _, need := range requirement.Needs {
				if need == scope {
					return true
				}
			}
		}
	}
	return false
}

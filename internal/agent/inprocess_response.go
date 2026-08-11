package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	restish "github.com/saltbo/restish/v2"
)

// NewInteractiveResponseMiddleware handles profiled controller interactions
// for any Resource Server without knowing its endpoint names.
func NewInteractiveResponseMiddleware(
	runtime *restish.CLI,
	open func(string) error,
	diagnostics io.Writer,
	noBrowser bool,
	profileName string,
) restish.ResponseMiddleware {
	if profileName == "" {
		profileName = "default"
	}
	return func(ctx context.Context, request *http.Request, response *restish.Response) (restish.ResponseMiddlewareResult, error) {
		if response.Status < 200 || response.Status >= 300 || !hasProfile(response.Headers, interactiveResourceProfile) {
			return restish.ResponseMiddlewareResult{}, nil
		}
		resource, err := decodeHookBody[interactiveResponse](response.Body)
		if err != nil {
			return restish.ResponseMiddlewareResult{}, fmt.Errorf("decode interactive Resource: %w", err)
		}
		origin, err := interactionOrigin(request.URL.String())
		if err != nil {
			return restish.ResponseMiddlewareResult{}, err
		}
		current := response
		opened := false
		approvalURL := resource.Interaction.URL
		expiresAt := resource.Interaction.ExpiresAt
		for {
			switch resource.Interaction.Status {
			case "completed":
				return restish.ResponseMiddlewareResult{Response: current}, nil
			case "denied", "expired", "failed":
				return restish.ResponseMiddlewareResult{}, fmt.Errorf("controller interaction %s", resource.Interaction.Status)
			case "pending":
			default:
				return restish.ResponseMiddlewareResult{}, fmt.Errorf("interactive Resource returned unsupported status %q", resource.Interaction.Status)
			}
			if resource.Interaction.URL != "" {
				approvalURL = resource.Interaction.URL
			}
			if resource.Interaction.ExpiresAt != nil {
				expiresAt = resource.Interaction.ExpiresAt
			}
			if resource.Interaction.Type != "user-approval" || resource.Links.Self == "" || approvalURL == "" || expiresAt == nil {
				return restish.ResponseMiddlewareResult{}, errors.New("pending interactive Resource is missing its self link, approval URL, expiry, or interaction type")
			}
			if !sameOrigin(resource.Links.Self, origin) || !sameOrigin(approvalURL, origin) {
				return restish.ResponseMiddlewareResult{}, errors.New("interactive Resource links must use the Resource Server origin")
			}
			if !opened {
				if noBrowser {
					fmt.Fprintln(diagnostics, "Approval URL:\n"+approvalURL)
				} else if err := open(approvalURL); err != nil {
					return restish.ResponseMiddlewareResult{}, fmt.Errorf("open controller interaction: %w", err)
				}
				fmt.Fprintln(diagnostics, "Waiting for controller approval...")
				opened = true
			}
			if !time.Now().Before(*expiresAt) {
				return restish.ResponseMiddlewareResult{}, errors.New("controller interaction expired; invoke the request again")
			}
			timer := time.NewTimer(retryAfter(response.Headers))
			select {
			case <-ctx.Done():
				timer.Stop()
				return restish.ResponseMiddlewareResult{}, ctx.Err()
			case <-timer.C:
			}
			polled, err := runtime.FetchResponse(ctx, http.MethodGet, resource.Links.Self, profileName, nil)
			if err != nil {
				return restish.ResponseMiddlewareResult{}, fmt.Errorf("poll interactive Resource: %w", err)
			}
			if polled.Status < 200 || polled.Status >= 300 {
				return restish.ResponseMiddlewareResult{}, fmt.Errorf("poll interactive Resource: HTTP %d", polled.Status)
			}
			resource, err = decodeHookBody[interactiveResponse](polled.Body)
			if err != nil {
				return restish.ResponseMiddlewareResult{}, fmt.Errorf("decode polled interactive Resource: %w", err)
			}
			current = polled
		}
	}
}

func interactionOrigin(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("interactive Resource request URL is invalid")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

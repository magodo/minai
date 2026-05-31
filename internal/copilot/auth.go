// Package copilot implements a minimal GitHub Copilot chat client.
//
// GitHub Copilot has no public REST API. The official VS Code / Neovim
// plugins obtain a long-lived OAuth token, then exchange it at
// api.github.com/copilot_internal/v2/token for a short-lived API token plus
// an endpoint URL.
//
// To keep minai minimal we do NOT implement the exchange ourselves. The user
// supplies a pre-issued API token via the MINAI_COPILOT_TOKEN env var (and
// optionally MINAI_COPILOT_ENDPOINT, defaulting to
// https://api.githubcopilot.com). Refresh the token via whatever tool
// produced it (e.g. the official Copilot CLI, an editor extension, or a
// proxy like litellm).
package copilot

import (
	"errors"
	"os"
)

// APIToken is the credential used as the Bearer for chat completions.
type APIToken struct {
	Token    string
	Endpoint string
}

// Auth resolves the API token from the environment.
type Auth struct {
	token APIToken
}

const defaultEndpoint = "https://api.githubcopilot.com"

// NewAuth reads MINAI_COPILOT_TOKEN (required) and MINAI_COPILOT_ENDPOINT
// (optional). It returns an error if the token is missing so configuration
// problems surface before the first chat call.
func NewAuth() (*Auth, error) {
	tok := os.Getenv("MINAI_COPILOT_TOKEN")
	if tok == "" {
		return nil, errors.New("MINAI_COPILOT_TOKEN is not set; export a Copilot API token (Bearer) before running minai")
	}
	ep := os.Getenv("MINAI_COPILOT_ENDPOINT")
	if ep == "" {
		ep = defaultEndpoint
	}
	return &Auth{token: APIToken{Token: tok, Endpoint: ep}}, nil
}

// Token returns the configured API token. The error return is preserved for
// API symmetry with refreshing implementations.
func (a *Auth) Token() (*APIToken, error) {
	return &a.token, nil
}

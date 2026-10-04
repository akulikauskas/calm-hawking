package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// TokenOutput holds the authentication tokens and metadata retrieved from Dex.
type TokenOutput struct {
	IDToken      string                 `json:"id_token"`
	AccessToken  string                 `json:"access_token,omitempty"`
	RefreshToken string                 `json:"refresh_token,omitempty"`
	TokenType    string                 `json:"token_type,omitempty"`
	ExpiresIn    int64                  `json:"expires_in,omitempty"`
	Expiry       time.Time              `json:"expiry,omitempty"`
	Claims       map[string]interface{} `json:"claims,omitempty"`
}

// formatOutput formats the token result according to the requested format:
// - "id_token", "jwt", "raw": Raw JWT string
// - "access_token": Raw access token
// - "refresh_token": Raw refresh token
// - "claims": Formatted JSON of the claims inside the ID Token
// - "json": Full JSON containing tokens and claims
func formatOutput(res *TokenOutput, format string) (string, error) {
	switch strings.ToLower(format) {
	case "", "id_token", "jwt", "raw":
		if res.IDToken == "" {
			return "", fmt.Errorf("no id_token found in response")
		}
		return res.IDToken, nil

	case "access_token":
		if res.AccessToken == "" {
			return "", fmt.Errorf("no access_token found in response")
		}
		return res.AccessToken, nil

	case "refresh_token":
		if res.RefreshToken == "" {
			return "", fmt.Errorf("no refresh_token found in response (did you request offline_access scope?)")
		}
		return res.RefreshToken, nil

	case "claims":
		if len(res.Claims) == 0 {
			// Try decoding raw ID token payload if claims not populated
			claims, err := parseUnverifiedClaims(res.IDToken)
			if err != nil {
				return "", fmt.Errorf("failed to parse claims from id_token: %w", err)
			}
			res.Claims = claims
		}
		b, err := json.MarshalIndent(res.Claims, "", "  ")
		if err != nil {
			return "", fmt.Errorf("failed to marshal claims: %w", err)
		}
		return string(b), nil

	case "json":
		b, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return "", fmt.Errorf("failed to marshal token output to json: %w", err)
		}
		return string(b), nil

	default:
		return "", fmt.Errorf("unsupported output format %q (allowed: id_token, jwt, raw, access_token, refresh_token, claims, json)", format)
	}
}

// parseUnverifiedClaims extracts the JSON claims payload from a JWT without signature verification.
// Note: Verification should be performed prior to this using OIDC verifier.
func parseUnverifiedClaims(jwtToken string) (map[string]interface{}, error) {
	parts := strings.Split(jwtToken, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid jwt format")
	}
	payloadSegment := parts[1]
	// Handle unpadded base64url encoding
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadSegment)
	if err != nil {
		// Fallback to standard base64 if needed
		payloadBytes, err = base64.URLEncoding.DecodeString(payloadSegment)
		if err != nil {
			return nil, fmt.Errorf("failed to base64-decode jwt payload: %w", err)
		}
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse jwt json payload: %w", err)
	}
	return claims, nil
}

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// AuthConfig contains configuration for the OIDC authorization flow.
type AuthConfig struct {
	DexURL            string
	ClientID          string
	ClientSecret      string
	RedirectURL       string
	Scopes            []string
	InsecureSkipTLS   bool
	UsePKCE           bool
	SkipClientIDCheck bool
}

// AuthSession holds the live state for an ongoing authentication request.
type AuthSession struct {
	Config       AuthConfig
	State        string
	Nonce        string
	CodeVerifier string
	AuthURL      string
	OAuth2Config *oauth2.Config
	Verifier     *oidc.IDTokenVerifier
	Provider     *oidc.Provider
	HTTPClient   *http.Client
}

// generateSecureRandom creates a cryptographically secure URL-safe random string.
func generateSecureRandom(numBytes int) (string, error) {
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// newHTTPClient creates an HTTP client with optional TLS verification disabling.
func newHTTPClient(insecureSkipTLS bool) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}
	if insecureSkipTLS {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

// InitAuthSession initializes OIDC discovery with Dex and builds the authorization URL.
func InitAuthSession(ctx context.Context, cfg AuthConfig) (*AuthSession, error) {
	client := newHTTPClient(cfg.InsecureSkipTLS)
	ctxWithClient := oidc.ClientContext(ctx, client)

	provider, err := oidc.NewProvider(ctxWithClient, cfg.DexURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider at %q: %w", cfg.DexURL, err)
	}

	state, err := generateSecureRandom(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	nonce, err := generateSecureRandom(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
	}

	session := &AuthSession{
		Config:       cfg,
		State:        state,
		Nonce:        nonce,
		OAuth2Config: oauth2Config,
		Provider:     provider,
		HTTPClient:   client,
	}

	var authOpts []oauth2.AuthCodeOption
	if cfg.UsePKCE {
		verifier := oauth2.GenerateVerifier()
		session.CodeVerifier = verifier
		authOpts = append(authOpts, oauth2.S256ChallengeOption(verifier))
	}
	if nonce != "" {
		authOpts = append(authOpts, oidc.Nonce(nonce))
	}

	session.AuthURL = oauth2Config.AuthCodeURL(state, authOpts...)

	oidcConfig := &oidc.Config{
		ClientID:          cfg.ClientID,
		SkipClientIDCheck: cfg.SkipClientIDCheck,
	}
	session.Verifier = provider.Verifier(oidcConfig)

	return session, nil
}

// Exchange exchanges the authorization code for tokens and verifies the ID Token.
func (s *AuthSession) Exchange(ctx context.Context, code string) (*TokenOutput, error) {
	ctxWithClient := oidc.ClientContext(ctx, s.HTTPClient)

	var exchangeOpts []oauth2.AuthCodeOption
	if s.CodeVerifier != "" {
		exchangeOpts = append(exchangeOpts, oauth2.VerifierOption(s.CodeVerifier))
	}

	oauthToken, err := s.OAuth2Config.Exchange(ctxWithClient, code, exchangeOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code for tokens: %w", err)
	}

	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("Dex did not return an id_token (ensure 'openid' scope is included in requested scopes)")
	}

	idToken, err := s.Verifier.Verify(ctxWithClient, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to decode claims from ID token: %w", err)
	}

	// Verify nonce claim if present
	if s.Nonce != "" {
		if nonceClaim, ok := claims["nonce"].(string); ok && nonceClaim != s.Nonce {
			return nil, fmt.Errorf("nonce mismatch: expected %q, got %q", s.Nonce, nonceClaim)
		}
	}

	expiry := oauthToken.Expiry
	if expiry.IsZero() {
		if expFloat, ok := claims["exp"].(float64); ok {
			expiry = time.Unix(int64(expFloat), 0)
		}
	}

	var expiresIn int64
	if !expiry.IsZero() {
		expiresIn = int64(time.Until(expiry).Seconds())
		if expiresIn < 0 {
			expiresIn = 0
		}
	}

	return &TokenOutput{
		IDToken:      rawIDToken,
		AccessToken:  oauthToken.AccessToken,
		RefreshToken: oauthToken.RefreshToken,
		TokenType:    oauthToken.TokenType,
		ExpiresIn:    expiresIn,
		Expiry:       expiry,
		Claims:       claims,
	}, nil
}

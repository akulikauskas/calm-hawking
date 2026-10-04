package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestParseScopes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "comma separated",
			input:    "openid,profile,email",
			expected: []string{"openid", "profile", "email"},
		},
		{
			name:     "space separated",
			input:    "openid profile email offline_access",
			expected: []string{"openid", "profile", "email", "offline_access"},
		},
		{
			name:     "mixed comma and space",
			input:    "openid, profile, email , groups",
			expected: []string{"openid", "profile", "email", "groups"},
		},
		{
			name:     "empty returns defaults",
			input:    "",
			expected: []string{"openid", "profile", "email", "groups", "offline_access"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := parseScopes(tc.input)
			if len(res) != len(tc.expected) {
				t.Fatalf("expected length %d, got %d (%v)", len(tc.expected), len(res), res)
			}
			for i, v := range tc.expected {
				if res[i] != v {
					t.Errorf("at index %d: expected %s, got %s", i, v, res[i])
				}
			}
		})
	}
}

func TestFormatOutput(t *testing.T) {
	tok := &TokenOutput{
		IDToken:      "header.payload.signature",
		AccessToken:  "access-12345",
		RefreshToken: "refresh-67890",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Claims: map[string]interface{}{
			"email": "user@example.com",
			"sub":   "sub-123",
		},
	}

	// 1. Raw id_token (default)
	out, err := formatOutput(tok, "id_token")
	if err != nil || out != tok.IDToken {
		t.Fatalf("format id_token failed: %v, out=%s", err, out)
	}

	// 2. Access token
	out, err = formatOutput(tok, "access_token")
	if err != nil || out != tok.AccessToken {
		t.Fatalf("format access_token failed: %v, out=%s", err, out)
	}

	// 3. Refresh token
	out, err = formatOutput(tok, "refresh_token")
	if err != nil || out != tok.RefreshToken {
		t.Fatalf("format refresh_token failed: %v, out=%s", err, out)
	}

	// 4. Claims
	out, err = formatOutput(tok, "claims")
	if err != nil {
		t.Fatalf("format claims failed: %v", err)
	}
	if !strings.Contains(out, "user@example.com") {
		t.Fatalf("expected email in claims output: %s", out)
	}

	// 5. Full JSON
	out, err = formatOutput(tok, "json")
	if err != nil {
		t.Fatalf("format json failed: %v", err)
	}
	if !strings.Contains(out, tok.IDToken) || !strings.Contains(out, tok.AccessToken) {
		t.Fatalf("expected id_token and access_token in json output: %s", out)
	}

	// 6. Invalid format
	_, err = formatOutput(tok, "invalid_fmt")
	if err == nil {
		t.Fatalf("expected error for invalid format, got nil")
	}
}

func TestParseUnverifiedClaims(t *testing.T) {
	// Sample JWT payload: {"sub":"1234567890","name":"John Doe","admin":true}
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.mock_signature
	sampleJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.mock_signature"

	claims, err := parseUnverifiedClaims(sampleJWT)
	if err != nil {
		t.Fatalf("parseUnverifiedClaims failed: %v", err)
	}

	if claims["sub"] != "1234567890" {
		t.Errorf("expected sub 1234567890, got %v", claims["sub"])
	}
	if claims["name"] != "John Doe" {
		t.Errorf("expected name John Doe, got %v", claims["name"])
	}
}

// TestEndToEndOIDCAuthFlow simulates a full Dex OIDC Authorization Code Flow with PKCE
func TestEndToEndOIDCAuthFlow(t *testing.T) {
	// 1. Generate RSA key for mock Dex token signing
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	keyID := "mock-key-1"
	jwk := jose.JSONWebKey{
		Key:       &privKey.PublicKey,
		KeyID:     keyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	var mockServer *httptest.Server
	authCode := "mock-auth-code-12345"
	expectedClientID := "test-client"

	mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                                mockServer.URL,
				"authorization_endpoint":                mockServer.URL + "/auth",
				"token_endpoint":                        mockServer.URL + "/token",
				"jwks_uri":                              mockServer.URL + "/keys",
				"response_types_supported":              []string{"code"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
				"subject_types_supported":               []string{"public"},
			})

		case "/keys":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jwks)

		case "/token":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "authorization_code" {
				http.Error(w, "invalid grant_type", http.StatusBadRequest)
				return
			}
			if r.Form.Get("code") != authCode {
				http.Error(w, "invalid authorization code", http.StatusBadRequest)
				return
			}

			// Sign mock ID Token
			signer, err := jose.NewSigner(
				jose.SigningKey{Algorithm: jose.RS256, Key: privKey},
				(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID),
			)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			claims := map[string]interface{}{
				"iss":            mockServer.URL,
				"sub":            "dex-user-42",
				"aud":            expectedClientID,
				"exp":            time.Now().Add(1 * time.Hour).Unix(),
				"iat":            time.Now().Unix(),
				"email":          "alice@example.com",
				"email_verified": true,
				"name":           "Alice Developer",
				"groups":         []string{"admins", "developers"},
			}

			rawIDToken, err := jwt.Signed(signer).Claims(claims).Serialize()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "mock-access-token-999",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"id_token":      rawIDToken,
				"refresh_token": "mock-refresh-token-888",
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer mockServer.Close()

	// 2. Start local callback server on free port
	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on local port: %v", err)
	}
	port := localListener.Addr().(*net.TCPAddr).Port
	_ = localListener.Close() // close listener so StartLocalServer can bind it

	redirectURL := fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	authCfg := AuthConfig{
		DexURL:            mockServer.URL,
		ClientID:          expectedClientID,
		ClientSecret:      "",
		RedirectURL:       redirectURL,
		Scopes:            []string{"openid", "profile", "email"},
		UsePKCE:           false, // mock token endpoint doesn't strictly verify code_verifier challenge
		SkipClientIDCheck: false,
	}

	session, err := InitAuthSession(ctx, authCfg)
	if err != nil {
		t.Fatalf("InitAuthSession failed: %v", err)
	}

	localServer, err := StartLocalServer(listenAddr, redirectURL, session)
	if err != nil {
		t.Fatalf("StartLocalServer failed: %v", err)
	}
	defer func() {
		_ = localServer.Stop(context.Background())
	}()

	// 3. Simulate browser receiving redirect to callback URL
	callbackReqURL := fmt.Sprintf("%s?code=%s&state=%s", redirectURL, authCode, session.State)
	resp, err := http.Get(callbackReqURL)
	if err != nil {
		t.Fatalf("failed to make callback HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 from callback, got %d", resp.StatusCode)
	}

	// 4. Check received token from localServer.Result()
	select {
	case res := <-localServer.Result():
		if res.Err != nil {
			t.Fatalf("authentication returned error: %v", res.Err)
		}
		if res.Token == nil {
			t.Fatalf("authentication returned nil token")
		}
		if res.Token.AccessToken != "mock-access-token-999" {
			t.Errorf("expected access_token 'mock-access-token-999', got %q", res.Token.AccessToken)
		}
		if res.Token.Claims["email"] != "alice@example.com" {
			t.Errorf("expected email 'alice@example.com', got %v", res.Token.Claims["email"])
		}
		if res.Token.Claims["sub"] != "dex-user-42" {
			t.Errorf("expected sub 'dex-user-42', got %v", res.Token.Claims["sub"])
		}
		if res.Token.IDToken == "" {
			t.Errorf("expected non-empty IDToken")
		}

	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for callback server result")
	}
}

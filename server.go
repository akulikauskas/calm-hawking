package main

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ServerResult encapsulates the result of the web server callback.
type ServerResult struct {
	Token *TokenOutput
	Err   error
}

// LocalServer handles the local HTTP redirect callback from Dex.
type LocalServer struct {
	server      *http.Server
	listener    net.Listener
	redirectURL string
	session     *AuthSession
	resultChan  chan ServerResult
	shutdownOnce sync.Once
}

type pageData struct {
	Success     bool
	Title       string
	Message     string
	ErrorDetail string
	User        string
	Issuer      string
	ClientID    string
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}} - Dex CLI</title>
  <style>
    :root {
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --text: #0f172a;
      --text-muted: #64748b;
      --border: #e2e8f0;
      --success: #10b981;
      --success-light: #ecfdf5;
      --error: #ef4444;
      --error-light: #fef2f2;
      --primary: #2563eb;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #090d16;
        --card-bg: #131c2e;
        --text: #f1f5f9;
        --text-muted: #94a3b8;
        --border: #1e293b;
        --success: #34d399;
        --success-light: #064e3b33;
        --error: #f87171;
        --error-light: #7f1d1d33;
        --primary: #3b82f6;
      }
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      padding: 1.5rem;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 16px;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05), 0 8px 10px -6px rgba(0, 0, 0, 0.02);
      max-width: 480px;
      width: 100%;
      padding: 2.5rem 2rem;
      text-align: center;
    }
    .icon-container {
      width: 72px;
      height: 72px;
      border-radius: 50%;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 1.5rem;
    }
    .icon-success {
      background-color: var(--success-light);
      color: var(--success);
    }
    .icon-error {
      background-color: var(--error-light);
      color: var(--error);
    }
    .icon-container svg {
      width: 40px;
      height: 40px;
    }
    h1 {
      font-size: 1.5rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
    }
    p.message {
      color: var(--text-muted);
      font-size: 0.975rem;
      line-height: 1.5;
      margin-bottom: 1.5rem;
    }
    .details {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      margin-bottom: 1.5rem;
      text-align: left;
      font-size: 0.875rem;
    }
    .detail-row {
      display: flex;
      justify-content: space-between;
      padding: 0.35rem 0;
      word-break: break-all;
    }
    .detail-label {
      color: var(--text-muted);
      font-weight: 500;
      margin-right: 1rem;
      white-space: nowrap;
    }
    .detail-val {
      font-weight: 600;
    }
    .error-box {
      background: var(--error-light);
      color: var(--error);
      border: 1px solid var(--error);
      border-radius: 8px;
      padding: 0.875rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
      margin-bottom: 1.5rem;
      word-break: break-all;
      text-align: left;
    }
    .close-btn {
      display: inline-block;
      width: 100%;
      padding: 0.75rem 1.5rem;
      border-radius: 8px;
      border: none;
      background-color: var(--primary);
      color: white;
      font-size: 0.95rem;
      font-weight: 600;
      cursor: pointer;
      transition: opacity 0.2s;
    }
    .close-btn:hover {
      opacity: 0.9;
    }
    .hint {
      margin-top: 1rem;
      font-size: 0.8rem;
      color: var(--text-muted);
    }
  </style>
</head>
<body>
  <div class="card">
    {{if .Success}}
      <div class="icon-container icon-success">
        <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
        </svg>
      </div>
      <h1>{{.Title}}</h1>
      <p class="message">{{.Message}}</p>

      <div class="details">
        {{if .User}}
        <div class="detail-row">
          <span class="detail-label">Authenticated As</span>
          <span class="detail-val">{{.User}}</span>
        </div>
        {{end}}
        <div class="detail-row">
          <span class="detail-label">Client ID</span>
          <span class="detail-val">{{.ClientID}}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Issuer</span>
          <span class="detail-val">{{.Issuer}}</span>
        </div>
      </div>

      <button class="close-btn" onclick="window.close()">Close Window</button>
      <p class="hint">You can safely close this window and return to your terminal.</p>
    {{else}}
      <div class="icon-container icon-error">
        <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
        </svg>
      </div>
      <h1>{{.Title}}</h1>
      <p class="message">{{.Message}}</p>

      {{if .ErrorDetail}}
      <div class="error-box">{{.ErrorDetail}}</div>
      {{end}}

      <button class="close-btn" onclick="window.close()">Close Window</button>
      <p class="hint">Check terminal output for detailed error logs.</p>
    {{end}}
  </div>
  <script>
    // Automatically try to close window after 4 seconds
    setTimeout(function() {
      window.close();
    }, 4000);
  </script>
</body>
</html>`

var parsedTemplate = template.Must(template.New("callback").Parse(htmlTemplate))

// StartLocalServer binds to the address and starts listening for OAuth callbacks.
func StartLocalServer(listenAddr string, redirectURLStr string, session *AuthSession) (*LocalServer, error) {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind address %s: %w", listenAddr, err)
	}

	ls := &LocalServer{
		listener:    listener,
		redirectURL: redirectURLStr,
		session:     session,
		resultChan:  make(chan ServerResult, 1),
	}

	mux := http.NewServeMux()

	parsedURL, err := url.Parse(redirectURLStr)
	callbackPath := "/callback"
	if err == nil && parsedURL.Path != "" {
		callbackPath = parsedURL.Path
	}

	mux.HandleFunc(callbackPath, ls.handleCallback)
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	ls.server = &http.Server{
		Handler: mux,
	}

	go func() {
		if serveErr := ls.server.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
			ls.resultChan <- ServerResult{Err: fmt.Errorf("server error: %w", serveErr)}
		}
	}()

	return ls, nil
}

// Result returns the channel for receiving the authentication outcome.
func (ls *LocalServer) Result() <-chan ServerResult {
	return ls.resultChan
}

// Addr returns the listener address (useful when dynamic port 0 is used).
func (ls *LocalServer) Addr() net.Addr {
	return ls.listener.Addr()
}

// Stop gracefully shuts down the local web server.
func (ls *LocalServer) Stop(ctx context.Context) error {
	var err error
	ls.shutdownOnce.Do(func() {
		err = ls.server.Shutdown(ctx)
	})
	return err
}

func (ls *LocalServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// 1. Handle error response from Dex
	if errParam := query.Get("error"); errParam != "" {
		errDesc := query.Get("error_description")
		if errDesc == "" {
			errDesc = "Authentication was cancelled or rejected by Dex."
		}
		data := pageData{
			Success:     false,
			Title:       "Authentication Failed",
			Message:     "Dex returned an authorization error.",
			ErrorDetail: fmt.Sprintf("%s: %s", errParam, errDesc),
		}
		w.WriteHeader(http.StatusUnauthorized)
		_ = parsedTemplate.Execute(w, data)

		ls.resultChan <- ServerResult{
			Err: fmt.Errorf("OIDC error from Dex: %s (%s)", errParam, errDesc),
		}
		ls.scheduleShutdown()
		return
	}

	// 2. Validate state to protect against CSRF attacks
	stateParam := query.Get("state")
	if stateParam == "" || stateParam != ls.session.State {
		data := pageData{
			Success:     false,
			Title:       "Invalid State Parameter",
			Message:     "State parameter mismatch. This could indicate a CSRF attack or an expired session.",
			ErrorDetail: "state mismatch",
		}
		w.WriteHeader(http.StatusBadRequest)
		_ = parsedTemplate.Execute(w, data)

		ls.resultChan <- ServerResult{
			Err: fmt.Errorf("state validation failed: received %q, expected %q", stateParam, ls.session.State),
		}
		ls.scheduleShutdown()
		return
	}

	// 3. Extract authorization code
	code := query.Get("code")
	if code == "" {
		data := pageData{
			Success:     false,
			Title:       "Missing Code Parameter",
			Message:     "No authorization code was found in the callback request.",
			ErrorDetail: "missing 'code' query parameter",
		}
		w.WriteHeader(http.StatusBadRequest)
		_ = parsedTemplate.Execute(w, data)

		ls.resultChan <- ServerResult{
			Err: fmt.Errorf("authorization code missing from callback URL"),
		}
		ls.scheduleShutdown()
		return
	}

	// 4. Exchange code for tokens
	tokenRes, err := ls.session.Exchange(r.Context(), code)
	if err != nil {
		data := pageData{
			Success:     false,
			Title:       "Token Exchange Failed",
			Message:     "Failed to exchange authorization code for tokens.",
			ErrorDetail: err.Error(),
		}
		w.WriteHeader(http.StatusInternalServerError)
		_ = parsedTemplate.Execute(w, data)

		ls.resultChan <- ServerResult{
			Err: fmt.Errorf("token exchange failed: %w", err),
		}
		ls.scheduleShutdown()
		return
	}

	// 5. Successful authentication
	userIdent := ""
	if email, ok := tokenRes.Claims["email"].(string); ok && email != "" {
		userIdent = email
	} else if name, ok := tokenRes.Claims["name"].(string); ok && name != "" {
		userIdent = name
	} else if sub, ok := tokenRes.Claims["sub"].(string); ok && sub != "" {
		userIdent = sub
	}

	data := pageData{
		Success:  true,
		Title:    "Authentication Successful!",
		Message:  "Dex JWT token retrieved successfully.",
		User:     userIdent,
		Issuer:   ls.session.Config.DexURL,
		ClientID: ls.session.Config.ClientID,
	}

	w.WriteHeader(http.StatusOK)
	_ = parsedTemplate.Execute(w, data)

	// Flush response bytes to browser before shutting down
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	ls.resultChan <- ServerResult{Token: tokenRes}
	ls.scheduleShutdown()
}

func (ls *LocalServer) scheduleShutdown() {
	go func() {
		// Small delay to allow the browser to completely read the HTTP response
		time.Sleep(300 * time.Millisecond)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = ls.Stop(shutdownCtx)
	}()
}

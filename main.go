package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var version = "1.0.0"

func logf(quiet bool, format string, a ...interface{}) {
	if !quiet {
		fmt.Fprintf(os.Stderr, "[dex-cli] "+format+"\n", a...)
	}
}

func parseScopes(raw string) []string {
	var scopes []string
	// Allow comma or space separated
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' '
	})
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			scopes = append(scopes, trimmed)
		}
	}
	if len(scopes) == 0 {
		return []string{"openid", "profile", "email", "groups", "offline_access"}
	}
	return scopes
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `dex-cli - Retrieve Dex OIDC JWT tokens via CLI

USAGE:
  dex-cli [flags] <DEX_URL>
  dex-cli -dex-url <DEX_URL> [flags]

EXAMPLES:
  # Retrieve ID Token (JWT) from local Dex instance
  dex-cli http://127.0.0.1:5556/dex

  # Store JWT in an environment variable cleanly
  export TOKEN=$(dex-cli http://127.0.0.1:5556/dex)

  # Custom client ID, port and custom redirect URL
  dex-cli -client-id my-app -port 8080 http://127.0.0.1:5556/dex

  # Output decoded claims as formatted JSON
  dex-cli -output claims http://127.0.0.1:5556/dex

  # Run headless / remote (do not launch browser, print URL only)
  dex-cli -no-browser http://127.0.0.1:5556/dex

FLAGS:
`)
	flag.PrintDefaults()
}

func main() {
	var (
		dexURLFlag        string
		clientID          string
		clientSecret      string
		listenAddr        string
		redirectURL       string
		port              int
		scopesRaw         string
		noBrowser         bool
		noPKCE            bool
		outputFormat      string
		timeout           time.Duration
		insecureSkipTLS   bool
		skipClientIDCheck bool
		quiet             bool
		showVersion       bool
	)

	flag.StringVar(&dexURLFlag, "dex-url", "", "Dex issuer URL (e.g. http://127.0.0.1:5556/dex)")
	flag.StringVar(&clientID, "client-id", "example-app", "OAuth2 Client ID registered in Dex")
	flag.StringVar(&clientSecret, "client-secret", "", "OAuth2 Client Secret (optional, or set DEX_CLIENT_SECRET env)")
	flag.StringVar(&listenAddr, "listen", "", "Local HTTP server bind address (default 127.0.0.1:<port>)")
	flag.StringVar(&redirectURL, "redirect-url", "", "OAuth2 redirect URI (default http://127.0.0.1:<port>/callback)")
	flag.IntVar(&port, "port", 5555, "Local HTTP server port (overridden if -redirect-url contains a port)")
	flag.StringVar(&scopesRaw, "scopes", "openid,profile,email,groups,offline_access", "Comma or space-separated list of scopes")
	flag.BoolVar(&noBrowser, "no-browser", false, "Do not open the browser automatically; print auth URL to stderr")
	flag.BoolVar(&noPKCE, "no-pkce", false, "Disable PKCE (Proof Key for Code Exchange)")
	flag.StringVar(&outputFormat, "output", "id_token", "Output format: id_token (raw JWT), access_token, refresh_token, claims, json")
	flag.StringVar(&outputFormat, "o", "id_token", "Short alias for -output")
	flag.DurationVar(&timeout, "timeout", 5*time.Minute, "Maximum time to wait for authentication flow")
	flag.BoolVar(&insecureSkipTLS, "insecure-skip-tls-verify", false, "Skip TLS certificate verification for Dex")
	flag.BoolVar(&skipClientIDCheck, "skip-client-id-check", false, "Skip ID token audience check against client ID")
	flag.BoolVar(&quiet, "quiet", false, "Suppress informational log output on stderr")
	flag.BoolVar(&quiet, "q", false, "Short alias for -quiet")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")
	flag.BoolVar(&showVersion, "v", false, "Short alias for -version")

	flag.Usage = printUsage
	flag.Parse()

	if showVersion {
		fmt.Printf("dex-cli version %s\n", version)
		os.Exit(0)
	}

	// Resolve Dex URL from flag or positional argument
	dexURL := strings.TrimSpace(dexURLFlag)
	if dexURL == "" && flag.NArg() > 0 {
		dexURL = strings.TrimSpace(flag.Arg(0))
	}

	if dexURL == "" {
		fmt.Fprintf(os.Stderr, "Error: Dex URL is required.\n\n")
		printUsage()
		os.Exit(1)
	}

	// Read client secret from environment variable if not passed as flag
	if clientSecret == "" {
		clientSecret = os.Getenv("DEX_CLIENT_SECRET")
	}

	scopes := parseScopes(scopesRaw)

	// Determine redirect URL and listen address
	if redirectURL != "" {
		parsedRedirect, err := url.Parse(redirectURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid -redirect-url: %v\n", err)
			os.Exit(1)
		}
		if listenAddr == "" {
			host := parsedRedirect.Hostname()
			if host == "localhost" || host == "" {
				host = "127.0.0.1"
			}
			p := parsedRedirect.Port()
			if p == "" {
				if parsedRedirect.Scheme == "https" {
					p = "443"
				} else {
					p = "80"
				}
			}
			listenAddr = fmt.Sprintf("%s:%s", host, p)
		}
	} else {
		// Use port to construct listen address and redirect URL
		if listenAddr == "" {
			listenAddr = fmt.Sprintf("127.0.0.1:%d", port)
		}
		redirectURL = fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	authCtx, cancelAuth := context.WithTimeout(ctx, timeout)
	defer cancelAuth()

	logf(quiet, "Discovering Dex provider at %s ...", dexURL)

	authCfg := AuthConfig{
		DexURL:            dexURL,
		ClientID:          clientID,
		ClientSecret:      clientSecret,
		RedirectURL:       redirectURL,
		Scopes:            scopes,
		InsecureSkipTLS:   insecureSkipTLS,
		UsePKCE:           !noPKCE,
		SkipClientIDCheck: skipClientIDCheck,
	}

	session, err := InitAuthSession(authCtx, authCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing OIDC session: %v\n", err)
		os.Exit(1)
	}

	logf(quiet, "Starting local callback server on %s ...", listenAddr)

	server, err := StartLocalServer(listenAddr, redirectURL, session)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting local web server on %s: %v\n", listenAddr, err)
		fmt.Fprintf(os.Stderr, "Hint: check if port is already in use or specify a different port with -port or -redirect-url\n")
		os.Exit(1)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = server.Stop(shutdownCtx)
	}()

	// If port 0 was passed, update redirect URL with actual bound port
	if tcpAddr, ok := server.Addr().(*net.TCPAddr); ok && port == 0 {
		actualPort := tcpAddr.Port
		actualRedirect := fmt.Sprintf("http://127.0.0.1:%d/callback", actualPort)
		logf(quiet, "Dynamic port allocated: %d (redirect URI: %s)", actualPort, actualRedirect)
	}

	logf(quiet, "Authentication URL:")
	fmt.Fprintf(os.Stderr, "\n  %s\n\n", session.AuthURL)

	if !noBrowser {
		logf(quiet, "Opening system default browser...")
		if err := openBrowser(session.AuthURL); err != nil {
			logf(quiet, "Could not launch browser automatically (%v).", err)
			logf(quiet, "Please open the URL above manually.")
		}
	} else {
		logf(quiet, "Browser launch disabled. Please open the URL above in your browser to sign in.")
	}

	logf(quiet, "Waiting for authentication callback (timeout: %s)...", timeout)

	select {
	case res := <-server.Result():
		if res.Err != nil {
			fmt.Fprintf(os.Stderr, "Authentication failed: %v\n", res.Err)
			os.Exit(1)
		}

		userDisplay := "authenticated"
		if email, ok := res.Token.Claims["email"].(string); ok && email != "" {
			userDisplay = email
		} else if sub, ok := res.Token.Claims["sub"].(string); ok && sub != "" {
			userDisplay = sub
		}
		logf(quiet, "Authentication successful! Signed in as [%s]", userDisplay)

		out, err := formatOutput(res.Token, outputFormat)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting token output: %v\n", err)
			os.Exit(1)
		}

		// Output token or formatted output to stdout
		fmt.Println(out)

	case <-authCtx.Done():
		if ctx.Err() != nil {
			fmt.Fprintf(os.Stderr, "\nAuthentication aborted by user.\n")
		} else {
			fmt.Fprintf(os.Stderr, "\nTimed out waiting for authentication callback (%s).\n", timeout)
		}
		os.Exit(1)
	}
}

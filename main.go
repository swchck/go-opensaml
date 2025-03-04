package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pkg/browser"
	"github.com/spf13/pflag"
)

type Config struct {
	Server        string
	Port          int
	Realm         string
	TrustAllCerts bool
}

func main() {
	config := new(Config)

	pflag.StringVarP(
		&config.Server,
		"server", "s",
		"",
		"Server to connect to",
	)
	pflag.IntVarP(
		&config.Port,
		"port", "p",
		8020,
		"Port to connect to",
	)
	pflag.StringVarP(
		&config.Realm,
		"realm", "r",
		"",
		"Realm to authenticate to",
	)
	pflag.BoolVarP(
		&config.TrustAllCerts,
		"trust-all", "t",
		false,
		"Trust all certificates",
	)
	pflag.Parse()

	if err := validateConfig(config); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	cookie, err := login(config)
	if err != nil {
		log.Fatalf("Login error: %v", err)
	}

	// Return the cookie to STDIN
	fmt.Println(cookie)
}

func validateConfig(config *Config) error {
	if config.Server == "" {
		return fmt.Errorf("server is required")
	}
	return nil
}

func login(config *Config) (string, error) {
	srvURL := fmt.Sprintf("https://%s", config.Server)
	cookieCh := make(chan string)
	errCh := make(chan error)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		id := query.Get("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			errCh <- fmt.Errorf("missing id parameter in redirect URL")
			return
		}

		cookie, err := retrieveCookieFromID(srvURL, id, config)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			errCh <- err
			return
		}

		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`
            <html>
            <body>
                <p>Login successful</p>
                <script type="text/javascript">
                    window.close();
                </script>
            </body>
            </html>
        `))
		cookieCh <- cookie
	})

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", config.Port))
	if err != nil {
		return "", fmt.Errorf("failed to listen on port %d: %w", config.Port, err)
	}
	defer lis.Close()

	server := &http.Server{}
	go func() {
		if err := server.Serve(lis); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("failed to serve HTTP: %w", err)
		}
	}()

	url := fmt.Sprintf("%s/remote/saml/start?redirect=1", srvURL)
	if config.Realm != "" {
		url = fmt.Sprintf("%s&realm=%s", url, config.Realm)
	}

	if err := browser.OpenURL(url); err != nil {
		return "", fmt.Errorf("failed to open browser: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down server...")
		server.Shutdown(ctx)
	}()

	select {
	case cookie := <-cookieCh:
		return cookie, nil
	case err := <-errCh:
		return "", err
	case <-ctx.Done():
		return "", fmt.Errorf("timeout waiting for login")
	}
}

func retrieveCookieFromID(srvURL, id string, config *Config) (string, error) {
	url := fmt.Sprintf("%s/remote/saml/auth_id?id=%s", srvURL, id)

	cli := &http.Client{}
	if config.TrustAllCerts {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		cli.Transport = tr
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := cli.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to perform HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to retrieve cookie: %s", body)
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == "SVPNCOOKIE" {
			return cookie.Value, nil
		}
	}

	return "", fmt.Errorf("cookie not found")
}

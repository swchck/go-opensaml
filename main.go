package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
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

	// Check if the server is set
	if config.Server == "" {
		pflag.Usage()
		return
	}

	cookie, err := login(config)
	if err != nil {
		// Print the error and exit
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Print the cookie to standard output
	fmt.Println(cookie)
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

		w.Write([]byte("Login successful"))
		cookieCh <- cookie
	})

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", config.Port))
	if err != nil {
		return "", fmt.Errorf("failed to listen on port %d: %w", config.Port, err)
	}
	defer lis.Close()

	go func() {
		if err := http.Serve(lis, nil); err != nil {
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

	select {
	case cookie := <-cookieCh:
		return cookie, nil
	case err := <-errCh:
		return "", err
	case <-time.After(5 * time.Minute):
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

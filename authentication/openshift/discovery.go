package openshift

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	oauthWellKnownPath = "/.well-known/oauth-authorization-server"

	// ServiceAccountNamespacePath is the path to the default serviceaccount namespace.
	ServiceAccountNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	// ServiceAccountTokenPath is the path to the default serviceaccount token.
	ServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec
	// ServiceAccountCAPath is the path to the default cluster CA certificate.
	ServiceAccountCAPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// GetServiceAccountCACert returns the PEM-encoded CA certificate currently mounted.
func GetServiceAccountCACert() ([]byte, error) {
	rawCA, err := os.ReadFile(ServiceAccountCAPath)
	if err != nil {
		return nil, err
	}

	return rawCA, nil
}

// DiscoverCredentials returns the clientID and clientSecret credentials for a
// serviceaccount name. Returns an error if the reading the auto-mounted files for
// the namespace and token are not readable.
func DiscoverCredentials(name string) (string, string, error) {
	n, err := os.ReadFile(ServiceAccountNamespacePath)
	if err != nil || len(n) == 0 {
		return "", "", err
	}

	d, err := os.ReadFile(ServiceAccountTokenPath)
	if err != nil || len(d) == 0 {
		return "", "", err
	}

	clientID := fmt.Sprintf("system:serviceaccount:%s:%s", strings.TrimSpace(string(n)), name)
	clientSecret := strings.TrimSpace(string(d))

	return clientID, clientSecret, nil
}

// DiscoverOAuth return the authorization and token endpoints of the OpenShift OAuth server.
// Returns an error if requesting the `/.well-known/oauth-authorization-server` fails.
// nolint:intefacer
func DiscoverOAuth(client *http.Client) (authURL *url.URL, tokenURL *url.URL, err error) {
	oauthURL := toKubeAPIURLWithPath(oauthWellKnownPath)

	req, err := http.NewRequest(http.MethodGet, oauthURL.String(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create request to oauth server: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to send request to oauth server: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("got %d %s", resp.StatusCode, body)
	}

	var oauthResp struct {
		AuthURL  string `json:"authorization_endpoint"`
		TokenURL string `json:"token_endpoint"`
	}

	err = json.Unmarshal(body, &oauthResp)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to unmarshal response: %w", err)
	}

	authURL, err = url.Parse(oauthResp.AuthURL)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse authorization endpoint URL: %w", err)
	}

	tokenURL, err = url.Parse(oauthResp.TokenURL)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse token endpoint URL: %w", err)
	}

	return authURL, tokenURL, nil
}

func toKubeAPIURLWithPath(path string) *url.URL {
	ret := &url.URL{
		Scheme: "https",
		Host:   "kubernetes.default.svc",
		Path:   path,
	}

	if host := os.Getenv("KUBERNETES_SERVICE_HOST"); len(host) > 0 {
		// assume IPv6 if host contains colons
		if strings.IndexByte(host, ':') != -1 {
			host = "[" + host + "]"
		}

		ret.Host = host
	}

	return ret
}

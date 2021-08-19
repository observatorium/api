package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efficientgo/e2e"
	"github.com/efficientgo/tools/core/pkg/testutil"
	"github.com/observatorium/api/test/testtls"
	"github.com/pkg/errors"
)

const dockerLocalSharedDir = "/shared"

func prepareConfigsAndCerts(t *testing.T, e e2e.Environment) (configsContainerDir string, certsContainerDir string) {
	var err error

	testutil.Ok(
		t,
		testtls.GenerateCerts(
			filepath.Join(e.SharedDir(), "certs"),
			getContainerName(apiName),
			[]string{getContainerName(apiName), "127.0.0.1"},
			getContainerName("dex"),
			[]string{getContainerName("dex")},
		),
	)

	// certsContainerDir, err = copyTestDir(e.SharedDir(), "../testtls/certs", "certs")
	// testutil.Ok(t, err)

	configsContainerDir, err = copyTestDir(e.SharedDir(), "../config", "config")
	testutil.Ok(t, err)

	return configsContainerDir, filepath.Join(dockerLocalSharedDir, "certs")
}

// copyTestDir copies a directory from host to the shared directory, returning
// path to where the directory is available within a container.
func copyTestDir(sharedDir string, srcDir string, dirName string) (string, error) {
	if err := exec.Command("cp", "-r", srcDir, sharedDir).Run(); err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("copying dir %s", srcDir))
	}

	return filepath.Join(dockerLocalSharedDir, dirName), nil
}

// obtainToken obtains a bearer token needed for communication with API.
func obtainToken(endpoint string, certPath string) (string, error) {
	type token struct {
		IDToken string `json:"id_token"`
	}

	cert, err := ioutil.ReadFile(filepath.Join(certPath, "ca.pem"))
	if err != nil {
		return "", errors.Wrap(err, "cannot read cert file")
	}

	// TODO: Fix certs?
	cp := x509.NewCertPool()
	cp.AppendCertsFromPEM(cert)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	data := url.Values{}
	data.Add("grant_type", "password")
	data.Add("username", "admin@example.com")
	data.Add("password", "password")
	data.Add("client_id", "test")
	data.Add("client_secret", "ZXhhbXBsZS1hcHAtc2VjcmV0")
	data.Add("scope", "openid email")

	r, err := http.NewRequest(http.MethodPost, "https://"+endpoint+"/dex/token", strings.NewReader(data.Encode()))
	if err != nil {
		return "", errors.Wrap(err, "cannot create new request")
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	c := &http.Client{
		Transport: tr,
	}

	res, err := c.Do(r)
	if err != nil {
		return "", errors.Wrap(err, "request failed")
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	var t token
	if err := json.Unmarshal(body, &t); err != nil {
		return "", errors.Wrap(err, "cannot unmarshal token")
	}

	return t.IDToken, nil
}

func getContainerName(serviceName string) string {
	return envName + "-" + serviceName
}

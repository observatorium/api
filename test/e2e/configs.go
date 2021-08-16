package e2e

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/efficientgo/tools/core/pkg/testutil"
)

const tenantsYamlTpl = `
tenants:
- name: test-oidc
  id: 1610b0c3-c509-4592-a256-a1871353dbfa
  oidc:
    clientID: test
    clientSecret: ZXhhbXBsZS1hcHAtc2VjcmV0
    issuerCAPath: %s
    issuerURL: https://%s
    redirectURL: https://localhost:8443/oidc/test-oidc/callback
    usernameClaim: email
  opa:
    query: data.observatorium.allow
    paths:
      - %s
      - %s
  rateLimits:
    - endpoint: "/api/metrics/v1/.+/api/v1/receive"
      limit: 100
      window: 1s
    - endpoint: "/api/logs/v1/.*"
      limit: 100
      window: 1s
- name: test-attacker
  id: 066df98b-04e1-46c5-86f7-dc3250bfe869
  oidc:
    clientID: test
    clientSecret: ZXhhbXBsZS1hcHAtc2VjcmV0
    issuerCAPath: %s
    issuerURL: https://%s
    redirectURL: https://localhost:8443/oidc/test-attacker/callback
    usernameClaim: email
  opa:
    query: data.observatorium.allow
    paths:
    - %s
    - %s
- name: test-mtls
  id: 845cdfd9-f936-443c-979c-2ee7dc91f646
  mTLS:
    caPath: %s
  opa:
    url: http://%s
  rateLimits:
    - endpoint: "/api/metrics/v1/.+/api/v1/receive"
      limit: 1
      window: 1s
    - endpoint: "/api/logs/v1/.*"
      limit: 1
      window: 1s
`

func createTenantsYAML(
	t *testing.T,
	configDir string,
	containerConfigDir string,
	issuerURL string,
	containerCertsDir string,
	opaURL string,
) {
	yamlContent := []byte(fmt.Sprintf(
		tenantsYamlTpl,
		filepath.Join(containerCertsDir, "ca.pem"),
		path.Join(issuerURL, "dex"),
		filepath.Join(containerConfigDir, "observatorium.rego"),
		filepath.Join(containerConfigDir, "rbac.yaml"),
		filepath.Join(containerCertsDir, "ca.pem"),
		path.Join(issuerURL, "dex"),
		filepath.Join(containerConfigDir, "observatorium.rego"),
		filepath.Join(containerConfigDir, "rbac.yaml"),
		filepath.Join(containerCertsDir, "ca.pem"),
		path.Join(opaURL, "v1/data/observatorium/allow"),
	))

	err := ioutil.WriteFile(
		filepath.Join(configDir, "tenants.yaml"),
		yamlContent,
		os.FileMode(0755),
	)
	fmt.Println(err)
	testutil.Ok(t, err)
}

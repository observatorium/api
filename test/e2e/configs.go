package e2e

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/efficientgo/e2e"
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

const dexYAMLTpl = `
issuer: https://%s:5556/dex
storage:
  type: sqlite3
  config:
    file: /tmp/dex.db
web:
  https: 0.0.0.0:5556
  tlsCert: /shared/certs/dex.pem
  tlsKey: /shared/certs/dex.key
telemetry:
  http: 0.0.0.0:5558
logger:
  level: "debug"
oauth2:
  passwordConnector: local
staticClients:
- id: test
  name: test
  secret: ZXhhbXBsZS1hcHAtc2VjcmV0
  redirectURIs:
  - https://%s:8443/oidc/test-oidc/callback
enablePasswordDB: true
staticPasswords:
- email: "admin@example.com"
  # bcrypt hash of the string "password"
  hash: "$2a$10$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W"
  username: "admin"
  userID: "08a8684b-db88-4b73-90a9-3cd1661f5466"
`

func createTenantsYAML(
	t *testing.T,
	e e2e.Environment,
	issuerURL string,
	opaURL string,
) {
	// TODO: Simplify
	yamlContent := []byte(fmt.Sprintf(
		tenantsYamlTpl,
		filepath.Join(certsContainerPath, "ca.pem"),
		path.Join(issuerURL, "dex"),
		filepath.Join(configsContainerPath, "observatorium.rego"),
		filepath.Join(configsContainerPath, "rbac.yaml"),
		filepath.Join(certsContainerPath, "ca.pem"),
		path.Join(issuerURL, "dex"),
		filepath.Join(configsContainerPath, "observatorium.rego"),
		filepath.Join(configsContainerPath, "rbac.yaml"),
		filepath.Join(certsContainerPath, "ca.pem"),
		path.Join(opaURL, "v1/data/observatorium/allow"),
	))

	err := ioutil.WriteFile(
		filepath.Join(e.SharedDir(), configSharedDir, "tenants.yaml"),
		yamlContent,
		os.FileMode(0755),
	)
	testutil.Ok(t, err)
}

func createDexYAML(
	t *testing.T,
	e e2e.Environment,
	issuer string,
	redirectURI string,
) {
	yamlContent := []byte(fmt.Sprintf(
		dexYAMLTpl,
		issuer,
		redirectURI,
	))

	err := ioutil.WriteFile(
		filepath.Join(e.SharedDir(), configSharedDir, "dex.yaml"),
		yamlContent,
		os.FileMode(0755),
	)
	testutil.Ok(t, err)
}
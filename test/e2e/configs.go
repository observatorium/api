// +build integration interactive

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

type testType string

const (
	metrics     testType = "metrics"
	rules       testType = "rules"
	logs        testType = "logs"
	tenants     testType = "tenants"
	interactive testType = "interactive"

	dockerLocalSharedDir = "/shared"
	certsSharedDir       = "certs"
	configSharedDir      = "config"

	certsContainerPath   = dockerLocalSharedDir + "/" + certsSharedDir
	configsContainerPath = dockerLocalSharedDir + "/" + configSharedDir

	envMetricsName  = "e2e_metrics_read_write"
	envRulesAPIName = "e2e_rules_api"
	envLogsName     = "e2e_logs_read_write_tail"
	envTenantsName  = "e2e_tenants"
	envInteractive  = "e2e_interactive"

	defaultTenantID = "1610b0c3-c509-4592-a256-a1871353dbfa"
	mtlsTenantID    = "845cdfd9-f936-443c-979c-2ee7dc91f646"

	defaultTenantName = "test-oidc"
)

const tenantsYamlTpl = `
tenants:
- name: test-oidc
  id: 1610b0c3-c509-4592-a256-a1871353dbfa
  authenticator:
    type: oidc
    config:
      clientID: test
      clientSecret: ZXhhbXBsZS1hcHAtc2VjcmV0
      issuerCAPath: %[1]s
      issuerURL: https://%[2]s
      redirectURL: https://localhost:8443/oidc/test-oidc/callback
      usernameClaim: email
  opa:
    query: data.observatorium.allow
    paths:
      - %[3]s
      - %[4]s
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
    issuerCAPath: %[1]s
    issuerURL: https://%[2]s
    redirectURL: https://localhost:8443/oidc/test-attacker/callback
    usernameClaim: email
  opa:
    query: data.observatorium.allow
    paths:
    - %[3]s
    - %[4]s
- name: test-mtls
  id: 845cdfd9-f936-443c-979c-2ee7dc91f646
  mTLS:
    caPath: %[5]s
  opa:
    url: http://%[6]s
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
	e e2e.Environment,
	issuerURL string,
	opaURL string,
) {
	yamlContent := []byte(fmt.Sprintf(
		tenantsYamlTpl,
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

const rulesYAMLTpl = `
type: S3
config:
  bucket: %s
  endpoint: %s
  access_key: %s
  insecure: true
  secret_key: %s
`

func createRulesYAML(
	t *testing.T,
	e e2e.Environment,
	bucket, endpoint, accessKey, secretKey string,
) {
	yamlContent := []byte(fmt.Sprintf(
		rulesYAMLTpl,
		bucket,
		endpoint,
		accessKey,
		secretKey,
	))

	err := ioutil.WriteFile(
		filepath.Join(e.SharedDir(), configSharedDir, "rules-objstore.yaml"),
		yamlContent,
		os.FileMode(0755),
	)
	testutil.Ok(t, err)
}

const recordingRuleYamlTpl = `
groups:
  - name: example
    interval: 30s
    rules:
      - record: id_network_type
        expr: 0 * topk by (ebs_account) (1, max by (ebs_account,account_type,internal,email_domain) (label_replace(label_replace(label_replace(subscription_labels{email_domain="domain1.com"}*0+5, "class", "Internal", "class", ".*") or label_replace(subscription_labels{class!="Customer",email_domain=~"(.*\\.|^)domain2.com"}*0+4, "class", "Internal", "class", ".*") or (subscription_labels{class="Customer"}*0+3) or (subscription_labels{class="Partner"}*0+2) or (subscription_labels{class="Evaluation"}*0+1) or label_replace(subscription_labels{class!~"Evaluation|Customer|Partner"}*0+0, "class", "", "class", ".*"), "account_type", "$1", "class", "(.+)"), "internal", "true", "email_domain", "domain1.com|(.*\\.|^)domain2.com") ))
`

const alertingRuleYamlTpl = `
groups:
  - name: example
  interval: 30s
  rules:
    - alert: HighRequestLatency
      expr: job:request_latency_seconds:mean5m{job="myjob"} > 0.5
      for: 10m
      labels:
        severity: page
      annotations:
        summary: High request latency
`
const recordAndAlertingRulesYamlTpl = `
groups:
  - name: node_rules
    interval: 30s
    rules:
      - record: job:up:avg
        expr: avg without(instance)(up{job="node"})
      - alert: ManyInstancesDown
        expr: job:up:avg{job="node"} < 0.5
      for: 10m
      annotations:
        Summary: Many instances down
`

const invalidRulesYamlTpl = `
invalid:
- name: testing
 invalid_rules:
 - rule1: job:up:avg
   expr: avg without(instance)(up{job="node"})
 - rule2: ManyInstancesDown
   expr: job:up:avg{job="node"} < 0.5
`

const validYamlWithInvalidRulesYamlTpl = `
groups:
  - name: example
    interval: 30TB
    rules:
      - record: job:http_inprogress_requests:sum
        expr: sum by (job) (http_inprogress_requests)
      - alert: ManyInstancesDown
        expr: job:up:avg{job="node"} < 0.5
        for: 10GB
        annotations: {}
`

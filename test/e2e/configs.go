//go:build integration || interactive

package e2e

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efficientgo/core/testutil"
	"github.com/efficientgo/e2e"
)

type testType string

const (
	metrics        testType = "metrics"
	rules          testType = "rules"
	logs           testType = "logs"
	traces         testType = "traces"
	tracesTemplate testType = "tracesTemplate"
	tenants        testType = "tenants"
	interactive    testType = "interactive"

	certsSharedDir  = "certs"
	configSharedDir = "config"

	envMetricsName        = "metrics"
	envRulesAPIName       = "rules-api"
	envLogsName           = "logs-tail"
	envTracesName         = "traces-export"
	envTracesTemplateName = "traces-template"
	envTenantsName        = "tenants"
	envInteractive        = "interactive"

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
      redirectURL: https://%[7]s:8443/oidc/test-oidc/callback
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
    redirectURL: https://%[7]s:8443/oidc/test-attacker/callback
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
	apiServiceHostname string,
) {
	yamlContent := []byte(fmt.Sprintf(
		tenantsYamlTpl,
		filepath.Join(e.SharedDir(), certsSharedDir, "ca.pem"),
		path.Join(issuerURL, "dex"),
		filepath.Join(e.SharedDir(), configSharedDir, "observatorium.rego"),
		filepath.Join(e.SharedDir(), configSharedDir, "rbac.yaml"),
		filepath.Join(e.SharedDir(), certsSharedDir, "ca.pem"),
		path.Join(opaURL, "v1/data/observatorium/allow"),
		apiServiceHostname,
	))

	err := os.WriteFile(
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
  tlsCert: %s
  tlsKey: %s
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
		filepath.Join(e.SharedDir(), certsSharedDir, "dex.pem"),
		filepath.Join(e.SharedDir(), certsSharedDir, "dex.key"),
		redirectURI,
	))

	err := os.WriteFile(
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

	err := os.WriteFile(
		filepath.Join(e.SharedDir(), configSharedDir, "rules-objstore.yaml"),
		yamlContent,
		os.FileMode(0755),
	)
	testutil.Ok(t, err)
}

const otelConfigTpl = `
receivers:
    otlp/grpc:
      protocols:
        grpc:
            endpoint: "0.0.0.0:4317"

exporters:
    logging:
        logLevel: debug
    jaeger:
        endpoint: %[1]s
        tls:
          insecure: true

service:
    telemetry:
        metrics:
            address: localhost:8888
        logs:
            level: "debug"

    pipelines:
        traces/grpc:
            receivers: [otlp/grpc]
            exporters: [logging,jaeger]
`

// createOtelCollectorConfigYAML() creates YAML for an Open Telemetry collector inside the Observatorium API boundary.
func createOtelCollectorConfigYAML(
	t *testing.T,
	e e2e.Environment,
	jaegerGRPCEndpoint string,
) {
	// Warn if a YAML change introduced a tab character
	if strings.ContainsRune(otelConfigTpl, '\t') {
		t.Errorf("Tab in the YAML")
	}

	yamlContent := []byte(fmt.Sprintf(
		otelConfigTpl,
		jaegerGRPCEndpoint))

	err := os.WriteFile(
		filepath.Join(e.SharedDir(), configSharedDir, "collector.yaml"),
		yamlContent,
		os.FileMode(0644),
	)
	testutil.Ok(t, err)
}

// OTel trace collector that receives in HTTP w/o security, but exports in gRPC with security.
const otelForwardingConfigTpl = `
receivers:
    otlp:
      protocols:
        http:
            endpoint: 0.0.0.0:4318
        grpc:
            endpoint: 0.0.0.0:4317

exporters:
    logging:
      logLevel: debug
    otlp:
      endpoint: %[1]s
      # auth:
      #   authenticator: oauth2client
      tls:
        insecure_skip_verify: true
      compression: none
      headers:
        x-tenant: test-oidc
        # (Use hard-coded auth header, because this forwarding collector
        # is unable to do OIDC password grant.)
        authorization: bearer %[2]s

extensions:
  health_check:

service:
    extensions: [health_check]
    telemetry:
      metrics:
        address: localhost:8889
    # extensions: [oauth2client]
    pipelines:
      traces:
        receivers: [otlp]
        exporters: [logging,otlp]
`

// createOtelForwardingCollectorConfigYAML() creates YAML for an Open Telemetry collector outside the
// Observatorium API boundary that forwards traces via GRPC to Observatorium.
func createOtelForwardingCollectorConfigYAML(
	t *testing.T,
	e e2e.Environment,
	observatoriumGRPCEndpoint string,
	dexToken string,
) {
	// Warn if a YAML change introduced a tab character
	if strings.ContainsRune(otelForwardingConfigTpl, '\t') {
		t.Errorf("Tab in the YAML")
	}

	yamlContent := []byte(fmt.Sprintf(
		otelForwardingConfigTpl,
		observatoriumGRPCEndpoint,
		dexToken))

	err := os.WriteFile(
		filepath.Join(e.SharedDir(), configSharedDir, "forwarding-collector.yaml"),
		yamlContent,
		os.FileMode(0644),
	)
	testutil.Ok(t, err)
}

const lokiYAMLTpl = `auth_enabled: true

server:
  http_listen_port: 3100

common:
 storage:
  s3:
    s3forcepathstyle: true
    access_key_id: %[1]s
    secret_access_key: %[2]s
    endpoint: %[3]s
    bucketnames: %[4]s
    insecure: true

compactor:
  working_directory: /tmp/loki/compactor
  shared_store: s3
  compaction_interval: 5m

distributor:
  ring:
    kvstore:
      store: inmemory

ingester:
  lifecycler:
    address: 0.0.0.0
    ring:
      kvstore:
        store: inmemory
      replication_factor: 1

    final_sleep: 0s
  chunk_idle_period: 5m
  chunk_retain_period: 30s
  wal:
    dir: /tmp/loki/ingester/wal
    enabled: false

querier:
  engine:
    max_look_back_period: 5m
    timeout: 3m

ruler:
  storage:
    type: s3
  wal:
   dir: /tmp/loki/ruler/wal
  rule_path: /tmp/loki/
 
schema_config:
  configs:
  - from: 2019-01-01
    store: boltdb-shipper
    object_store: s3
    schema: v12
    index:
      prefix: index_
      period: 24h

storage_config:
  boltdb_shipper:
    active_index_directory: /tmp/loki/index
    cache_location: /tmp/loki/index_cache
    shared_store: s3

limits_config:
  enforce_metric_name: false
  reject_old_samples: false

`

func createLokiYAML(
	t *testing.T,
	e e2e.Environment,
	accessId, accessKey, endpoint, bucket string,
) {
	yamlContent := []byte(fmt.Sprintf(lokiYAMLTpl, accessId, accessKey, endpoint, bucket))

	err := os.WriteFile(
		filepath.Join(e.SharedDir(), configSharedDir, "loki.yml"),
		yamlContent,
		os.FileMode(0755),
	)

	testutil.Ok(t, err)
}

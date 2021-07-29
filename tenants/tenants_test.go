package tenants

import (
	"net/url"
	"testing"
	"time"

	prometheus "github.com/prometheus/client_model/go"
)

// Tests if retries are working for tenant registrations.
// To test this, a tenant with wrong configuration needs to be present at /test/conf/tenants.yaml.
func TestListenAndServeTenants(t *testing.T) {
	cfg := config{}

	cfg.server.listen = "0.0.0.0:8443"
	cfg.server.listenInternal = "0.0.0.0:8448"

	u, _ := url.ParseRequestURI("http://127.0.0.1:3100")
	cfg.logs.readEndpoint = u

	u, _ = url.ParseRequestURI("http://127.0.0.1:3100")
	cfg.logs.writeEndpoint = u

	u, _ = url.ParseRequestURI("http://127.0.0.1:9091")
	cfg.metrics.readEndpoint = u

	u, _ = url.ParseRequestURI("http://127.0.0.1:19291")
	cfg.metrics.writeEndpoint = u

	cfg.rbacConfigPath = "../test/config/rbac.yaml"
	cfg.tenantsConfigPath = "../test/config/tenants.yaml"
	cfg.server.healthcheckURL = "https://127.0.0.1:8443"
	cfg.tls.reloadInterval = time.Minute
	cfg.middleware.concurrentRequestLimit = 1000
	cfg.middleware.backLogLimitConcurrentRequests = 0
	cfg.logLevel = "debug"

	// command line configuration is now setup, populate tenantsConfig struct from commadline configuration.
	tCfg := loadTenantConfigs(&cfg)

	// onboard teants in a goroutine and watch retry metrics to go up as the tenant registration fails for
	// a tenant with wrong configuration at ./test/conf/tenants.yaml.
	go listenAndServeTenants(cfg, tCfg)

	var initCount, laterCount *float64

	time.Sleep(300 * time.Millisecond)

	mFamily, err := tCfg.reg.Gather()
	if err != nil {
		t.FailNow()
	}

	// Get the initial value for retry attempt counter.
	initCount = getRetryMetricCounter(mFamily)

	// Wait for more retry attempts.
	time.Sleep(10 * time.Second)

	mFamily, err = tCfg.reg.Gather()
	if err != nil {
		t.FailNow()
	}

	// Get the current value for retry attempt counter.
	laterCount = getRetryMetricCounter(mFamily)

	// Fail the test if the retry attempts are not increasing.
	if *initCount <= 0 || (*laterCount <= *initCount) {
		t.FailNow()
	}
}

func getRetryMetricCounter(mFamily []*prometheus.MetricFamily) *float64 {
	var retryCount *float64

	for _, m := range mFamily {
		if m.GetName() == "tenant_onboarding_attempts_total" {
			retryCount = m.Metric[0].Counter.Value
			break
		}
	}

	return retryCount
}

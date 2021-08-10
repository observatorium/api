package tenants

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	rbacConfig   = "../test/config/rbac.yaml"
	tenantConfig = "../test/config/tenants-failing.yaml"
)

// TODO @matej-g: Consider redesigning this as an integration test to test full flow and
// avoid sleeping here
func TestListenAndServeTenants(t *testing.T) {
	cfg := Config{
		RBACConfigPath:    rbacConfig,
		TenantsConfigPath: tenantConfig,
		Middleware: middlewareConfig{
			ConcurrentRequestLimit: 1000,
		},
		LogLevel: "debug",
	}

	tCfg := loadTenantConfigs(&cfg)

	// onboard teants in a goroutine and watch retry metrics to go up as the tenant registration fails for
	// a tenant with wrong configuration
	go listenAndServeTenants(&cfg, &tCfg)

	// Get the initial value for retry attempt counter.
	time.Sleep(300 * time.Millisecond)
	initCount := getRetryMetricCounter(t, tCfg.reg)

	// Wait for more retry attempts.
	time.Sleep(300 * time.Millisecond)
	laterCount := getRetryMetricCounter(t, tCfg.reg)

	if *initCount <= 0 {
		t.Fatalf("unexpected initial registration retry count: wanted 0, got %v instead", *initCount)
	}

	if *laterCount <= *initCount {
		t.Fatalf(
			"later registration retry count should be lower than initial count: got later count %v, initial count %v",
			*initCount,
			*laterCount,
		)
	}
}

func getRetryMetricCounter(t *testing.T, reg *prometheus.Registry) *float64 {
	mFamily, err := reg.Gather()
	if err != nil {
		t.Fatalf("error gathering metrics: %v", err)
	}

	for _, m := range mFamily {
		if m.GetName() == "tenant_onboarding_attempts_total" {
			return m.Metric[0].Counter.Value
		}
	}

	t.Fatalf("metric not found")
	return nil
}

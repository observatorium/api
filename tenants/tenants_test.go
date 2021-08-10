package tenants

import (
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-kit/kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/common/version"
)

const (
	rbacConfig   = "../test/config/rbac.yaml"
	tenantConfig = "../test/config/tenants-failing.yaml"
)

func TestRegister(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		version.NewCollector("observatorium"),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	r := chi.NewRouter()
	Register(
		r,
		tenantConfig,
		rbacConfig,
		"",
		MetricsConfig{},
		LogsConfig{},
		log.NewNopLogger(),
		reg,
	)

	// onboard teants in a goroutine and watch retry metrics to go up as the tenant registration fails for
	// a tenant with wrong configuration

	// Get the initial value for retry attempt counter.
	time.Sleep(300 * time.Millisecond)

	initCount := getRetryMetricCounter(t, reg)

	// Wait for more retry attempts.
	time.Sleep(300 * time.Millisecond)

	laterCount := getRetryMetricCounter(t, reg)

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

func getRetryMetricCounter(t *testing.T, reg prometheus.Gatherer) *float64 {
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

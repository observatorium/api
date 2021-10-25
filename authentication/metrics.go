package authentication

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	providerOIDC      = "oidc"
	providerOpenShift = "openshift"
)

func RegisterTenantsFailingMetric(reg prometheus.Registerer) *prometheus.CounterVec {
	return promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
		Namespace: "observatorium",
		Subsystem: "api",
		Name:      "tenants_failed_registrations",
		Help:      "The number of failed provider instantiations.",
	}, []string{"tenant", "provider"})
}

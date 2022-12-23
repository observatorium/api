package authentication

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

func RegisterTenantsFailingMetric(reg prometheus.Registerer) *prometheus.CounterVec {
	return promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
		Namespace: "observatorium",
		Subsystem: "api",
		Name:      "tenants_failed_registrations_total",
		Help:      "The number of failed provider instantiations.",
	}, []string{"tenant", "provider"})
}

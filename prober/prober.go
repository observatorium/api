package prober

import (
	"io"
	"net/http"
	"sync/atomic"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

type Check func() bool

// Prober represents health and readiness status of given component.
type Prober struct {
	logger log.Logger

	ready   uint32
	healthy uint32
}

// New returns Prober representing readiness and healthiness of given component.
func New(logger log.Logger) *Prober {
	return &Prober{logger: logger}
}

// HealthyHandler returns a HTTP Handler which responds health checks.
func (p *Prober) HealthyHandler() http.HandlerFunc {
	return p.handler(p.isHealthy)
}

// ReadyHandler returns a HTTP Handler which responds readiness checks.
func (p *Prober) ReadyHandler() http.HandlerFunc {
	return p.handler(p.isReady)
}

func (p *Prober) handler(check Check) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if !check() {
			http.Error(w, "NOT OK", http.StatusServiceUnavailable)
			return
		}
		if _, err := io.WriteString(w, "OK"); err != nil {
			level.Error(p.logger).Log("msg", "failed to write probe response", "err", err)
		}
	}
}

// isReady returns true if component is ready.
func (p *Prober) isReady() bool {
	ready := atomic.LoadUint32(&p.ready)
	return ready > 0
}

// Ready sets components status to ready.
func (p *Prober) Ready() {
	old := atomic.SwapUint32(&p.ready, 1)

	if old == 0 {
		level.Info(p.logger).Log("msg", "changing probe status", "status", "ready")
	}
}

// NotReady sets components status to not ready with given error as a cause.
func (p *Prober) NotReady(err error) {
	old := atomic.SwapUint32(&p.ready, 0)

	if old == 1 {
		level.Warn(p.logger).Log("msg", "changing probe status", "status", "not-ready", "reason", err)
	}
}

// isHealthy returns true if component is healthy.
func (p *Prober) isHealthy() bool {
	healthy := atomic.LoadUint32(&p.healthy)
	return healthy > 0
}

// Healthy sets components status to healthy.
func (p *Prober) Healthy() {
	old := atomic.SwapUint32(&p.healthy, 1)

	if old == 0 {
		level.Info(p.logger).Log("msg", "changing probe status", "status", "healthy")
	}
}

// NotHealthy sets components status to not healthy with given error as a cause.
func (p *Prober) NotHealthy(err error) {
	old := atomic.SwapUint32(&p.healthy, 0)

	if old == 1 {
		level.Info(p.logger).Log("msg", "changing probe status", "status", "healthy")
	}
}

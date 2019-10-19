package internal

import (
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

type probeType string

const (
	ready   probeType = "ready"
	healthy probeType = "healthy"

	probeErrorHTTPStatus = 503
)

// Prober represents health and readiness status of given component.
//
//   liveness: Many applications running for long periods of time eventually transition to broken states,
//   (healthy) and cannot recover except by being restarted.
//             Kubernetes provides liveness probes to detect and remedy such situations.
//
//   readiness: Sometimes, applications are temporarily unable to serve traffic.
//   (ready)    For example, an application might need to load large data or configuration files during startup,
//              or depend on external services after startup. In such cases, you don’t want to kill the application,
//              but you don’t want to send it requests either. Kubernetes provides readiness probes to detect
//              and mitigate these situations. A pod with containers reporting that they are not ready
//              does not receive traffic through Kubernetes Services.
type Prober struct {
	logger log.Logger

	readiness   bool
	healthiness bool

	readyMu   sync.RWMutex
	healthyMu sync.RWMutex
}

// NewProber returns Prober representing readiness and healthiness of given component.
func NewProber(logger log.Logger) *Prober {
	return &Prober{logger: logger}
}

// HealthyHandlerFunc returns a HTTP Handler which responds health checks.
func (p *Prober) HealthyHandlerFunc() http.HandlerFunc {
	return p.probeHandlerFunc(p.isHealthy, healthy)
}

// ReadyHandlerFunc returns a HTTP Handler which responds readiness checks.
func (p *Prober) ReadyHandlerFunc() http.HandlerFunc {
	return p.probeHandlerFunc(p.isReady, ready)
}

func (p *Prober) probeHandlerFunc(probeFunc func() bool, t probeType) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if !probeFunc() {
			http.Error(w, fmt.Sprintf("observatorium is NOT %v", t), probeErrorHTTPStatus)
			return
		}
		if _, err := io.WriteString(w, fmt.Sprintf("observatorium is %v", t)); err != nil {
			level.Error(p.logger).Log("msg", "failed to write probe response", "probe type", t, "err", err)
		}
	}
}

// isReady returns true if component is ready.
func (p *Prober) isReady() bool {
	p.readyMu.RLock()
	defer p.readyMu.RUnlock()

	return p.readiness
}

// SetReady sets components status to ready.
func (p *Prober) SetReady() {
	p.readyMu.Lock()
	defer p.readyMu.Unlock()

	if !p.readiness {
		p.readiness = true
		level.Info(p.logger).Log("msg", "changing probe status", "status", "ready")
	}
}

// SetNotReady sets components status to not ready with given error as a cause.
func (p *Prober) SetNotReady(err error) {
	p.readyMu.Lock()
	defer p.readyMu.Unlock()

	if p.readiness {
		p.readiness = false
		level.Warn(p.logger).Log("msg", "changing probe status", "status", "not-ready", "reason", err)
	}
}

// isHealthy returns true if component is healthy.
func (p *Prober) isHealthy() bool {
	p.healthyMu.RLock()
	defer p.healthyMu.RUnlock()

	return p.healthiness
}

// SetHealthy sets components status to healthy.
func (p *Prober) SetHealthy() {
	p.healthyMu.Lock()
	defer p.healthyMu.Unlock()

	if !p.healthiness {
		p.healthiness = true
		level.Info(p.logger).Log("msg", "changing probe status", "status", "healthy")
	}
}

// SetNotHealthy sets components status to not healthy with given error as a cause.
func (p *Prober) SetNotHealthy(err error) {
	p.healthyMu.Lock()
	defer p.healthyMu.Unlock()

	if p.healthiness {
		p.healthiness = false
		level.Info(p.logger).Log("msg", "changing probe status", "status", "healthy")
	}
}

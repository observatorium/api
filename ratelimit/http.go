package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/httprate"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/httperr"
)

const (
	requestName    = "observatorium:tenant_per_endpoint"
	requestTimeout = time.Second * 2

	headerKeyRemaining = "X-RateLimit-Remaining"
	headerKeyLimit     = "X-RateLimit-Limit"
	headerKeyReset     = "X-RateLimit-Reset"

	headerRetryAfter = "Retry-After"
)

// Config configures a rate limiter per endpoint, per tenant.
type Config struct {
	Tenant        string
	Matcher       *regexp.Regexp
	Limit         int
	Window        time.Duration
	FailClosed    bool
	RetryAfterMin time.Duration
	RetryAfterMax time.Duration
}

// Middleware is a convenience type for functions that wrap http.Handlers.
type Middleware func(http.Handler) http.Handler

type middleware struct {
	matcher *regexp.Regexp
	handler Middleware
}

// WithLocalRateLimiter returns a middleware that controls the amount of requests per tenant using an in-memory store.
func WithLocalRateLimiter(configs ...Config) Middleware {
	middlewares := make(map[string][]middleware)
	for _, c := range configs {
		middlewares[c.Tenant] = append(middlewares[c.Tenant], middleware{c.Matcher, httprate.NewRateLimiter(
			c.Limit,
			c.Window,
		).Handler})
	}

	return combine(middlewares)
}

// WithSharedRateLimiter returns a middleware that controls the amount of requests per tenant using an external service.
func WithSharedRateLimiter(logger log.Logger, client SharedRateLimiter, configs ...Config) Middleware {
	logger = log.With(logger, "component", "rate limiter")

	middlewares := make(map[string][]middleware)
	for _, c := range configs {
		middlewares[c.Tenant] = append(middlewares[c.Tenant],
			middleware{
				c.Matcher,
				rateLimiter{logger, client,
					&request{
						name:          requestName,
						key:           fmt.Sprintf("%s:%s", c.Tenant, c.Matcher.String()),
						limit:         int64(c.Limit),
						duration:      c.Window.Milliseconds(),
						failClosed:    c.FailClosed,
						retryAfterMin: c.RetryAfterMin,
						retryAfterMax: c.RetryAfterMax,
					},
					sync.RWMutex{},
					make(map[string]time.Duration),
				}.Handler,
			})
	}

	return combine(middlewares)
}

func combine(middlewares map[string][]middleware) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := authentication.GetTenant(r.Context())
			if !ok {
				// This shouldn't have happened.
				httperr.PrometheusAPIError(w, "error finding tenant", http.StatusUnauthorized)
				return
			}

			tms, ok := middlewares[tenant]
			if !ok {
				// No rate limits configured for this tenant.
				next.ServeHTTP(w, r)
				return
			}

			for _, m := range tms {
				if m.matcher.MatchString(r.URL.Path) {
					m.handler(next).ServeHTTP(w, r)
					return
				}
			}

			// No rate limits configured for this endpoint.
			next.ServeHTTP(w, r)
		})
	}
}

type rateLimiter struct {
	logger        log.Logger
	limiterClient SharedRateLimiter
	req           *request
	mut           sync.RWMutex
	limitTracker  map[string]time.Duration
}

func (l rateLimiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()

		remaining, resetTime, err := l.limiterClient.GetRateLimits(ctx, l.req)
		w.Header().Set(headerKeyLimit, strconv.FormatInt(l.req.limit, 10))
		w.Header().Set(headerKeyRemaining, strconv.FormatInt(remaining, 10))
		w.Header().Set(headerKeyReset, strconv.FormatInt(resetTime, 10))

		if err != nil {
			// in all cases, where we will return an error
			// if the rate limiter becomes overloaded or unavailable, we should start to force the client to back off
			if retryAfter, ok := l.getAndSetNextRetryAfterValue(); ok {
				w.Header().Set(headerRetryAfter, retryAfter)
			}

			if errors.Is(err, errOverLimit) {
				httperr.PrometheusAPIError(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
				return
			}

			level.Warn(l.logger).Log(
				"msg", "failed to determine rate limiting action from remote server", "err", err.Error())

			if l.req.failClosed {
				httperr.PrometheusAPIError(w, err.Error(), http.StatusInternalServerError)
				return
			}

			level.Warn(l.logger).Log("msg", "request forwarded upstream due to rate limit failure mode policy fail open")
		}
		next.ServeHTTP(w, r)
	})
}

func (l rateLimiter) getAndSetNextRetryAfterValue() (string, bool) {
	if l.req.retryAfterMin == 0 {
		return "", false
	}
	l.mut.Lock()
	defer l.mut.Unlock()

	current, ok := l.limitTracker[l.req.key]
	if !ok {
		nextValue := l.req.retryAfterMin.Seconds()
		l.limitTracker[l.req.key] = l.req.retryAfterMin * 2
		return fmt.Sprintf("%d", int(nextValue)), true
	}

	nextValue := current * 2
	// check if we have gone above the max value
	// if so, set the value to the max value
	// if max value is 0, then we don't set a max value
	if l.req.retryAfterMax != 0 && nextValue > l.req.retryAfterMax {
		nextValue = l.req.retryAfterMax
	}

	l.limitTracker[l.req.key] = nextValue
	next := strconv.Itoa(int(nextValue.Seconds()))
	return next, true
}

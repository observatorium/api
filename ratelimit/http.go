package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/httprate"

	"github.com/observatorium/observatorium/authentication"
)

const (
	requestName    = "observatorium:tenant_per_endpoint"
	requestTimeout = time.Millisecond * 500
)

// Config configures a rate limiter per endpoint, per tenant.
type Config struct {
	Tenant  string
	Matcher *regexp.Regexp
	Limit   int
	Window  time.Duration
}

// Middleware is a convenience type for functions that wrap http.Handlers.
type Middleware func(http.Handler) http.Handler

type middleware struct {
	matcher *regexp.Regexp
	handler Middleware
}

// WithLocalRateLimiter returns a middleware that controls amount of requests per tenant using in-memory store.
func WithLocalRateLimiter(configs ...Config) Middleware {
	middlewares := make(map[string][]middleware)
	for _, c := range configs {
		middlewares[c.Tenant] = append(middlewares[c.Tenant], middleware{c.Matcher, httprate.NewRateLimiter(
			c.Limit,
			c.Window,
			nil,
		).Handler})
	}

	return combine(middlewares)
}

// WithSharedRateLimiter returns a middleware that controls amount of requests per tenant using external service.
func WithSharedRateLimiter(client *Client, configs ...Config) Middleware {
	middlewares := make(map[string][]middleware)
	for _, c := range configs {
		middlewares[c.Tenant] = append(middlewares[c.Tenant], middleware{c.Matcher, rateLimiter{client, &request{
			name:     requestName,
			key:      fmt.Sprintf("%s:%s", c.Tenant, c.Matcher.String()),
			limit:    int64(c.Limit),
			duration: c.Window.Microseconds(),
		}}.Handler})
	}

	return combine(middlewares)
}

func combine(middlewares map[string][]middleware) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := authentication.GetTenant(r.Context())
			if !ok {
				// This shouldn't have happened.
				http.Error(w, "error finding tenant", http.StatusUnauthorized)
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
	client *Client

	req *request
}

func (l rateLimiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()

		remaining, resetTime, err := l.client.GetRateLimits(ctx, l.req)
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", l.req.limit))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime))

		if err != nil {
			if err == errOverLimit {
				http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
				return
			}

			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		next.ServeHTTP(w, r)
	})
}

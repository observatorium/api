package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/go-chi/httprate"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	"github.com/observatorium/api/authentication"
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

// WithLocalRateLimiter returns a middleware that controls the amount of requests per tenant using an in-memory store.
func WithLocalRateLimiter(configs ...Config) Middleware {
	var mWare middleware
	for _, c := range configs {
		mWare = middleware{c.Matcher, httprate.NewRateLimiter(
			c.Limit,
			c.Window,
			nil,
		).Handler}
	}

	return combine(mWare)
}

// WithSharedRateLimiter returns a middleware that controls the amount of requests per tenant using an external service.
func WithSharedRateLimiter(logger log.Logger, client *Client, configs ...Config) Middleware {
	logger = log.With(logger, "component", "rate limiter")

	var mWare middleware
	for _, c := range configs {
		mWare = middleware{c.Matcher, rateLimiter{logger, client, &request{
			name:     requestName,
			key:      fmt.Sprintf("%s:%s", c.Tenant, c.Matcher.String()),
			limit:    int64(c.Limit),
			duration: c.Window.Microseconds(),
		}}.Handler}
	}

	return combine(mWare)
}

func combine(mWare middleware) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, ok := authentication.GetTenant(r.Context())
			if !ok {
				// This shouldn't have happened.
				http.Error(w, "error finding tenant", http.StatusUnauthorized)
				return
			}

			if mWare.matcher == nil {
				// No rate limits configured for this tenant.
				next.ServeHTTP(w, r)
				return
			}

			if mWare.matcher.MatchString(r.URL.Path) {
				mWare.handler(next).ServeHTTP(w, r)
				return
			}

			// No rate limits configured for this endpoint.
			next.ServeHTTP(w, r)
		})
	}
}

type rateLimiter struct {
	logger log.Logger
	client *Client
	req    *request
}

func (l rateLimiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()

		remaining, resetTime, err := l.client.GetRateLimits(ctx, l.req)
		w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(l.req.limit, 10))
		w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(remaining, 10))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime, 10))

		if err != nil {
			if err == errOverLimit {
				http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
				return
			}
			level.Warn(l.logger).Log("msg", "API failed", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		next.ServeHTTP(w, r)
	})
}

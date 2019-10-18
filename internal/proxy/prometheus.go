package proxy

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

type promURL string

func NewPrometheus(prefix string, endpoint *url.URL) http.HandlerFunc {
	var promKey promURL

	director := func(r *http.Request) {
		prometheusURL := r.Context().Value(promKey).(*url.URL)

		r.URL.Scheme = prometheusURL.Scheme
		r.URL.Host = prometheusURL.Host
		// Normalize request so Prometheus doesn't know that request was proxied.
		r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Put the upstream PrometheusURL into the request's context for the director.
		r = r.WithContext(context.WithValue(r.Context(), promKey, endpoint))

		proxy := &httputil.ReverseProxy{
			Director: director,
		}
		proxy.ServeHTTP(w, r)
	}
}

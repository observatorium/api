package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/httperr"
	"github.com/prometheus/alertmanager/api/v2/models"
	amlabels "github.com/prometheus/alertmanager/pkg/labels"
	"github.com/prometheus/prometheus/model/labels"
)

// WithEnforceTenancyOnFilter returns a middleware that ensures that every filter has a tenant label enforced.
func WithEnforceTenancyOnFilter(label string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// https://github.com/prometheus-community/prom-label-proxy/
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := authentication.GetTenantID(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "error finding tenant ID", http.StatusInternalServerError)

				return
			}

			matcher := &labels.Matcher{
				Name:  label,
				Type:  labels.MatchEqual,
				Value: id,
			}
			matcherStr := matcher.String()

			q := r.URL.Query()
			filters := q["filter"]
			modified := []string{matcherStr}

			if len(filters) == 0 {
				q.Set("filter", matcherStr)
			} else {

				for _, filter := range filters {
					m, err := amlabels.ParseMatcher(filter)
					if err != nil {
						return
					}
					// Keep the original matcher in case of multi label values because
					// the user might want to filter on a specific value.
					if m.Name == label {
						continue
					}
					modified = append(modified, filter)
				}
			}

			q["filter"] = modified
			q.Del(label)
			r.URL.RawQuery = q.Encode()
			next.ServeHTTP(w, r)
		})
	}
}

// WithEnforceTenancyOnFilter returns a middleware that ensures that every filter has a tenant label enforced.
func WithEnforceTenancyOnSilenceMatchers(label string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// https://github.com/prometheus-community/prom-label-proxy/
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := authentication.GetTenantID(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "error finding tenant ID", http.StatusInternalServerError)
				return
			}

			if r.Method != http.MethodPost {
				httperr.PrometheusAPIError(w, "error method not allowed", http.StatusMethodNotAllowed)
				return
			}

			var (
				sil models.PostableSilence
			)

			if err := json.NewDecoder(r.Body).Decode(&sil); err != nil {
				httperr.PrometheusAPIError(w, fmt.Sprintf("bad request: can't decode: %v", err), http.StatusBadRequest)
				return
			}

			if sil.ID != "" {
				// This is an update for an existing silence.
				httperr.PrometheusAPIError(w, "updates to silence by ID not allowed", http.StatusUnprocessableEntity)
			}

			var falsy bool
			modified := models.Matchers{
				&models.Matcher{Name: &(label), Value: &id, IsRegex: &falsy},
			}
			for _, m := range sil.Matchers {
				if m.Name != nil && *m.Name == label {
					continue
				}
				modified = append(modified, m)
			}

			// At least one matcher in addition to the enforced label is required,
			// otherwise all alerts would be silenced
			if len(modified) < 2 {
				httperr.PrometheusAPIError(w, "need at least one matcher, got none", http.StatusBadRequest)
				return
			}
			sil.Matchers = modified

			var buf bytes.Buffer
			if err := json.NewEncoder(&buf).Encode(&sil); err != nil {
				httperr.PrometheusAPIError(w, fmt.Sprintf("can't encode: %v", err), http.StatusInternalServerError)
				return
			}

			r = r.Clone(r.Context())
			r.Body = io.NopCloser(&buf)
			r.URL.RawQuery = ""
			r.Header["Content-Length"] = []string{strconv.Itoa(buf.Len())}
			r.ContentLength = int64(buf.Len())
			next.ServeHTTP(w, r)
		})
	}
}

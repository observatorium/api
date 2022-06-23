package httperr

import (
	"encoding/json"
	"log"
	"net/http"
)

// Adapted from https://github.com/prometheus-community/prom-label-proxy/blob/02d43edb82b7d139f4a4e41912ad903bff46d5c4/injectproxy/utils.go#L22
func PrometheusAPIError(w http.ResponseWriter, errorMessage string, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)

	// As per Prometheus HTTP API format: https://prometheus.io/docs/prometheus/latest/querying/api/#format-overview
	res := map[string]string{"status": "error", "errorType": "observatorium-api", "error": errorMessage}

	if err := json.NewEncoder(w).Encode(res); err != nil {
		log.Printf("failed to encode json: %v", err)
	}
}

package server

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

// PathsHandlerFunc lists all paths available from the provided routes.
func PathsHandlerFunc(logger log.Logger, routes []chi.Route) http.HandlerFunc {
	paths := make([]string, 0, len(routes))
	for _, r := range routes {
		paths = append(paths, r.Pattern)
	}

	pathsStruct := struct {
		Paths []string `json:"paths"`
	}{
		Paths: paths,
	}

	return func(w http.ResponseWriter, r *http.Request) {
		externalPathJSON, err := json.MarshalIndent(pathsStruct, "", "  ")
		if err != nil {
			level.Error(logger).Log("msg", "failed to marshal paths input to JSON", "err", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		if _, err := w.Write(externalPathJSON); err != nil {
			level.Error(logger).Log("msg", "could not write external paths", "err", err.Error())
		}
	}
}

package v1

import (
	"io"
	"net/http"

	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/rules"
)

type rulesHandler struct {
	client rules.ClientInterface
}

func (rh *rulesHandler) get(w http.ResponseWriter, r *http.Request) {
	tenant, ok := authentication.GetTenant(r.Context())
	if !ok {
		http.Error(w, "error finding tenant", http.StatusUnauthorized)
		return
	}

	resp, err := rh.client.ListRules(r.Context(), tenant)
	if err != nil {
		http.Error(w, "error listing rules %w", resp.StatusCode)
		return
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	if err != nil {
		http.Error(w, "error reading rules response", http.StatusInternalServerError)
		return
	}

	_, err = w.Write(body)
	if err != nil {
		http.Error(w, "error writing rules response", http.StatusInternalServerError)
		return
	}
}

func (rh *rulesHandler) put(w http.ResponseWriter, r *http.Request) {
	tenant, ok := authentication.GetTenant(r.Context())
	if !ok {
		http.Error(w, "error finding tenant", http.StatusUnauthorized)
	}

	resp, err := rh.client.SetRulesWithBody(r.Context(), tenant, r.Header.Get("Content-type"), r.Body)
	if err != nil {
		http.Error(w, "error creating rules %w", resp.StatusCode)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	if err != nil {
		http.Error(w, "error reading rules response", http.StatusInternalServerError)
		return
	}

	_, err = w.Write(body)
	if err != nil {
		http.Error(w, "error writing rules response", http.StatusInternalServerError)
		return
	}
}

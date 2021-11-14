package v1

import (
	"io"
	"io/ioutil"
	"net/http"

	"github.com/ghodss/yaml"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/rules"
)

type rulesHandler struct {
	client      rules.ClientInterface
	logger      log.Logger
	tenantLabel string
}

func (rh *rulesHandler) get(w http.ResponseWriter, r *http.Request) {
	tenant, ok := authentication.GetTenant(r.Context())
	if !ok {
		http.Error(w, "error finding tenant", http.StatusUnauthorized)
		return
	}

	id, ok := authentication.GetTenantID(r.Context())
	if !ok {
		http.Error(w, "error finding tenant ID", http.StatusUnauthorized)
		return
	}

	resp, err := rh.client.ListRules(r.Context(), tenant)
	if err != nil {
		level.Error(rh.logger).Log("msg", "could not list rules", "err", err.Error())

		sc := http.StatusInternalServerError
		if resp != nil {
			sc = resp.StatusCode
		}

		http.Error(w, "error listing rules", sc)

		return
	}

	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		http.Error(w, "error listing rules", resp.StatusCode)
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "error listing rules", http.StatusInternalServerError)
		return
	}

	var rawRules rules.Rules
	if err := yaml.Unmarshal(body, &rawRules); err != nil {
		level.Error(rh.logger).Log("msg", "could not unmarshal rules", "err", err.Error())
		http.Error(w, "error unmarshaling rules", http.StatusInternalServerError)

		return
	}

	for i := range rawRules.Groups {
		for j := range rawRules.Groups[i].Rules {
			switch r := rawRules.Groups[i].Rules[j].(type) {
			case rules.RecordingRule:
				if r.Labels.AdditionalProperties == nil {
					r.Labels.AdditionalProperties = make(map[string]string)
				}

				r.Labels.AdditionalProperties[rh.tenantLabel] = id
				rawRules.Groups[i].Rules[j] = r
			case rules.AlertingRule:
				if r.Labels.AdditionalProperties == nil {
					r.Labels.AdditionalProperties = make(map[string]string)
				}

				r.Labels.AdditionalProperties[rh.tenantLabel] = id
				rawRules.Groups[i].Rules[j] = r
			}
		}
	}

	body, err = yaml.Marshal(rawRules)
	if err != nil {
		level.Error(rh.logger).Log("msg", "could not marshal YAML", "err", err.Error())
		http.Error(w, "error marshaling YAML", http.StatusInternalServerError)

		return
	}

	if _, err := w.Write(body); err != nil {
		level.Error(rh.logger).Log("msg", "could not write body", "err", err.Error())
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
		sc := http.StatusInternalServerError
		if resp != nil {
			sc = resp.StatusCode
		}

		level.Error(rh.logger).Log("msg", "could not set rules", "err", err.Error())
		http.Error(w, "error creating rules", sc)

		return
	}

	defer resp.Body.Close()

	if _, err := io.Copy(w, resp.Body); err != nil {
		http.Error(w, "error writing rules response", http.StatusInternalServerError)
		return
	}
}

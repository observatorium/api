package v1

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/go-chi/chi"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/pkg/rulefmt"
	"gopkg.in/yaml.v3"

	"github.com/observatorium/api/authentication"
)

// ErrRuleNotFound is returned when a particular rule wasn't found by its name.
var ErrRuleNotFound = errors.New("rule not found")

type RuleGroups struct {
	Groups []RuleGroup `yaml:"groups"`
}

type RuleGroup struct {
	Name     string         `yaml:"name"`
	Interval model.Duration `yaml:"interval"`
	Rules    []rulefmt.Rule `yaml:"rules"`
}

type RulesRepository interface {
	RulesLister
	RulesGetter
	//CreateRules()
	RulesUpdater
	//DeleteRules()
}

// WithRulesAPI adds the rules APIs to the API router.
func WithRulesAPI(repository RulesRepository) HandlerOption {
	return func(h *handlerConfiguration) {
		h.router.Get("/rules", h.instrument.NewHandler(
			prometheus.Labels{"group": "metricsv1", "handler": "rules"},
			listRulesHandler(h.logger, repository),
		))
		h.router.Get("/rules/{name}", h.instrument.NewHandler(
			prometheus.Labels{"group": "metricsv1", "handler": "rulesGet"},
			getRuleHandler(h.logger, repository),
		))
		h.router.Get("/rules/{name}/edit", h.instrument.NewHandler(
			prometheus.Labels{"group": "metricsv1", "handler": "rulesEdit"},
			editRuleHandler(h.logger, repository),
		))
		h.router.Post("/rules/{name}", h.instrument.NewHandler(
			prometheus.Labels{"group": "metricsv1", "handler": "rulesUpdate"},
			updateRuleHandler(h.logger, repository),
		))
	}
}

type RulesLister interface {
	ListRuleGroups(ctx context.Context, tenant string) (RuleGroups, error)
}

func listRulesHandler(logger log.Logger, lister RulesLister) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := authentication.GetTenant(r.Context())
		if !ok {
			http.Error(w, "failed to get tenant", http.StatusInternalServerError)
			return
		}

		rules, err := lister.ListRuleGroups(r.Context(), tenant)
		if err != nil {
			msg := "failed to list rules"
			level.Debug(logger).Log("msg", msg, "err", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		bytes, err := yaml.Marshal(rules)
		if err != nil {
			msg := "failed to marshal rules"
			level.Debug(logger).Log("msg", msg, "err", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		_, _ = w.Write(bytes)
	}
}

type RulesGetter interface {
	GetRules(ctx context.Context, tenant string, name string) (RuleGroup, error)
}

func getRuleHandler(logger log.Logger, repository RulesGetter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := authentication.GetTenant(r.Context())
		if !ok {
			http.Error(w, "failed to get tenant", http.StatusInternalServerError)
			return
		}
		name := chi.URLParam(r, "name")

		rules, err := repository.GetRules(r.Context(), tenant, name)
		if err == ErrRuleNotFound {
			msg := "rule not found"
			level.Debug(logger).Log("msg", msg)
			http.Error(w, msg, http.StatusNotFound)
			return
		}
		if err != nil {
			msg := "failed to get rules"
			level.Warn(logger).Log("msg", msg, "err", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		bytes, err := yaml.Marshal(rules)
		if err != nil {
			msg := "failed to marshal rules"
			level.Warn(logger).Log("msg", msg, "err", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		_, _ = w.Write(bytes)
	}
}

const editHTML = `
<html lang="en">
<head>
    <title>Edit Rules - Observatorium</title>
</head>
<body>
    <h3>Edit Rule {{ .Name }}</h3>
    <form action="/api/metrics/v1/{{ .Tenant }}/rules/{{ .Name }}" method="post">
        <textarea cols="120" rows="30" name="rulegroup">{{ .Rules }}</textarea><br>
        <button type="submit">Update</button>
    </form>
</body>
</html>
`

func editRuleHandler(logger log.Logger, repository RulesGetter) http.HandlerFunc {
	tmpl, err := template.New("edit").Parse(editHTML)
	if err != nil {
		level.Error(logger).Log("msg", "failed to parse rule edit HTML", "err", err)
		os.Exit(1)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := authentication.GetTenant(r.Context())
		if !ok {
			http.Error(w, "failed to get tenant", http.StatusInternalServerError)
			return
		}
		name := chi.URLParam(r, "name")

		rules, err := repository.GetRules(r.Context(), tenant, name)
		if err == ErrRuleNotFound {
			const msg = "rule not found"
			level.Debug(logger).Log("msg", msg)
			http.Error(w, msg, http.StatusNotFound)
			return
		}
		if err != nil {
			const msg = "failed to get rules"
			level.Warn(logger).Log("msg", msg, "err", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		bytes, err := yaml.Marshal(rules)
		if err != nil {
			const msg = "failed to marshal rules"
			level.Warn(logger).Log("msg", msg, "err", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		_ = tmpl.Execute(w, struct {
			Name   string
			Rules  string
			Tenant string
		}{
			Name:   name,
			Rules:  string(bytes),
			Tenant: tenant,
		})
	}
}

type RulesUpdater interface {
	UpdateRule(ctx context.Context, tenant string, name string, content []byte) error
}

func updateRuleHandler(logger log.Logger, repository RulesUpdater) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := authentication.GetTenant(r.Context())
		if !ok {
			const msg = "failed to get tenant"
			level.Warn(logger).Log("msg", msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
		name := chi.URLParam(r, "name")

		defer r.Body.Close()

		//mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		//if err != nil {
		//	const msg = "failed to parse media type"
		//	level.Warn(logger).Log("msg", msg, "err", err)
		//	http.Error(w, msg, http.StatusBadRequest)
		//	return
		//}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			const msg = "failed to read rules from request body"
			level.Warn(logger).Log("msg", msg, "err", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		fmt.Println(string(body))

		var group RuleGroup
		if err := yaml.Unmarshal(body, &group); err != nil {
			const msg = "failed to unmarshal YAMl to rule group"
			level.Warn(logger).Log("msg", msg, "err", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		rules, err := yaml.Marshal(group.Rules)
		if err != nil {
			const msg = "failed to unmarshal YAMl to rule group"
			level.Warn(logger).Log("msg", msg, "err", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		if err := repository.UpdateRule(r.Context(), tenant, name, rules); err != nil {
			const msg = "failed to save rules"
			level.Warn(logger).Log("msg", msg, "err", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
	}
}

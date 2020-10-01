package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/server/types"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/observatorium/observatorium/rbac"
)

// Input models the data that is used for OPA input documents.
type Input struct {
	Groups     []string        `json:"groups"`
	Permission rbac.Permission `json:"permission"`
	Resource   string          `json:"resource"`
	Subject    string          `json:"subject"`
	Tenant     string          `json:"tenant"`
}

type config struct {
	logger     log.Logger
	registerer prometheus.Registerer
}

// Option modifies the configuration of an OPA authorizer.
type Option func(c *config)

// LoggerOption sets a custom logger for the authorizer.
func LoggerOption(logger log.Logger) Option {
	return func(c *config) {
		c.logger = logger
	}
}

// RegistererOption sets a Prometheus registerer for the authorizer.
func RegistererOption(r prometheus.Registerer) Option {
	return func(c *config) {
		c.registerer = r
	}
}

type restAuthorizer struct {
	client *http.Client
	url    *url.URL

	logger     log.Logger
	registerer prometheus.Registerer
}

// Authorize implements the rbac.Authorizer interface.
func (a *restAuthorizer) Authorize(subject string, groups []string, permission rbac.Permission, resource, tenant string) bool {
	var i interface{} = Input{
		Groups:     groups,
		Permission: permission,
		Resource:   resource,
		Subject:    subject,
		Tenant:     tenant,
	}
	dreq := types.DataRequestV1{
		Input: &i,
	}
	j, err := json.Marshal(dreq)
	if err != nil {
		level.Error(a.logger).Log("msg", "failed to marshal OPA input to JSON", "err", err.Error())
		return false
	}

	res, err := a.client.Post(a.url.String(), "application/json", bytes.NewBuffer(j))
	if err != nil {
		level.Error(a.logger).Log("msg", "make request to OPA endpoint", "URL", a.url.String(), "err", err.Error())
		return false
	}

	if res.StatusCode/100 != 2 {
		body, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()
		level.Error(a.logger).Log("msg", "received non-200 status code from OPA endpoint", "URL", a.url.String(), "body", body, "status", res.Status)
		return false
	}

	dres := types.DataResponseV1{}
	if err := json.NewDecoder(res.Body).Decode(&dres); err != nil {
		level.Error(a.logger).Log("msg", "failed to unmarshal OPA response", "err", err.Error())
		return false
	}

	if dres.Result == nil {
		level.Error(a.logger).Log("msg", "received an empty OPA response")
		return false
	}

	result, ok := (*dres.Result).(bool)
	if !ok {
		level.Error(a.logger).Log("msg", "received a malformed OPA response")
		return false
	}

	return result
}

// NewRESTAuthorizer creates a new rbac.Authorizer that works against an OPA endpoint.
func NewRESTAuthorizer(u *url.URL, opts ...Option) rbac.Authorizer {
	c := &config{
		logger:     log.NewNopLogger(),
		registerer: prometheus.NewRegistry(),
	}

	for _, o := range opts {
		o(c)
	}

	return &restAuthorizer{
		client:     http.DefaultClient,
		logger:     c.logger,
		registerer: c.registerer,
		url:        u,
	}
}

type inProcessAuthorizer struct {
	query *rego.PreparedEvalQuery

	logger     log.Logger
	registerer prometheus.Registerer
}

// Authorize implements the rbac.Authorizer interface.
func (a *inProcessAuthorizer) Authorize(subject string, groups []string, permission rbac.Permission, resource, tenant string) bool {
	var i interface{} = Input{
		Groups:     groups,
		Permission: permission,
		Resource:   resource,
		Subject:    subject,
		Tenant:     tenant,
	}
	res, err := a.query.Eval(context.Background(), rego.EvalInput(i))
	if err != nil {
		level.Error(a.logger).Log("msg", "failed to evaluate OPA query", "err", err.Error())
		return false
	}

	if len(res) == 0 || len(res[0].Expressions) == 0 || res[0].Expressions[0] == nil {
		level.Error(a.logger).Log("msg", "received a empty OPA response")
		return false
	}

	result, ok := (res[0].Expressions[0].Value).(bool)
	if !ok {
		level.Error(a.logger).Log("msg", "received a malformed OPA response")
		return false
	}

	return result
}

// NewInProcessAuthorizer creates a new rbac.Authorizer that works in-process.
func NewInProcessAuthorizer(query string, paths []string, opts ...Option) (rbac.Authorizer, error) {
	c := &config{
		logger:     log.NewNopLogger(),
		registerer: prometheus.NewRegistry(),
	}

	for _, o := range opts {
		o(c)
	}

	r := rego.New(rego.Query(query), rego.Load(paths, nil))
	q, err := r.PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to prepare OPA query: %w", err)
	}

	return &inProcessAuthorizer{
		logger:     c.logger,
		query:      &q,
		registerer: c.registerer,
	}, nil
}

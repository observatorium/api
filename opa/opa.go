package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/server/types"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/observatorium/api/rbac"
)

const (
	contentTypeHeader           = "Content-Type"
	xForwardedAccessTokenHeader = "X-Forwarded-Access-Token" //nolint:gosec
)

// regoFunctions map is used for the providers' self-registration.
var regoFunctions map[string]func(log.Logger) func(*rego.Rego)

// regoFunctionsMtx is used to protect the providerFactories.
var regoFunctionsMtx sync.RWMutex

func init() {
	regoFunctions = make(map[string]func(log.Logger) func(*rego.Rego))
}

// onboardNewFunction is used by pluggable custom functions to register theirself.
func onboardNewFunction(regoFunctionName string, regoFunction func(log.Logger) func(*rego.Rego)) {
	regoFunctionsMtx.Lock()
	defer regoFunctionsMtx.Unlock()

	regoFunctions[regoFunctionName] = regoFunction
}

// Input models the data that is used for OPA input documents.
type Input struct {
	Groups     []string        `json:"groups"`
	Permission rbac.Permission `json:"permission"`
	Resource   string          `json:"resource"`
	Subject    string          `json:"subject"`
	Tenant     string          `json:"tenant"`
	TenantID   string          `json:"tenantID"`
	Token      string          `json:"token"`
}

type config struct {
	logger          log.Logger
	registerer      prometheus.Registerer
	withAccessToken bool
}

// Option modifies the configuration of an OPA authorizer.
type Option func(c *config)

// LoggerOption sets a custom logger for the authorizer.
func LoggerOption(logger log.Logger) Option {
	return func(c *config) {
		c.logger = logger
	}
}

// AccessTokenOptions sets the flag for the access token requirement.
func AccessTokenOption(f bool) Option {
	return func(c *config) {
		c.withAccessToken = f
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

	logger          log.Logger
	registerer      prometheus.Registerer
	withAccessToken bool
}

// Authorize implements the rbac.Authorizer interface.
func (a *restAuthorizer) Authorize(
	subject string,
	groups []string,
	permission rbac.Permission,
	resource, tenant, tenantID, token string,
) (int, bool, string) {
	var i interface{} = Input{
		Groups:     groups,
		Permission: permission,
		Resource:   resource,
		Subject:    subject,
		Tenant:     tenant,
		TenantID:   tenantID,
	}

	dreq := types.DataRequestV1{
		Input: &i,
	}

	j, err := json.Marshal(dreq)
	if err != nil {
		level.Error(a.logger).Log("msg", "failed to marshal OPA input to JSON", "err", err.Error())

		return http.StatusForbidden, false, ""
	}

	req, err := http.NewRequest(http.MethodPost, a.url.String(), bytes.NewBuffer(j))
	if err != nil {
		level.Error(a.logger).Log("msg", "failed to build authorization request", "err", err.Error())

		return http.StatusInternalServerError, false, ""
	}

	req.Header.Set(contentTypeHeader, "application/json")

	if a.withAccessToken {
		if token == "" {
			level.Error(a.logger).Log("msg", "failed to forward access token to authorization request")

			return http.StatusInternalServerError, false, ""
		}

		req.Header.Set(xForwardedAccessTokenHeader, token)
	}

	res, err := a.client.Do(req)
	if err != nil {
		level.Error(a.logger).Log("msg", "make request to OPA endpoint", "URL", a.url.String(), "err", err.Error())

		if res == nil {
			return http.StatusInternalServerError, false, ""
		}

		return res.StatusCode, false, ""
	}

	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		level.Error(a.logger).Log(
			"msg", "received non-200 status code from OPA endpoint",
			"URL", a.url.String(),
			"body", body,
			"status", res.Status,
		)

		return res.StatusCode, false, ""
	}

	dres := types.DataResponseV1{}
	if err := json.NewDecoder(res.Body).Decode(&dres); err != nil {
		level.Error(a.logger).Log("msg", "failed to unmarshal OPA response", "err", err.Error())

		return http.StatusForbidden, false, ""
	}

	if dres.Result == nil {
		level.Error(a.logger).Log("msg", "received an empty OPA response")

		return http.StatusForbidden, false, ""
	}

	var (
		allowed bool
		data    string
	)

	switch res := (*dres.Result).(type) {
	case bool:
		allowed = res
	case map[string]interface{}:
		allow, ok := res["allowed"]
		if !ok {
			level.Error(a.logger).Log("msg", "received a malformed OPA response")

			return http.StatusForbidden, false, ""
		}

		allowed, err = strconv.ParseBool(allow.(string))
		if err != nil {
			level.Error(a.logger).Log("msg", "received a malformed OPA response")

			return http.StatusForbidden, false, ""
		}

		data = res["data"].(string)

	default:
		level.Error(a.logger).Log("msg", "received a malformed OPA response")

		return http.StatusForbidden, false, ""
	}

	if !allowed {
		return http.StatusForbidden, allowed, data
	}

	return http.StatusOK, allowed, data
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
		client:          http.DefaultClient,
		logger:          c.logger,
		registerer:      c.registerer,
		url:             u,
		withAccessToken: c.withAccessToken,
	}
}

type inProcessAuthorizer struct {
	query *rego.PreparedEvalQuery

	logger     log.Logger
	registerer prometheus.Registerer
}

// Authorize implements the rbac.Authorizer interface.
func (a *inProcessAuthorizer) Authorize(
	subject string,
	groups []string,
	permission rbac.Permission,
	resource, tenant, tenantID, token string,
) (int, bool, string) {
	var i interface{} = Input{
		Groups:     groups,
		Permission: permission,
		Resource:   resource,
		Subject:    subject,
		Tenant:     tenant,
		TenantID:   tenantID,
		Token:      token,
	}

	res, err := a.query.Eval(context.Background(), rego.EvalInput(i))
	if err != nil {
		level.Error(a.logger).Log("msg", "failed to evaluate OPA query", "err", err.Error())

		return http.StatusForbidden, false, ""
	}

	if len(res) == 0 || len(res[0].Expressions) == 0 || res[0].Expressions[0] == nil {
		level.Error(a.logger).Log("msg", "received a empty OPA response")

		return http.StatusForbidden, false, ""
	}

	var (
		allowed bool
		data    string
	)

	switch res := (res[0].Expressions[0].Value).(type) {
	case bool:
		allowed = res
	case map[string]string:
		allow, ok := res["allowed"]
		if !ok {
			level.Error(a.logger).Log("msg", "received a malformed OPA response")

			return http.StatusForbidden, false, ""
		}

		allowed, err = strconv.ParseBool(allow)
		if err != nil {
			level.Error(a.logger).Log("msg", "received a malformed OPA response")

			return http.StatusForbidden, false, ""
		}

		data = res["data"]

	default:
		level.Error(a.logger).Log("msg", "received a malformed OPA response")

		return http.StatusForbidden, false, ""
	}

	if !allowed {
		return http.StatusForbidden, allowed, data
	}

	return http.StatusOK, allowed, data
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

	var r *rego.Rego

	regoArgs := make([]func(*rego.Rego), 0, len(regoFunctions)+2)
	for _, regoFunction := range regoFunctions {
		regoArgs = append(regoArgs, regoFunction(c.logger))
	}

	// Register all provided custom built-in functions
	regoArgs = append(regoArgs, rego.Query(query), rego.Load(paths, nil))

	r = rego.New(regoArgs...)

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

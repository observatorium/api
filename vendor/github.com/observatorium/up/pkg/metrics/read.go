package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/observatorium/up/pkg/auth"
	"github.com/observatorium/up/pkg/instr"
	"github.com/observatorium/up/pkg/options"
	"github.com/observatorium/up/pkg/transport"

	"github.com/go-kit/kit/log"
	"github.com/pkg/errors"
	promapi "github.com/prometheus/client_golang/api"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/prompb"
)

type queryResult struct {
	Type   model.ValueType `json:"resultType"`
	Result interface{}     `json:"result"`

	v model.Value
}

// UnmarshalJSON writes a queryResult instance to a byte sequence supporting scalar, vector and matrics data payloads.
func (qr *queryResult) UnmarshalJSON(b []byte) error {
	v := struct {
		Status string `json:"status"`
		Data   struct {
			Type   model.ValueType `json:"resultType"`
			Result json.RawMessage `json:"result"`
		} `json:"data"`
	}{}

	err := json.Unmarshal(b, &v)
	if err != nil {
		return err
	}

	switch v.Data.Type {
	case model.ValScalar:
		var sv model.Scalar
		err = json.Unmarshal(v.Data.Result, &sv)
		qr.v = &sv

	case model.ValVector:
		var vv model.Vector
		err = json.Unmarshal(v.Data.Result, &vv)
		qr.v = vv

	case model.ValMatrix:
		var mv model.Matrix
		err = json.Unmarshal(v.Data.Result, &mv)
		qr.v = mv

	default:
		err = errors.Errorf("unexpected value type %q", v.Data.Type)
	}

	return err
}

// Read executes query against Prometheus with the same labels to retrieve the written metrics back.
func Read(
	ctx context.Context,
	endpoint *url.URL,
	tp auth.TokenProvider,
	labels []prompb.Label,
	ago, latency time.Duration,
	m instr.Metrics,
	l log.Logger,
	tls options.TLS,
) error {
	var (
		rt  http.RoundTripper
		err error
	)

	if endpoint.Scheme == transport.HTTPS {
		rt, err = transport.NewTLSTransport(l, tls)
		if err != nil {
			return errors.Wrap(err, "create round tripper")
		}

		rt = auth.NewBearerTokenRoundTripper(l, tp, rt)
	} else {
		rt = auth.NewBearerTokenRoundTripper(l, tp, nil)
	}

	client, err := promapi.NewClient(promapi.Config{
		Address:      endpoint.String(),
		RoundTripper: rt,
	})
	if err != nil {
		return err
	}

	labelSelectors := make([]string, len(labels))
	for i, label := range labels {
		labelSelectors[i] = fmt.Sprintf(`%s="%s"`, label.Name, label.Value)
	}

	query := fmt.Sprintf("{%s}", strings.Join(labelSelectors, ","))

	q := endpoint.Query()
	q.Set("query", query)

	ts := time.Now().Add(ago)
	if !ts.IsZero() {
		q.Set("time", formatTime(ts))
	}

	_, body, err := doGetFallback(ctx, client, endpoint, q) //nolint:bodyclose
	if err != nil {
		return errors.Wrap(err, "query request failed")
	}

	var result queryResult
	if err := json.Unmarshal(body, &result); err != nil {
		return errors.Wrap(err, "query response parse failed")
	}

	vec := result.v.(model.Vector)
	if len(vec) != 1 {
		return errors.Errorf("expected one metric, got %d", len(vec))
	}

	t := time.Unix(int64(vec[0].Value/1000), 0) //nolint:mnd

	diffSeconds := time.Since(t).Seconds()

	m.MetricValueDifference.Observe(diffSeconds)

	if diffSeconds > latency.Seconds() {
		return errors.Errorf("metric value is too old: %2.fs", diffSeconds)
	}

	return nil
}

// doGetFallback will attempt to do the request as-is, and on a 405 it will fallback to a GET request.
// Copied from the prometheus API client v1.2.1 (as it was removed afterwards).
// https://github.com/prometheus/client_golang/blob/55450579111f95e3722cb93dec62fe9e847d6130/api/client.go#L64
func doGetFallback(ctx context.Context, c promapi.Client, u *url.URL, args url.Values) (*http.Response, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, u.String(), strings.NewReader(args.Encode()))
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, body, err := c.Do(ctx, req)
	if resp != nil && resp.StatusCode == http.StatusMethodNotAllowed {
		u.RawQuery = args.Encode()
		req, err = http.NewRequest(http.MethodGet, u.String(), nil)

		if err != nil {
			return nil, nil, err
		}
	} else {
		if err != nil {
			return resp, body, err
		}

		return resp, body, nil
	}

	return c.Do(ctx, req)
}

func formatTime(t time.Time) string {
	return strconv.FormatFloat(float64(t.Unix())+float64(t.Nanosecond())/1e9, 'f', -1, 64)
}

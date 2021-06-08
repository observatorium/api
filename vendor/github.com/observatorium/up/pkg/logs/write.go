package logs

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/observatorium/up/pkg/auth"
	"github.com/observatorium/up/pkg/options"
	"github.com/observatorium/up/pkg/transport"

	"github.com/go-kit/kit/log"
	"github.com/pkg/errors"
	"github.com/prometheus/prometheus/prompb"
)

// Write executes a push against Loki sending a set of labels and log entries to store.
func Write(ctx context.Context, endpoint *url.URL, t auth.TokenProvider, wreq *PushRequest, l log.Logger, tls options.TLS) error {
	var (
		buf []byte
		err error
		req *http.Request
		res *http.Response
		rt  http.RoundTripper
	)

	if endpoint.Scheme == transport.HTTPS {
		rt, err = transport.NewTLSTransport(l, tls)
		if err != nil {
			return errors.Wrap(err, "create round tripper")
		}

		rt = auth.NewBearerTokenRoundTripper(l, t, rt)
	} else {
		rt = auth.NewBearerTokenRoundTripper(l, t, nil)
	}

	client := &http.Client{Transport: rt}

	buf, err = json.Marshal(wreq)
	if err != nil {
		return errors.Wrap(err, "marshalling payload")
	}

	req, err = http.NewRequest(http.MethodPost, endpoint.String(), bytes.NewBuffer(buf))
	if err != nil {
		return errors.Wrap(err, "creating request")
	}

	req.Header.Add("Content-Type", "application/json")

	res, err = client.Do(req.WithContext(ctx)) //nolint:bodyclose
	if err != nil {
		return errors.Wrap(err, "making request")
	}

	defer transport.ExhaustCloseWithLogOnErr(l, res.Body)

	if res.StatusCode != http.StatusNoContent {
		err = errors.Errorf(res.Status)
		return errors.Wrap(err, "non-204 status")
	}

	return nil
}

// Generate takes a set of labels and log lines and returns the payload to push logs to Loki.
func Generate(labels []prompb.Label, values [][]string) *PushRequest {
	s := make(map[string]string)
	for _, label := range labels {
		s[label.Name] = label.Value
	}

	return &PushRequest{
		Streams: []stream{
			{
				Stream: s,
				Values: values,
			},
		},
	}
}

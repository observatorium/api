package metrics

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/observatorium/up/pkg/auth"
	"github.com/observatorium/up/pkg/options"
	"github.com/observatorium/up/pkg/transport"

	"github.com/go-kit/kit/log"
	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	"github.com/pkg/errors"
	"github.com/prometheus/prometheus/prompb"
)

// Write executes a remote-write against Prometheus sending a set of labels and metrics to store.
func Write(ctx context.Context, endpoint *url.URL, t auth.TokenProvider, wreq proto.Message, l log.Logger, tls options.TLS) error {
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
	} else {
		rt = http.DefaultTransport
	}

	client := &http.Client{Transport: rt}

	buf, err = proto.Marshal(wreq)
	if err != nil {
		return errors.Wrap(err, "marshalling proto")
	}

	req, err = http.NewRequest("POST", endpoint.String(), bytes.NewBuffer(snappy.Encode(nil, buf)))
	if err != nil {
		return errors.Wrap(err, "creating request")
	}

	token, err := t.Get()
	if err != nil {
		return errors.Wrap(err, "retrieving token")
	}

	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
	}

	res, err = client.Do(req.WithContext(ctx)) //nolint:bodyclose
	if err != nil {
		return errors.Wrap(err, "making request")
	}

	defer transport.ExhaustCloseWithLogOnErr(l, res.Body)

	if res.StatusCode != http.StatusOK {
		err = errors.Errorf(res.Status)
		return errors.Wrap(err, "non-200 status")
	}

	return nil
}

// Generate takes a set of labels and metrics key-value pairs and returns the payload to write metrics to Prometheus.
func Generate(labels []prompb.Label) *prompb.WriteRequest {
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	return &prompb.WriteRequest{
		Timeseries: []prompb.TimeSeries{
			{
				Labels: labels,
				Samples: []prompb.Sample{
					{
						Value:     float64(timestamp),
						Timestamp: timestamp,
					},
				},
			},
		},
	}
}

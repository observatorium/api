package options

import (
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/kit/log/level"
	"github.com/observatorium/up/pkg/auth"
	"github.com/pkg/errors"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/prompb"
)

type TLS struct {
	Cert   string
	Key    string
	CACert string
}

type Options struct {
	LogLevel          level.Option
	EndpointType      EndpointType
	WriteEndpoint     *url.URL
	ReadEndpoint      *url.URL
	Labels            labelArg
	Logs              logs
	Listen            string
	Name              string
	Token             auth.TokenProvider
	Queries           []QuerySpec
	Period            time.Duration
	Duration          time.Duration
	Latency           time.Duration
	InitialQueryDelay time.Duration
	SuccessThreshold  float64
	TLS               TLS
}

type EndpointType string

const (
	LogsEndpointType    EndpointType = "logs"
	MetricsEndpointType EndpointType = "metrics"
)

type QuerySpec struct {
	Name  string `yaml:"name"`
	Query string `yaml:"query"`
}

type labelArg []prompb.Label

func (la *labelArg) String() string {
	ls := make([]string, len(*la))
	for i, l := range *la {
		ls[i] = l.Name + "=" + l.Value
	}

	return strings.Join(ls, ", ")
}

func (la *labelArg) Set(v string) error {
	labels := strings.Split(v, ",")
	lset := make([]prompb.Label, len(labels))

	for i, l := range labels {
		parts := strings.SplitN(l, "=", 2)
		if len(parts) != 2 { //nolint:gomnd
			return errors.Errorf("unrecognized label %q", l)
		}

		if !model.LabelName.IsValid(model.LabelName(parts[0])) {
			return errors.Errorf("unsupported format for label %s", l)
		}

		val, err := strconv.Unquote(parts[1])
		if err != nil {
			return errors.Wrap(err, "unquote label value")
		}

		lset[i] = prompb.Label{Name: parts[0], Value: val}
	}

	*la = lset

	return nil
}

type logs [][]string

func (va *logs) String() string {
	s := make([]string, len(*va))

	for i, l := range *va {
		s[i] = strings.Join(l, ",")
	}

	return strings.Join(s, ",")
}

func (va *logs) Set(v string) error {
	vas := strings.Split(v, "],[")
	vset := make(logs, len(vas))

	for i, v := range vas {
		v = strings.TrimLeft(v, "[")
		v = strings.TrimRight(v, "]")
		vs := strings.Split(v, ",")

		for i, s := range vs {
			vs[i] = strings.Trim(s, `"`)
		}

		vset[i] = vs
	}

	*va = vset

	return nil
}

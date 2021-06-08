package auth

import (
	"net/http"

	"github.com/go-kit/kit/log"
)

type BearerTokenRoundTripper struct {
	l       log.Logger
	r       http.RoundTripper
	t       TokenProvider
	TraceID string
}

func NewBearerTokenRoundTripper(l log.Logger, t TokenProvider, r http.RoundTripper) *BearerTokenRoundTripper {
	if r == nil {
		r = http.DefaultTransport
	}

	return &BearerTokenRoundTripper{
		l: l,
		t: t,
		r: r,
	}
}

func (r *BearerTokenRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := r.t.Get()
	if err != nil {
		return nil, err
	}

	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
	}

	resp, err := r.r.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	r.TraceID = resp.Header.Get("X-Thanos-Trace-Id")

	return resp, err
}

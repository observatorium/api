package ratelimit

import (
	"context"
	"errors"
	"fmt"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/observatorium/api/ratelimit/gubernator"
)

var errOverLimit = errors.New("over limit")

type request struct {
	name     string
	key      string
	limit    int64
	duration int64
}

// Client can connect to gubernator and get rate limits.
type Client struct {
	dialOpts []grpc.DialOption
	client   gubernator.V1Client
}

type SharedRateLimiter interface {
	GetRateLimits(ctx context.Context, req *request) (remaining, resetTime int64, err error)
}

// NewClient creates a new gubernator client with default configuration.
func NewClient(reg prometheus.Registerer) *Client {
	grpcMetrics := grpc_prometheus.NewClientMetrics()
	grpcMetrics.EnableClientHandlingTimeHistogram()
	dialOpts := []grpc.DialOption{
		grpc.WithUnaryInterceptor(
			grpc_middleware.ChainUnaryClient(grpcMetrics.UnaryClientInterceptor()),
		),
		grpc.WithStreamInterceptor(
			grpc_middleware.ChainStreamClient(grpcMetrics.StreamClientInterceptor()),
		),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	if reg != nil {
		reg.MustRegister(grpcMetrics)
	}

	return &Client{dialOpts: dialOpts}
}

// Dial connects the client to gubernator.
func (c *Client) Dial(ctx context.Context, address string) error {
	conn, err := grpc.DialContext(ctx, address, c.dialOpts...)
	if err != nil {
		return fmt.Errorf("failed to dial gubernator with %q: %v", address, err)
	}

	c.client = gubernator.NewV1Client(conn)

	return nil
}

// GetRateLimits gets the rate limits corresponding to a request.
// Note: Dial must be called before calling this method, otherwise the client will panic.
func (c *Client) GetRateLimits(ctx context.Context, req *request) (remaining, resetTime int64, err error) {
	resp, err := c.client.GetRateLimits(ctx, &gubernator.GetRateLimitsReq{
		Requests: []*gubernator.RateLimitReq{{
			Name:      req.name,
			UniqueKey: req.key,
			Hits:      1,
			Limit:     req.limit,
			Duration:  req.duration,
			Algorithm: gubernator.Algorithm_LEAKY_BUCKET,
		}},
	})
	if err != nil {
		return 0, 0, err
	}

	if resp.Responses[0].Status == gubernator.Status_OVER_LIMIT {
		return 0, 0, errOverLimit
	}

	return resp.Responses[0].Remaining, resp.Responses[0].ResetTime, nil
}

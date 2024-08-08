package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/observatorium/api/ratelimit/gubernator"
)

var ErrOverLimit = errors.New("over limit")

type Request struct {
	name  string
	Key   string
	Limit int64
	// Duration is the Duration of the rate limit window in milliseconds.
	Duration      int64
	failOpen      bool
	retryAfterMin time.Duration
	retryAfterMax time.Duration
}

// Client can connect to gubernator and get rate limits.
type Client struct {
	dialOpts []grpc.DialOption
	client   gubernator.V1Client
}

type SharedRateLimiter interface {
	// GetRateLimits retrieves the rate limits for a given request.
	// It returns the remaining requests, the reset time as Unix time (millisecond from epoch), and any error that occurred.
	// When a rate limit is exceeded, the error errOverLimit is returned.
	GetRateLimits(ctx context.Context, req *Request) (remaining, resetTime int64, err error)
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
		grpc.WithDefaultServiceConfig(`{"loadBalancingConfig": [{"round_robin":{}}]}`),
	}

	if reg != nil {
		reg.MustRegister(grpcMetrics)
	}

	return &Client{dialOpts: dialOpts}
}

// Dial connects the client to gubernator.
func (c *Client) Dial(ctx context.Context, address string) error {
	address = fmt.Sprintf("dns:///%s", address)
	conn, err := grpc.DialContext(ctx, address, c.dialOpts...) // nolint: staticcheck
	if err != nil {
		return fmt.Errorf("failed to dial gubernator with %q: %v", address, err)
	}

	c.client = gubernator.NewV1Client(conn)

	return nil
}

// GetRateLimits gets the rate limits corresponding to a request.
// Note: Dial must be called before calling this method, otherwise the client will panic.
func (c *Client) GetRateLimits(ctx context.Context, req *Request) (remaining, resetTime int64, err error) {
	resp, err := c.client.GetRateLimits(ctx, &gubernator.GetRateLimitsReq{
		Requests: []*gubernator.RateLimitReq{{
			Name:      req.name,
			UniqueKey: req.Key,
			Hits:      1,
			Limit:     req.Limit,
			Duration:  req.Duration,
			Algorithm: gubernator.Algorithm_LEAKY_BUCKET,
			Behavior:  gubernator.Behavior_GLOBAL,
		}},
	})
	if err != nil {
		return 0, 0, err
	}

	response := resp.Responses[0]
	if response.Status == gubernator.Status_OVER_LIMIT {
		return 0, 0, ErrOverLimit
	}

	return response.GetRemaining(), response.GetResetTime(), nil
}

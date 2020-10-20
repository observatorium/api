package gubernator

import (
	"context"
	stdlog "log"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
)

// NewClient creates a new gubernator client with default configuration.
func NewClient(ctx context.Context, reg prometheus.Registerer, address string) V1Client {
	grpcMetrics := grpc_prometheus.NewClientMetrics()
	grpcMetrics.EnableClientHandlingTimeHistogram()
	dialOpts := []grpc.DialOption{
		grpc.WithUnaryInterceptor(
			grpc_middleware.ChainUnaryClient(grpcMetrics.UnaryClientInterceptor()),
		),
		grpc.WithStreamInterceptor(
			grpc_middleware.ChainStreamClient(grpcMetrics.StreamClientInterceptor()),
		),
		grpc.WithInsecure(),
	}

	if reg != nil {
		reg.MustRegister(grpcMetrics)
	}

	conn, err := grpc.DialContext(ctx, address, dialOpts...)
	if err != nil {
		stdlog.Fatalf("failed to dial gubernator with %q: %v", address, err)
	}

	return NewV1Client(conn)
}

package v1

import (
	"context"
	stdtls "crypto/tls"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	grpcproxy "github.com/mwitkow/grpc-proxy/proxy"
	"github.com/observatorium/api/tls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// TraceRoute represents the fully-qualified gRPC method name for exporting a trace.
const TraceRoute = "/opentelemetry.proto.collector.trace.v1.TraceService/Export"

type connOptions struct {
	logger             log.Logger
	tracesUpstreamCert *stdtls.Certificate
	tracesUpstreamCA   []byte
}

// ClientOption modifies the connection's configuration.
type ClientOption func(h *connOptions)

// WithLogger add a custom logger for the handler to use.
func WithLogger(logger log.Logger) ClientOption {
	return func(h *connOptions) {
		h.logger = logger
	}
}

func WithUpstreamTLS(tracesUpstreamCA []byte, tracesUpstreamCert *stdtls.Certificate) ClientOption {
	return func(h *connOptions) {
		h.tracesUpstreamCA = tracesUpstreamCA
		h.tracesUpstreamCert = tracesUpstreamCert
	}
}

func newCredentials(upstreamCA []byte, upstreamCert *stdtls.Certificate) credentials.TransportCredentials {
	tlsConfig := tls.NewClientConfig(upstreamCA, upstreamCert)
	if tlsConfig == nil {
		return insecure.NewCredentials()
	}
	return credentials.NewTLS(tlsConfig)
}

// NewOTelConnection creates new GRPC connection to OTel handler.
func NewOTelConnection(write string, opts ...ClientOption) (*grpc.ClientConn, error) {
	c := &connOptions{
		logger: log.NewNopLogger(),
	}

	for _, o := range opts {
		o(c)
	}

	// The endpoint is typically an OTel collector, but can be any gRPC
	// service supporting opentelemetry.proto.collector.trace.v1.TraceService
	level.Info(c.logger).Log("msg", "gRPC dialing OTel", "endpoint", write)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return grpc.DialContext(ctx, write,
		// Note that CustomCodec() is deprecated.  The fix for this isn't calling WithDefaultCallOptions(ForceCodec(...)) as suggested,
		// because the codec we need to register is also deprecated.  A better fix, is the newer
		// version of mwitkow/grpc-proxy, but that version doesn't (currently) work with OTel protocol.
		grpc.WithCodec(grpcproxy.Codec()), // nolint: staticcheck
		grpc.WithTransportCredentials(newCredentials(c.tracesUpstreamCA, c.tracesUpstreamCert)))
}

package v1

import (
	"context"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	grpcproxy "github.com/mwitkow/grpc-proxy/proxy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const TraceRoute = "/opentelemetry.proto.collector.trace.v1.TraceService/Export"

type handlerConfiguration struct {
	logger log.Logger
}

// HandlerOption modifies the handler's configuration.
type HandlerOption func(h *handlerConfiguration)

// WithLogger add a custom logger for the handler to use.
func WithLogger(logger log.Logger) HandlerOption {
	return func(h *handlerConfiguration) {
		h.logger = logger
	}
}

// NewHandler creates the new traces v1 handler.
func NewOTelConnection(write string, opts ...HandlerOption) (*grpc.ClientConn, error) {
	c := &handlerConfiguration{
		logger: log.NewNopLogger(),
	}

	for _, o := range opts {
		o(c)
	}

	level.Info(c.logger).Log("msg", "gRPC dialing OTel collector", "endpoint", write)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	connOtel, err := grpc.DialContext(ctx, write,
		// Note that CustomCodec() is deprecated.  The fix for this isn't calling WithDefaultCallOptions(ForceCodec(...)) as suggested,
		// because the codec we need to register is also deprecated.  A better fix, is the newer
		// version of mwitkow/grpc-proxy, but that version doesn't (currently) work with OTel protocol.
		grpc.WithCodec(grpcproxy.Codec()), // nolint: staticcheck
		grpc.WithTransportCredentials(insecure.NewCredentials()))

	// Note that err == nil does not mean connected; this is a non-blocking ClientConn.
	if err != nil {
		level.Warn(c.logger).Log("msg", "gRPC did not dial to OTel collector", "target", write)
		return nil, err
	}

	return connOtel, nil
}

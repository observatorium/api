package v1

import (
	"context"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	grpcproxy "github.com/mwitkow/grpc-proxy/proxy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const traceRoute = "/opentelemetry.proto.collector.trace.v1.TraceService/Export"

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
func NewHandler(write string, opts ...HandlerOption) grpcproxy.StreamDirector {
	c := &handlerConfiguration{
		logger: log.NewNopLogger(),
	}

	for _, o := range opts {
		o(c)
	}

	var conn *grpc.ClientConn

	director := func(ctx context.Context, fullMethodName string) (context.Context, *grpc.ClientConn, error) {
		md, _ := metadata.FromIncomingContext(ctx)

		outCtx := metadata.NewOutgoingContext(ctx, md.Copy())

		if fullMethodName == traceRoute {
			var err error

			if conn == nil {
				// Create the connection lazily, when we first receive a trace to forward
				level.Info(c.logger).Log("msg", "gRPC dialing OTel collector")

				// TODO test where the keep-alive fails and the connection closes
				conn, err = grpc.DialContext(ctx, write,
					// Note that CustomCodec() is deprecated.  The fix for this isn't calling WithDefaultCallOptions(ForceCodec(...)) as suggested,
					// because the codec we need to register is also deprecated.  A better fix, if Google removes
					// the deprecated type, is https://github.com/mwitkow/grpc-proxy/pull/48
					grpc.WithCodec(grpcproxy.Codec()), // nolint: staticcheck
					grpc.WithInsecure(),               // nolint: staticcheck
					grpc.WithBlock())

				if err == nil {
					level.Info(c.logger).Log("msg", "gRPC connected to OTel collector")
				} else {
					conn = nil
					level.Warn(c.logger).Log("msg", "gRPC did not connect to OTel collector")
				}
			}

			return outCtx, conn, err
		}

		level.Info(c.logger).Log("msg", "gRPC reverse proxy director caught unknown method", "methodName", fullMethodName)

		return outCtx, nil, status.Errorf(codes.Unimplemented, "Unknown method")
	}

	return director
}

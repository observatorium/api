package authentication

import (
	"context"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// WithGRPCMTLSTenantExtraction returns a gRPC StreamServerInterceptor that extracts tenant from
// the client certificate's OrganizationalUnit field and adds it to the gRPC metadata.
// This is designed for write-path authentication where machines authenticate via mTLS.
func WithGRPCMTLSTenantExtraction(tenantHeader string, logger log.Logger) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()

		// Extract peer information (TLS state)
		p, ok := peer.FromContext(ctx)
		if !ok {
			level.Debug(logger).Log("msg", "no peer information in gRPC context")
			return status.Error(codes.Unauthenticated, "no peer information")
		}

		// Check for TLS credentials
		tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok {
			level.Debug(logger).Log("msg", "no TLS credentials in gRPC peer")
			return status.Error(codes.Unauthenticated, "TLS connection required")
		}

		if len(tlsInfo.State.PeerCertificates) == 0 {
			level.Debug(logger).Log("msg", "no client certificate in gRPC TLS connection")
			return status.Error(codes.Unauthenticated, "client certificate required")
		}

		cert := tlsInfo.State.PeerCertificates[0]

		// Note: Certificate has already been verified by the TLS handshake when
		// the server is configured with RequireAndVerifyClientCert.
		// We just need to extract the tenant from the OU field.

		// Extract tenant from OrganizationalUnit field
		if len(cert.Subject.OrganizationalUnit) == 0 {
			level.Debug(logger).Log("msg", "no organizational unit in client certificate")
			return status.Error(codes.InvalidArgument, "tenant not found in certificate OU")
		}

		// Use the first OU as the tenant identifier
		tenant := cert.Subject.OrganizationalUnit[0]

		level.Debug(logger).Log("msg", "extracted tenant from gRPC mTLS certificate", "tenant", tenant)

		// Add tenant to context
		ctx = context.WithValue(ctx, tenantKey, tenant)

		// Add tenant to outgoing metadata for upstream forwarding
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			md = metadata.New(nil)
		} else {
			md = md.Copy()
		}
		md.Set(tenantHeader, tenant)
		ctx = metadata.NewIncomingContext(ctx, md)

		// Create a new server stream with the updated context
		wrappedStream := &wrappedServerStream{
			ServerStream: ss,
			ctx:          ctx,
		}

		return handler(srv, wrappedStream)
	}
}

// wrappedServerStream wraps a grpc.ServerStream to override the context.
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the wrapped context.
func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

package authentication

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-kit/log"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware/v2"
	grpc_middleware_auth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	_ "google.golang.org/grpc/encoding/gzip" // Allow GRPC to handle GZipped streams
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// GRPCMiddlewareFunc is a function type able to return authentication middleware for
// a given tenant. If no middleware is found, the second return value should be false.
type GRPCMiddlewareFunc func(tenant string) (grpc.StreamServerInterceptor, bool)

// WithGRPCTenantHeader returns a new StreamServerInterceptor that adds the tenant and tenantID
// to the stream Context.
func WithGRPCTenantHeader(header string, tenantIDs map[string]string, logger log.Logger) grpc.StreamServerInterceptor {
	header = strings.ToLower(header)

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return status.Errorf(codes.Internal, "metadata not found")
		}

		headerTenants := md[header]
		if len(headerTenants) == 0 {
			return status.Errorf(codes.InvalidArgument, fmt.Sprintf("header %q not set", header))
		}
		if len(headerTenants) > 1 {
			return status.Errorf(codes.InvalidArgument, fmt.Sprintf("header %q requested multiple tenants", header))
		}

		tenant := headerTenants[0]
		ctx = context.WithValue(ctx, tenantKey, tenant)

		id, ok := tenantIDs[tenant]
		if !ok {
			// This lets unauthenticated users know the tenant is invalid, but can't be helped, as we
			// can't validate the bearer token until we know the tenant.  (An alternative is to return
			// codes.Unauthenticated and not explain about the tenant if this is a concern.)
			return status.Error(codes.InvalidArgument, "unknown tenant")
		}
		// The tenant header contains the tenant name.
		// It needs to be overridden to send the ID to match the HTTP functionality from openshift.WithTenantHeader.
		md.Set(header, id)
		ctx = metadata.NewIncomingContext(ctx, md)
		ctx = context.WithValue(ctx, tenantIDKey, id)

		wrapped := grpc_middleware.WrapServerStream(ss)
		wrapped.WrappedContext = ctx

		return handler(srv, wrapped)
	}
}

func WithGRPCAccessToken() grpc.StreamServerInterceptor {
	return grpc_middleware_auth.StreamServerInterceptor(func(ctx context.Context) (context.Context, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Internal, "metadata error")
		}
		rawTokens := md["authorization"]
		if len(rawTokens) == 0 {
			return ctx, status.Error(codes.Unauthenticated, "error no access token")
		}
		rawToken := rawTokens[len(rawTokens)-1]
		token := rawToken[strings.LastIndex(rawToken, " ")+1:]
		return context.WithValue(ctx, accessTokenKey, token), nil
	})
}

// WithGRPCTenantInterceptors creates a single Middleware for all
// provided tenant-middleware sets.
func WithGRPCTenantInterceptors(logger log.Logger, mwFns ...GRPCMiddlewareFunc) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		tenant, ok := GetTenant(ss.Context())
		if !ok {
			return status.Error(codes.InvalidArgument, "error finding tenant")
		}

		for _, mwFn := range mwFns {
			if m, ok := mwFn(tenant); ok {
				return m(srv, ss, info, handler)
			}
		}

		return status.Error(codes.PermissionDenied, "tenant not found, have you registered it?")
	}
}

package authorization

import (
	"context"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	grpc_middleware_auth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/rbac"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AccessRequirement holds a permission for a particular resource type.
type AccessRequirement struct {
	Permission rbac.Permission
	// Resource is typically "logs", "metrics", or "traces"
	Resource string
}

// GRPCRBac represents the RBAC requirements for a particular fully-qualified gRPC Method.
// For example, "opentelemetry.proto.collector.trace.v1.TraceService/Export"
// requires "write" permission for "traces".
type GRPCRBac map[string]AccessRequirement

// WithGRPCAuthorizers is the gRPC version of WithAuthorizers.
func WithGRPCAuthorizers(authorizers map[string]rbac.Authorizer, methReq GRPCRBac, logger log.Logger) grpc_middleware_auth.AuthFunc {
	return func(ctx context.Context) (context.Context, error) {
		fullMethodName, ok := grpc.Method(ctx)
		if !ok {
			return ctx, status.Error(codes.Internal, "fullMethodName not in context")
		}

		accessReq, ok := methReq[fullMethodName]
		if !ok {
			return ctx, status.Error(codes.PermissionDenied, "method never permitted")
		}

		tenant, ok := authentication.GetTenant(ctx)
		if !ok {
			return ctx, status.Error(codes.Internal, "error finding tenant")
		}

		subject, ok := authentication.GetSubject(ctx)
		if !ok {
			return ctx, status.Error(codes.PermissionDenied, "unknown subject")
		}

		groups, ok := authentication.GetGroups(ctx)
		if !ok {
			groups = []string{}
		}
		a, ok := authorizers[tenant]
		if !ok {
			return ctx, status.Error(codes.Unauthenticated, "error finding tenant")
		}

		token, ok := authentication.GetAccessToken(ctx)
		if !ok {
			return ctx, status.Error(codes.Unauthenticated, "error finding access token")
		}

		tenantID, ok := authentication.GetTenantID(ctx)
		if !ok {
			return ctx, status.Error(codes.Unauthenticated, "error finding tenant id")
		}

		_, ok, data := a.Authorize(subject, groups, accessReq.Permission, accessReq.Resource, tenant, tenantID, token)
		if !ok {
			level.Debug(logger).Log("msg", "gRPC Authorizer: insufficient auth", "subject", subject, "tenant", tenant)
			return ctx, status.Error(codes.PermissionDenied, "forbidden")
		}

		return context.WithValue(ctx, authorizationDataKey, data), nil
	}
}

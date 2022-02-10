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

type MethodName string

type AccessRequirement struct {
	Permission rbac.Permission
	Resource   string
}

type GRPCRBac map[MethodName]AccessRequirement

// WithGRPCAuthorizers is the gRPC version of WithAuthorizers
func WithGRPCAuthorizers(authorizers map[string]rbac.Authorizer, methReq GRPCRBac, logger log.Logger) grpc_middleware_auth.AuthFunc {
	return func(ctx context.Context) (context.Context, error) {
		fullMethodName, ok := grpc.Method(ctx)
		if !ok {
			level.Warn(logger).Log("msg", "fullMethodName not in context")
			return ctx, status.Error(codes.Internal, "fullMethodName not in context")
		}

		accessReq, ok := methReq[MethodName(fullMethodName)]
		if !ok {
			level.Debug(logger).Log("msg", "method never permitted", "method", fullMethodName)
			return ctx, status.Error(codes.PermissionDenied, "method never permitted")
		}

		tenant, ok := authentication.GetTenant(ctx)
		if !ok {
			level.Debug(logger).Log("msg", "gRPC Authorizer: no tenant")
			return ctx, status.Error(codes.Internal, "error finding tenant")
		}

		subject, ok := authentication.GetSubject(ctx)
		if !ok {
			level.Debug(logger).Log("msg", "gRPC Authorizer: unknown subject")
			return ctx, status.Error(codes.PermissionDenied, "unknown subject")
		}

		groups, ok := authentication.GetGroups(ctx)
		if !ok {
			groups = []string{}
		}
		a, ok := authorizers[tenant]
		if !ok {
			level.Debug(logger).Log("msg", "gRPC Authorizer: unregistered tenant", "tenant", tenant)
			return ctx, status.Error(codes.Unauthenticated, "error finding tenant")
		}

		token, ok := authentication.GetAccessToken(ctx)
		if !ok {
			level.Debug(logger).Log("msg", "gRPC Authorizer: no access token")
			return ctx, status.Error(codes.Unauthenticated, "error finding access token")
		}

		tenantID, ok := authentication.GetTenantID(ctx)
		if !ok {
			level.Debug(logger).Log("msg", "gRPC Authorizer: finding tenant id")
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

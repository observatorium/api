package authentication

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/go-kit/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// mockServerStream implements grpc.ServerStream for testing
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func TestWithGRPCMTLSTenantExtraction(t *testing.T) {
	logger := log.NewNopLogger()
	tenantHeader := "x-tenant"

	t.Run("extracts tenant from gRPC peer certificate", func(t *testing.T) {
		interceptor := WithGRPCMTLSTenantExtraction(tenantHeader, logger)

		cert := &x509.Certificate{
			Subject: pkix.Name{
				OrganizationalUnit: []string{"team-alpha"},
			},
		}

		tlsInfo := credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		}

		p := &peer.Peer{
			AuthInfo: tlsInfo,
		}

		ctx := peer.NewContext(context.Background(), p)
		ss := &mockServerStream{ctx: ctx}

		var capturedTenant string
		var capturedMetadata metadata.MD
		handler := func(srv interface{}, stream grpc.ServerStream) error {
			tenant, ok := GetTenant(stream.Context())
			if ok {
				capturedTenant = tenant
			}
			md, ok := metadata.FromIncomingContext(stream.Context())
			if ok {
				capturedMetadata = md
			}
			return nil
		}

		err := interceptor(nil, ss, nil, handler)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if capturedTenant != "team-alpha" {
			t.Errorf("expected tenant 'team-alpha', got '%s'", capturedTenant)
		}

		tenantValues := capturedMetadata.Get(tenantHeader)
		if len(tenantValues) == 0 || tenantValues[0] != "team-alpha" {
			t.Errorf("expected metadata tenant 'team-alpha', got %v", tenantValues)
		}
	})

	t.Run("returns error when no peer information", func(t *testing.T) {
		interceptor := WithGRPCMTLSTenantExtraction(tenantHeader, logger)

		ctx := context.Background()
		ss := &mockServerStream{ctx: ctx}

		handler := func(srv interface{}, stream grpc.ServerStream) error {
			t.Fatal("handler should not be called")
			return nil
		}

		err := interceptor(nil, ss, nil, handler)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("expected gRPC status error")
		}

		if st.Code() != codes.Unauthenticated {
			t.Errorf("expected code Unauthenticated, got %v", st.Code())
		}
	})

	t.Run("returns error when no TLS credentials", func(t *testing.T) {
		interceptor := WithGRPCMTLSTenantExtraction(tenantHeader, logger)

		// Peer with non-TLS auth info
		p := &peer.Peer{
			AuthInfo: nil,
		}

		ctx := peer.NewContext(context.Background(), p)
		ss := &mockServerStream{ctx: ctx}

		handler := func(srv interface{}, stream grpc.ServerStream) error {
			t.Fatal("handler should not be called")
			return nil
		}

		err := interceptor(nil, ss, nil, handler)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("expected gRPC status error")
		}

		if st.Code() != codes.Unauthenticated {
			t.Errorf("expected code Unauthenticated, got %v", st.Code())
		}
	})

	t.Run("returns error when no client certificate", func(t *testing.T) {
		interceptor := WithGRPCMTLSTenantExtraction(tenantHeader, logger)

		tlsInfo := credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{},
			},
		}

		p := &peer.Peer{
			AuthInfo: tlsInfo,
		}

		ctx := peer.NewContext(context.Background(), p)
		ss := &mockServerStream{ctx: ctx}

		handler := func(srv interface{}, stream grpc.ServerStream) error {
			t.Fatal("handler should not be called")
			return nil
		}

		err := interceptor(nil, ss, nil, handler)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("expected gRPC status error")
		}

		if st.Code() != codes.Unauthenticated {
			t.Errorf("expected code Unauthenticated, got %v", st.Code())
		}
	})

	t.Run("returns error when certificate has no OU", func(t *testing.T) {
		interceptor := WithGRPCMTLSTenantExtraction(tenantHeader, logger)

		cert := &x509.Certificate{
			Subject: pkix.Name{
				OrganizationalUnit: []string{},
			},
		}

		tlsInfo := credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		}

		p := &peer.Peer{
			AuthInfo: tlsInfo,
		}

		ctx := peer.NewContext(context.Background(), p)
		ss := &mockServerStream{ctx: ctx}

		handler := func(srv interface{}, stream grpc.ServerStream) error {
			t.Fatal("handler should not be called")
			return nil
		}

		err := interceptor(nil, ss, nil, handler)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatal("expected gRPC status error")
		}

		if st.Code() != codes.InvalidArgument {
			t.Errorf("expected code InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("uses first OU when multiple present", func(t *testing.T) {
		interceptor := WithGRPCMTLSTenantExtraction(tenantHeader, logger)

		cert := &x509.Certificate{
			Subject: pkix.Name{
				OrganizationalUnit: []string{"first-tenant", "second-tenant"},
			},
		}

		tlsInfo := credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		}

		p := &peer.Peer{
			AuthInfo: tlsInfo,
		}

		ctx := peer.NewContext(context.Background(), p)
		ss := &mockServerStream{ctx: ctx}

		var capturedTenant string
		handler := func(srv interface{}, stream grpc.ServerStream) error {
			tenant, _ := GetTenant(stream.Context())
			capturedTenant = tenant
			return nil
		}

		err := interceptor(nil, ss, nil, handler)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if capturedTenant != "first-tenant" {
			t.Errorf("expected first OU 'first-tenant', got '%s'", capturedTenant)
		}
	})

	t.Run("merges with existing metadata", func(t *testing.T) {
		interceptor := WithGRPCMTLSTenantExtraction(tenantHeader, logger)

		cert := &x509.Certificate{
			Subject: pkix.Name{
				OrganizationalUnit: []string{"team-beta"},
			},
		}

		tlsInfo := credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		}

		p := &peer.Peer{
			AuthInfo: tlsInfo,
		}

		// Add existing metadata
		md := metadata.New(map[string]string{
			"existing-key": "existing-value",
		})
		ctx := metadata.NewIncomingContext(context.Background(), md)
		ctx = peer.NewContext(ctx, p)
		ss := &mockServerStream{ctx: ctx}

		var capturedMetadata metadata.MD
		handler := func(srv interface{}, stream grpc.ServerStream) error {
			md, ok := metadata.FromIncomingContext(stream.Context())
			if ok {
				capturedMetadata = md
			}
			return nil
		}

		err := interceptor(nil, ss, nil, handler)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Check existing metadata is preserved
		existingValues := capturedMetadata.Get("existing-key")
		if len(existingValues) == 0 || existingValues[0] != "existing-value" {
			t.Errorf("expected existing metadata to be preserved, got %v", existingValues)
		}

		// Check new tenant metadata is added
		tenantValues := capturedMetadata.Get(tenantHeader)
		if len(tenantValues) == 0 || tenantValues[0] != "team-beta" {
			t.Errorf("expected tenant metadata 'team-beta', got %v", tenantValues)
		}
	})
}

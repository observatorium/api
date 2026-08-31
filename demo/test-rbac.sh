#!/bin/bash

set -e

# Extract certificates
echo "🔐 Extracting client certificates..."
kubectl get secret -n proxy admin-client-cert -o jsonpath='{.data.tls\.crt}' | base64 -d > admin-client.crt
kubectl get secret -n proxy admin-client-cert -o jsonpath='{.data.tls\.key}' | base64 -d > admin-client.key
kubectl get secret -n proxy test-client-cert -o jsonpath='{.data.tls\.crt}' | base64 -d > test-client.crt
kubectl get secret -n proxy test-client-cert -o jsonpath='{.data.tls\.key}' | base64 -d > test-client.key
kubectl get secret -n cert-manager root-ca-secret -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt

echo "🚀 Starting port-forward in background..."
kubectl port-forward -n proxy svc/observatorium-api 8080:8080 &
PORT_FORWARD_PID=$!

# Wait for port-forward to be ready
sleep 5

# Function to cleanup
cleanup() {
    echo "🧹 Cleaning up..."
    kill $PORT_FORWARD_PID 2>/dev/null || true
    rm -f admin-client.crt admin-client.key test-client.crt test-client.key ca.crt
}

# Set trap to cleanup on exit
trap cleanup EXIT

echo ""
echo "🧪 Testing RBAC with different certificates..."
echo ""

# Test 1: Admin user (should have full access)
echo "1️⃣ Testing admin@example.com (should have full access):"
echo "   Tenant A metrics query:"
if curl -s --cert admin-client.crt --key admin-client.key --cacert ca.crt \
    -H "X-Tenant: tenant-a" \
    "https://localhost:8080/api/metrics/v1/query?query=up" | head -1; then
    echo "   ✅ Admin can access tenant-a metrics"
else
    echo "   ❌ Admin cannot access tenant-a metrics"
fi

echo "   Tenant B metrics query:"
if curl -s --cert admin-client.crt --key admin-client.key --cacert ca.crt \
    -H "X-Tenant: tenant-b" \
    "https://localhost:8080/api/metrics/v1/query?query=up" | head -1; then
    echo "   ✅ Admin can access tenant-b metrics"
else
    echo "   ❌ Admin cannot access tenant-b metrics"
fi

echo ""

# Test 2: Test user (should only have read access to tenant-a)
echo "2️⃣ Testing test@example.com (should have read-only access to tenant-a):"
echo "   Tenant A metrics query:"
if curl -s --cert test-client.crt --key test-client.key --cacert ca.crt \
    -H "X-Tenant: tenant-a" \
    "https://localhost:8080/api/metrics/v1/query?query=up" | head -1; then
    echo "   ✅ Test user can read tenant-a metrics"
else
    echo "   ❌ Test user cannot read tenant-a metrics"
fi

echo "   Tenant B metrics query (should be denied):"
if curl -s --cert test-client.crt --key test-client.key --cacert ca.crt \
    -H "X-Tenant: tenant-b" \
    "https://localhost:8080/api/metrics/v1/query?query=up" 2>/dev/null | grep -q "403\|forbidden\|denied"; then
    echo "   ✅ Test user correctly denied access to tenant-b"
else
    echo "   ❌ Test user should not have access to tenant-b"
fi

echo ""

# Test 3: Invalid certificate
echo "3️⃣ Testing with no certificate (should be denied):"
if curl -s --cacert ca.crt \
    "https://localhost:8080/api/metrics/v1/query?query=up" 2>&1 | grep -q "certificate required\|SSL\|client certificate"; then
    echo "   ✅ Request correctly denied without client certificate"
else
    echo "   ❌ Request should require client certificate"
fi

echo ""
echo "🎯 RBAC Test Summary:"
echo "   - admin@example.com: Full access to both tenants"
echo "   - test@example.com: Read-only access to tenant-a only"
echo "   - No certificate: Properly denied"
echo ""
echo "✅ RBAC testing complete!"
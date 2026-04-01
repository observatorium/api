#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔐 Setting up path-based RBAC tests...${NC}"

# Extract certificates
echo "🔑 Extracting client certificates..."
kubectl get secret -n proxy admin-client-cert -o jsonpath='{.data.tls\.crt}' | base64 -d > admin-client.crt
kubectl get secret -n proxy admin-client-cert -o jsonpath='{.data.tls\.key}' | base64 -d > admin-client.key
kubectl get secret -n proxy test-client-cert -o jsonpath='{.data.tls\.crt}' | base64 -d > test-client.crt
kubectl get secret -n proxy test-client-cert -o jsonpath='{.data.tls\.key}' | base64 -d > test-client.key
kubectl get secret -n cert-manager root-ca-secret -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt

# Extract additional certificates if they exist
if kubectl get secret -n proxy query-user-cert >/dev/null 2>&1; then
  kubectl get secret -n proxy query-user-cert -o jsonpath='{.data.tls\.crt}' | base64 -d > query-user.crt
  kubectl get secret -n proxy query-user-cert -o jsonpath='{.data.tls\.key}' | base64 -d > query-user.key
fi

if kubectl get secret -n proxy write-user-cert >/dev/null 2>&1; then
  kubectl get secret -n proxy write-user-cert -o jsonpath='{.data.tls\.crt}' | base64 -d > write-user.crt
  kubectl get secret -n proxy write-user-cert -o jsonpath='{.data.tls\.key}' | base64 -d > write-user.key
fi

if kubectl get secret -n proxy logs-reader-cert >/dev/null 2>&1; then
  kubectl get secret -n proxy logs-reader-cert -o jsonpath='{.data.tls\.crt}' | base64 -d > logs-reader.crt
  kubectl get secret -n proxy logs-reader-cert -o jsonpath='{.data.tls\.key}' | base64 -d > logs-reader.key
fi

# Start port-forward
echo "🚀 Starting port-forward in background..."
kubectl port-forward -n proxy svc/observatorium-api 8080:8080 &
PORT_FORWARD_PID=$!

# Wait for port-forward to be ready
sleep 3

echo -e "${BLUE}🧪 Testing path-based RBAC with different certificates...${NC}"

# Function to test endpoint
test_endpoint() {
    local cert_file="$1"
    local key_file="$2"
    local tenant="$3"
    local path="$4"
    local user_desc="$5"
    local expected_status="$6"
    
    echo -n "   Testing ${user_desc} accessing ${path} (tenant: ${tenant}): "
    
    if [[ ! -f "$cert_file" || ! -f "$key_file" ]]; then
        echo -e "${YELLOW}SKIP (certificates not found)${NC}"
        return
    fi
    
    response=$(curl -s -w "%{http_code}" --cert "$cert_file" --key "$key_file" --cacert ca.crt \
        -H "X-Tenant: $tenant" \
        "https://localhost:8080$path" 2>/dev/null || echo "000")
    
    status_code="${response: -3}"
    
    if [[ "$status_code" == "$expected_status" ]]; then
        echo -e "${GREEN}✅ Expected ${expected_status}, got ${status_code}${NC}"
    else
        echo -e "${RED}❌ Expected ${expected_status}, got ${status_code}${NC}"
    fi
}

echo -e "${YELLOW}1️⃣ Testing admin@example.com (should have full access to all paths):${NC}"
test_endpoint "admin-client.crt" "admin-client.key" "tenant-a" "/api/metrics/v1/query?query=up" "admin" "200"
test_endpoint "admin-client.crt" "admin-client.key" "tenant-a" "/api/metrics/v1/query_range?query=up&start=0&end=1&step=1" "admin" "200"
test_endpoint "admin-client.crt" "admin-client.key" "tenant-a" "/api/metrics/v1/receive" "admin" "200"
test_endpoint "admin-client.crt" "admin-client.key" "tenant-a" "/api/logs/v1/query?query={}" "admin" "200"
test_endpoint "admin-client.crt" "admin-client.key" "tenant-b" "/api/metrics/v1/query?query=up" "admin" "200"

echo -e "${YELLOW}2️⃣ Testing test@example.com (should have limited read access):${NC}"
test_endpoint "test-client.crt" "test-client.key" "tenant-a" "/api/metrics/v1/query?query=up" "test user" "200"
test_endpoint "test-client.crt" "test-client.key" "tenant-a" "/api/metrics/v1/query_range?query=up&start=0&end=1&step=1" "test user" "200"
test_endpoint "test-client.crt" "test-client.key" "tenant-a" "/api/metrics/v1/receive" "test user" "403"
test_endpoint "test-client.crt" "test-client.key" "tenant-b" "/api/metrics/v1/query?query=up" "test user" "403"

echo -e "${YELLOW}3️⃣ Testing query-only access (if certificate exists):${NC}"
test_endpoint "query-user.crt" "query-user.key" "tenant-a" "/api/metrics/v1/query?query=up" "query-only user" "200"
test_endpoint "query-user.crt" "query-user.key" "tenant-a" "/api/metrics/v1/receive" "query-only user" "403"
test_endpoint "query-user.crt" "query-user.key" "tenant-a" "/api/metrics/v1/series" "query-only user" "403"

echo -e "${YELLOW}4️⃣ Testing write-only access (if certificate exists):${NC}"
test_endpoint "write-user.crt" "write-user.key" "tenant-b" "/api/metrics/v1/receive" "write-only user" "200"
test_endpoint "write-user.crt" "write-user.key" "tenant-b" "/api/metrics/v1/query?query=up" "write-only user" "403"

echo -e "${YELLOW}5️⃣ Testing logs-reader access (if certificate exists):${NC}"
test_endpoint "logs-reader.crt" "logs-reader.key" "tenant-a" "/api/logs/v1/query?query={}" "logs reader" "200"
test_endpoint "logs-reader.crt" "logs-reader.key" "tenant-b" "/api/logs/v1/query?query={}" "logs reader" "200"
test_endpoint "logs-reader.crt" "logs-reader.key" "tenant-a" "/api/metrics/v1/query?query=up" "logs reader" "403"

echo -e "${YELLOW}6️⃣ Testing no certificate (should be denied):${NC}"
response=$(curl -s -w "%{http_code}" -H "X-Tenant: tenant-a" \
    "https://localhost:8080/api/metrics/v1/query?query=up" 2>/dev/null || echo "000")
status_code="${response: -3}"
echo -n "   No certificate access: "
if [[ "$status_code" == "000" || "$status_code" == "403" ]]; then
    echo -e "${GREEN}✅ Properly denied (${status_code})${NC}"
else
    echo -e "${RED}❌ Should be denied but got ${status_code}${NC}"
fi

echo -e "${BLUE}🎯 Path-based RBAC Test Summary:${NC}"
echo "   - admin@example.com: Full access to all paths and tenants"
echo "   - test@example.com: Limited read access to specific paths in tenant-a"
echo "   - query@example.com: Query-only access (query and query_range endpoints)"
echo "   - write@example.com: Write-only access (receive endpoint)"
echo "   - logs-reader@example.com: Logs read access across tenants"
echo "   - No certificate: Properly denied"

echo -e "${GREEN}✅ Path-based RBAC testing complete!${NC}"

# Cleanup
echo "🧹 Cleaning up..."
kill $PORT_FORWARD_PID 2>/dev/null || true
rm -f *.crt *.key 2>/dev/null || true
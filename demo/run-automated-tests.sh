#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔬 Running Automated Path-Based RBAC Tests${NC}"
echo "=============================================="

# Function to cleanup on exit
cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up...${NC}"
    if [[ -n "$PORT_FORWARD_PID" ]]; then
        kill $PORT_FORWARD_PID 2>/dev/null || true
    fi
    rm -f *.crt *.key 2>/dev/null || true
}

trap cleanup EXIT

# Check if the cluster is running
if ! kubectl get nodes >/dev/null 2>&1; then
    echo -e "${RED}❌ Kubernetes cluster not accessible. Please ensure KinD cluster is running.${NC}"
    exit 1
fi

# Check if observatorium-api is deployed
if ! kubectl get deployment observatorium-api -n proxy >/dev/null 2>&1; then
    echo -e "${RED}❌ Observatorium API not found. Please run the demo setup first.${NC}"
    echo "    Try: ./demo/setup.sh"
    exit 1
fi

# Wait for deployment to be ready
echo -e "${BLUE}⏳ Waiting for Observatorium API to be ready...${NC}"
kubectl wait --for=condition=Available deployment/observatorium-api -n proxy --timeout=60s

# Extract certificates
echo -e "${BLUE}🔑 Extracting client certificates...${NC}"
mkdir -p certs
cd certs

# Always extract these certificates (they should exist)
kubectl get secret -n proxy admin-client-cert -o jsonpath='{.data.tls\.crt}' | base64 -d > admin-client.crt 2>/dev/null || echo "⚠️  Admin certificate not found"
kubectl get secret -n proxy admin-client-cert -o jsonpath='{.data.tls\.key}' | base64 -d > admin-client.key 2>/dev/null || echo "⚠️  Admin key not found"
kubectl get secret -n proxy test-client-cert -o jsonpath='{.data.tls\.crt}' | base64 -d > test-client.crt 2>/dev/null || echo "⚠️  Test certificate not found"
kubectl get secret -n proxy test-client-cert -o jsonpath='{.data.tls\.key}' | base64 -d > test-client.key 2>/dev/null || echo "⚠️  Test key not found"
kubectl get secret -n cert-manager root-ca-secret -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt 2>/dev/null || echo "⚠️  CA certificate not found"

# Try to extract extended certificates (may not exist)
kubectl get secret -n proxy query-user-cert -o jsonpath='{.data.tls\.crt}' | base64 -d > query-user.crt 2>/dev/null || true
kubectl get secret -n proxy query-user-cert -o jsonpath='{.data.tls\.key}' | base64 -d > query-user.key 2>/dev/null || true
kubectl get secret -n proxy write-user-cert -o jsonpath='{.data.tls\.crt}' | base64 -d > write-user.crt 2>/dev/null || true
kubectl get secret -n proxy write-user-cert -o jsonpath='{.data.tls\.key}' | base64 -d > write-user.key 2>/dev/null || true
kubectl get secret -n proxy logs-reader-cert -o jsonpath='{.data.tls\.crt}' | base64 -d > logs-reader.crt 2>/dev/null || true
kubectl get secret -n proxy logs-reader-cert -o jsonpath='{.data.tls\.key}' | base64 -d > logs-reader.key 2>/dev/null || true

cd ..

# Start port-forward in background
echo -e "${BLUE}🚀 Starting port-forward...${NC}"
kubectl port-forward -n proxy svc/observatorium-api 8080:8080 >/dev/null 2>&1 &
PORT_FORWARD_PID=$!

# Wait for port-forward to be ready
echo -e "${BLUE}⏳ Waiting for port-forward to be ready...${NC}"
sleep 5

# Check if port-forward is working
if ! nc -z localhost 8080 2>/dev/null; then
    echo -e "${YELLOW}⚠️  Port-forward might not be ready, waiting a bit more...${NC}"
    sleep 5
fi

# Run the automated tests
echo -e "${BLUE}🧪 Running automated tests...${NC}"
cd certs

# Build and run the test program
if ! go mod init automated-test 2>/dev/null; then
    echo "Go module already initialized or error occurred"
fi

# Run the tests
if go run ../demo/automated-test.go localhost:8080; then
    echo -e "${GREEN}✅ All automated tests completed successfully!${NC}"
    exit_code=0
else
    echo -e "${RED}❌ Some automated tests failed!${NC}"
    exit_code=1
fi

cd ..

# Additional validation
echo -e "${BLUE}📊 Running additional validations...${NC}"

# Check API health
echo -n "🏥 API Health Check: "
if curl -s -k --cert certs/admin-client.crt --key certs/admin-client.key --cacert certs/ca.crt \
   "https://localhost:8080/metrics" >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Healthy${NC}"
else
    echo -e "${RED}❌ Unhealthy${NC}"
fi

# Check certificate validity
echo -n "📜 Certificate Validity: "
if openssl x509 -in certs/admin-client.crt -noout -checkend 86400 2>/dev/null; then
    echo -e "${GREEN}✅ Valid${NC}"
else
    echo -e "${YELLOW}⚠️  Expires soon or invalid${NC}"
fi

# Check RBAC configuration
echo -n "🔐 RBAC Configuration: "
if kubectl get configmap observatorium-config -n proxy >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Present${NC}"
else
    echo -e "${RED}❌ Missing${NC}"
fi

# Summary
echo ""
echo -e "${BLUE}📋 Test Summary${NC}"
echo "==============="
echo "• Cluster Status: $(kubectl get nodes --no-headers | wc -l) node(s) ready"
echo "• API Status: $(kubectl get pods -n proxy -l app=observatorium-api --no-headers | grep Running | wc -l) pod(s) running"
echo "• Certificates: $(ls certs/*.crt 2>/dev/null | wc -l) certificate(s) available"
echo "• Port Forward: Process ID $PORT_FORWARD_PID"

if [[ $exit_code -eq 0 ]]; then
    echo -e "${GREEN}🎉 All tests passed! Path-based RBAC is working correctly.${NC}"
else
    echo -e "${RED}💥 Some tests failed. Please check the logs above.${NC}"
fi

exit $exit_code
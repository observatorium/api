#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Setting up Observatorium Demo with Automated Testing${NC}"
echo "========================================================"

# Check prerequisites
echo "🔍 Checking prerequisites..."
command -v docker >/dev/null 2>&1 || { echo "❌ Docker is required but not installed. Aborting." >&2; exit 1; }
command -v kind >/dev/null 2>&1 || { echo "❌ kind is required but not installed. Aborting." >&2; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "❌ kubectl is required but not installed. Aborting." >&2; exit 1; }

# Build the observatorium binary
echo -e "${BLUE}🔨 Building observatorium binary...${NC}"
make observatorium-api

# Create KinD cluster if it doesn't exist
if ! kind get clusters | grep -q "observatorium"; then
    echo -e "${BLUE}📦 Creating KinD cluster...${NC}"
    kind create cluster --name=observatorium --config=demo/kind-config.yaml
else
    echo -e "${YELLOW}📦 KinD cluster 'observatorium' already exists${NC}"
fi

# Wait for cluster to be ready
echo "⏳ Waiting for cluster to be ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=300s

# Apply cert-manager
echo -e "${BLUE}🔐 Installing cert-manager...${NC}"
kubectl apply -f demo/cert-manager.yaml
kubectl wait --for=condition=Available deployment/cert-manager -n cert-manager --timeout=300s
kubectl wait --for=condition=Available deployment/cert-manager-cainjector -n cert-manager --timeout=300s
kubectl wait --for=condition=Available deployment/cert-manager-webhook -n cert-manager --timeout=300s

# Create proxy namespace
kubectl create namespace proxy --dry-run=client -o yaml | kubectl apply -f -

# Apply certificates (including extended ones)
echo -e "${BLUE}📜 Creating certificates...${NC}"
kubectl apply -f demo/certificates.yaml

# Create extended certificates if they exist
if [[ -f "demo/certificates-extended.yaml" ]]; then
    kubectl apply -f demo/certificates-extended.yaml
fi

# Wait for core certificates to be ready
echo "⏳ Waiting for certificates to be ready..."
kubectl wait --for=condition=Ready certificate/observatorium-server-tls -n proxy --timeout=300s
kubectl wait --for=condition=Ready certificate/admin-client-cert -n proxy --timeout=300s
kubectl wait --for=condition=Ready certificate/test-client-cert -n proxy --timeout=300s

# Wait for extended certificates if they're being created
sleep 10
extended_certs=("query-user-cert" "write-user-cert" "logs-reader-cert")
for cert in "${extended_certs[@]}"; do
    if kubectl get certificate "$cert" -n proxy >/dev/null 2>&1; then
        echo "⏳ Waiting for $cert..."
        kubectl wait --for=condition=Ready certificate/"$cert" -n proxy --timeout=300s || echo "⚠️  $cert might not be ready yet"
    fi
done

# Deploy httpbin backends
echo -e "${BLUE}🌐 Deploying httpbin backends...${NC}"
kubectl apply -f demo/httpbin.yaml
kubectl wait --for=condition=Available deployment/httpbin -n proxy --timeout=300s
kubectl wait --for=condition=Available deployment/httpbin-metrics -n proxy --timeout=300s
kubectl wait --for=condition=Available deployment/httpbin-logs -n proxy --timeout=300s

# Deploy Observatorium API
echo -e "${BLUE}🎯 Deploying Observatorium API...${NC}"
kubectl apply -f demo/observatorium-deployment.yaml
kubectl wait --for=condition=Available deployment/observatorium-api -n proxy --timeout=300s

# Deploy test configuration
echo -e "${BLUE}🧪 Setting up automated tests...${NC}"
if [[ -f "demo/test-suite.yaml" ]]; then
    kubectl apply -f demo/test-suite.yaml
fi

# Run initial automated tests
echo -e "${BLUE}🔬 Running initial automated tests...${NC}"
if [[ -f "demo/run-automated-tests.sh" ]]; then
    chmod +x demo/run-automated-tests.sh
    if ./demo/run-automated-tests.sh; then
        echo -e "${GREEN}✅ Initial tests passed!${NC}"
    else
        echo -e "${YELLOW}⚠️  Some initial tests failed, but continuing setup...${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Automated test script not found, skipping initial tests${NC}"
fi

# Create convenience scripts
echo -e "${BLUE}📋 Creating convenience scripts...${NC}"

cat > demo/quick-test.sh << 'EOF'
#!/bin/bash
echo "🚀 Running quick RBAC test..."
kubectl delete job path-rbac-test-job -n proxy --ignore-not-found
kubectl apply -f demo/test-suite.yaml
kubectl wait --for=condition=complete job/path-rbac-test-job -n proxy --timeout=120s
kubectl logs job/path-rbac-test-job -n proxy
EOF

cat > demo/watch-tests.sh << 'EOF'
#!/bin/bash
echo "👀 Watching test job logs..."
kubectl logs -f job/path-rbac-test-job -n proxy
EOF

cat > demo/port-forward.sh << 'EOF'
#!/bin/bash
echo "🔗 Starting port-forward to Observatorium API..."
echo "Access API at: https://localhost:8080"
echo "Press Ctrl+C to stop"
kubectl port-forward -n proxy svc/observatorium-api 8080:8080
EOF

chmod +x demo/quick-test.sh demo/watch-tests.sh demo/port-forward.sh

echo -e "${GREEN}✅ Demo environment setup complete!${NC}"
echo ""
echo -e "${BLUE}📋 Available Commands:${NC}"
echo "==============================="
echo "• Test RBAC manually:           ./demo/test-rbac.sh"
echo "• Run automated tests:          ./demo/run-automated-tests.sh"
echo "• Run quick Kubernetes test:    ./demo/quick-test.sh"
echo "• Start port-forward:           ./demo/port-forward.sh"
echo "• Watch test logs:               ./demo/watch-tests.sh"
echo "• View API logs:                 kubectl logs -n proxy deployment/observatorium-api -f"
echo "• Check certificates:            kubectl get certificates -n proxy"
echo "• Cleanup:                       ./demo/cleanup.sh"
echo ""
echo -e "${BLUE}🎯 Testing Options:${NC}"
echo "==================="
echo "1. ${GREEN}Manual Testing${NC}: Use the shell scripts to test manually"
echo "2. ${GREEN}Automated Testing${NC}: Run comprehensive Go-based tests"
echo "3. ${GREEN}Kubernetes Jobs${NC}: Use in-cluster test jobs"
echo "4. ${GREEN}Continuous Testing${NC}: Set up watches and monitors"
echo ""
echo -e "${BLUE}📊 Current Status:${NC}"
echo "=================="
echo "• Cluster: $(kubectl get nodes --no-headers | wc -l) node(s)"
echo "• Pods: $(kubectl get pods -n proxy --no-headers | grep Running | wc -l) running"
echo "• Certificates: $(kubectl get certificates -n proxy --no-headers | wc -l) created"
echo ""
if kubectl get job path-rbac-test-job -n proxy >/dev/null 2>&1; then
    echo -e "${GREEN}🧪 Automated tests are configured and ready!${NC}"
    echo "   Run './demo/quick-test.sh' to execute them."
else
    echo -e "${YELLOW}⚠️  Some test components may not be available.${NC}"
fi

echo ""
echo -e "${GREEN}🎉 Ready to test path-based RBAC!${NC}"
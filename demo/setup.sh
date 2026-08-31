#!/bin/bash

set -e

echo "🚀 Setting up Observatorium Demo Environment..."

# Check required tools
for cmd in kind kubectl docker; do
    if ! command -v $cmd &> /dev/null; then
        echo "❌ $cmd is required but not installed."
        exit 1
    fi
done

# Build the Observatorium API image
echo "🔨 Building Observatorium API image..."
docker build -t observatorium-api:demo .

# Create KinD cluster
echo "🏗️ Creating KinD cluster..."
kind create cluster --config demo/kind-config.yaml

# Load the image into KinD
echo "📦 Loading image into KinD..."
kind load docker-image observatorium-api:demo --name observatorium-demo

# Install cert-manager
echo "🔐 Installing cert-manager..."
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.1/cert-manager.yaml

# Wait for cert-manager to be ready
echo "⏳ Waiting for cert-manager to be ready..."
kubectl wait --namespace cert-manager \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/instance=cert-manager \
  --timeout=300s

# Apply cert-manager configuration
echo "📜 Creating certificate issuers..."
kubectl apply -f demo/cert-manager.yaml

# Wait for root CA to be ready
echo "⏳ Waiting for root CA certificate..."
kubectl wait --namespace cert-manager \
  --for=condition=ready certificate root-ca \
  --timeout=300s

# Create proxy namespace and certificates
echo "🏷️ Creating proxy namespace and certificates..."
kubectl apply -f demo/certificates.yaml

# Wait for certificates to be ready
echo "⏳ Waiting for certificates to be ready..."
kubectl wait --namespace proxy \
  --for=condition=ready certificate observatorium-server-tls \
  --timeout=300s
kubectl wait --namespace proxy \
  --for=condition=ready certificate admin-client-cert \
  --timeout=300s
kubectl wait --namespace proxy \
  --for=condition=ready certificate test-client-cert \
  --timeout=300s

# Deploy httpbin backends
echo "🌐 Deploying httpbin backends..."
kubectl apply -f demo/httpbin.yaml

# Wait for httpbin to be ready
echo "⏳ Waiting for httpbin deployments..."
kubectl wait --namespace proxy \
  --for=condition=available deployment httpbin \
  --timeout=300s
kubectl wait --namespace proxy \
  --for=condition=available deployment httpbin-metrics \
  --timeout=300s
kubectl wait --namespace proxy \
  --for=condition=available deployment httpbin-logs \
  --timeout=300s

# Deploy Observatorium API
echo "🔧 Deploying Observatorium API..."
# Update the deployment to use our local image
sed 's|quay.io/observatorium/api:latest|observatorium-api:demo|g' demo/observatorium-deployment.yaml | kubectl apply -f -

# Wait for Observatorium API to be ready
echo "⏳ Waiting for Observatorium API..."
kubectl wait --namespace proxy \
  --for=condition=available deployment observatorium-api \
  --timeout=300s

echo ""
echo "✅ Setup complete!"
echo ""
echo "📋 Useful commands:"
echo ""
echo "# Check pod status:"
echo "kubectl get pods -n proxy"
echo ""
echo "# View Observatorium API logs:"
echo "kubectl logs -n proxy deployment/observatorium-api -f"
echo ""
echo "# Port forward to access the API:"
echo "kubectl port-forward -n proxy svc/observatorium-api 8080:8080"
echo ""
echo "# Extract client certificates for testing:"
echo "kubectl get secret -n proxy admin-client-cert -o jsonpath='{.data.tls\.crt}' | base64 -d > admin-client.crt"
echo "kubectl get secret -n proxy admin-client-cert -o jsonpath='{.data.tls\.key}' | base64 -d > admin-client.key"
echo "kubectl get secret -n cert-manager root-ca-secret -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt"
echo ""
echo "# Test with curl (after port-forward):"
echo "curl -v --cert admin-client.crt --key admin-client.key --cacert ca.crt \\"
echo "  https://localhost:8080/api/metrics/v1/query?query=up"
echo ""
echo "🔍 RBAC Testing:"
echo "- admin@example.com: Full access to tenant-a and tenant-b"
echo "- test@example.com: Read-only access to tenant-a"
echo "- metrics@example.com: Metrics-only access to tenant-b"
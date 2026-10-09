#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Setting up Observatorium with Path-Based RBAC...${NC}"

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
kubectl apply -f demo/certificates-extended.yaml

# Wait for certificates to be ready
echo "⏳ Waiting for certificates to be ready..."
kubectl wait --for=condition=Ready certificate/observatorium-server-tls -n proxy --timeout=300s
kubectl wait --for=condition=Ready certificate/admin-client-cert -n proxy --timeout=300s
kubectl wait --for=condition=Ready certificate/test-client-cert -n proxy --timeout=300s

# Wait for extended certificates if they're being created
sleep 10
if kubectl get certificate query-user-cert -n proxy >/dev/null 2>&1; then
    kubectl wait --for=condition=Ready certificate/query-user-cert -n proxy --timeout=300s || true
fi
if kubectl get certificate write-user-cert -n proxy >/dev/null 2>&1; then
    kubectl wait --for=condition=Ready certificate/write-user-cert -n proxy --timeout=300s || true
fi
if kubectl get certificate logs-reader-cert -n proxy >/dev/null 2>&1; then
    kubectl wait --for=condition=Ready certificate/logs-reader-cert -n proxy --timeout=300s || true
fi

# Deploy httpbin backends
echo -e "${BLUE}🌐 Deploying httpbin backends...${NC}"
kubectl apply -f demo/httpbin.yaml
kubectl wait --for=condition=Available deployment/httpbin -n proxy --timeout=300s
kubectl wait --for=condition=Available deployment/httpbin-metrics -n proxy --timeout=300s
kubectl wait --for=condition=Available deployment/httpbin-logs -n proxy --timeout=300s

# Create configmaps with path-based RBAC configuration
echo -e "${BLUE}⚙️ Creating path-based RBAC configuration...${NC}"
kubectl create configmap rbac-config -n proxy --from-file=demo/rbac-with-paths.yaml --dry-run=client -o yaml | kubectl apply -f -
kubectl create configmap tenants-config -n proxy --from-file=demo/tenants.yaml --dry-run=client -o yaml | kubectl apply -f -
kubectl create configmap opa-policy -n proxy --from-file=demo/observatorium-path-based.rego --dry-run=client -o yaml | kubectl apply -f -

# Deploy observatorium with path-based configuration
echo -e "${BLUE}🎯 Deploying Observatorium API with path-based RBAC...${NC}"
cat > demo/observatorium-path-deployment.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: observatorium-api
  namespace: proxy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: observatorium-api
  template:
    metadata:
      labels:
        app: observatorium-api
    spec:
      containers:
      - name: observatorium-api
        image: observatorium-api:latest
        imagePullPolicy: Never
        command:
        - ./observatorium-api
        args:
        - --web.listen=0.0.0.0:8080
        - --web.internal.listen=0.0.0.0:8081
        - --tls.server.cert-file=/etc/certs/tls.crt
        - --tls.server.private-key-file=/etc/certs/tls.key
        - --tls.ca-file=/etc/certs/ca.crt
        - --tenants.config=/etc/config/tenants.yaml
        - --rbac.config=/etc/config/rbac-with-paths.yaml
        - --opa.url=http://localhost:8181/v1/data/observatorium/allow
        - --metrics.read.endpoint=http://httpbin-metrics.proxy.svc.cluster.local
        - --metrics.write.endpoint=http://httpbin-metrics.proxy.svc.cluster.local
        - --logs.read.endpoint=http://httpbin-logs.proxy.svc.cluster.local
        - --logs.write.endpoint=http://httpbin-logs.proxy.svc.cluster.local
        ports:
        - containerPort: 8080
          name: https
        - containerPort: 8081
          name: http-internal
        volumeMounts:
        - name: server-certs
          mountPath: /etc/certs
          readOnly: true
        - name: rbac-config
          mountPath: /etc/config/rbac-with-paths.yaml
          subPath: rbac-with-paths.yaml
          readOnly: true
        - name: tenants-config
          mountPath: /etc/config/tenants.yaml
          subPath: tenants.yaml
          readOnly: true
        resources:
          limits:
            cpu: 100m
            memory: 128Mi
          requests:
            cpu: 50m
            memory: 64Mi
      - name: opa
        image: openpolicyagent/opa:latest
        command:
        - opa
        args:
        - run
        - --server
        - --addr=0.0.0.0:8181
        - --config-file=/etc/opa/config.yaml
        - /etc/opa/policy.rego
        - /etc/opa/data.yaml
        ports:
        - containerPort: 8181
          name: opa-http
        volumeMounts:
        - name: opa-policy
          mountPath: /etc/opa/policy.rego
          subPath: observatorium-path-based.rego
          readOnly: true
        - name: rbac-config
          mountPath: /etc/opa/data.yaml
          subPath: rbac-with-paths.yaml
          readOnly: true
        - name: opa-config
          mountPath: /etc/opa/config.yaml
          subPath: config.yaml
          readOnly: true
        resources:
          limits:
            cpu: 100m
            memory: 128Mi
          requests:
            cpu: 50m
            memory: 64Mi
      volumes:
      - name: server-certs
        secret:
          secretName: observatorium-server-tls
      - name: rbac-config
        configMap:
          name: rbac-config
      - name: tenants-config
        configMap:
          name: tenants-config
      - name: opa-policy
        configMap:
          name: opa-policy
      - name: opa-config
        configMap:
          name: opa-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: opa-config
  namespace: proxy
data:
  config.yaml: |
    services:
      authz:
        url: http://localhost:8181
    bundles:
      authz:
        resource: ""
---
apiVersion: v1
kind: Service
metadata:
  name: observatorium-api
  namespace: proxy
spec:
  selector:
    app: observatorium-api
  ports:
  - name: https
    port: 8080
    targetPort: 8080
  - name: http-internal
    port: 8081
    targetPort: 8081
EOF

kubectl apply -f demo/observatorium-path-deployment.yaml

# Wait for deployment to be ready
echo "⏳ Waiting for Observatorium API to be ready..."
kubectl wait --for=condition=Available deployment/observatorium-api -n proxy --timeout=300s

echo -e "${GREEN}✅ Path-based RBAC setup complete!${NC}"
echo ""
echo -e "${BLUE}📋 Next steps:${NC}"
echo "1. Test the path-based RBAC: ./demo/test-path-rbac.sh"
echo "2. View API logs: kubectl logs -n proxy deployment/observatorium-api -f"
echo "3. Check certificates: kubectl get certificates -n proxy"
echo "4. Port-forward to access API: kubectl port-forward -n proxy svc/observatorium-api 8080:8080"
echo ""
echo -e "${YELLOW}🎯 New Features:${NC}"
echo "- Path-based authorization (users can only access specific API endpoints)"
echo "- Extended user personas with different path permissions"
echo "- OPA policy engine with path matching support"
echo "- Wildcard path matching (e.g., /api/metrics/v1/*)"
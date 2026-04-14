#!/bin/bash
set -e

CLUSTER_NAME="observatorium-auth-test"
NAMESPACE="proxy"
TESTDATA_DIR="testdata"

echo "Extracting configuration from cluster..."

# Create testdata directory
mkdir -p "$TESTDATA_DIR"

# Extract certificates
echo "✓ Extracting certificates..."
kubectl get secret ca-cert -n $NAMESPACE --context kind-$CLUSTER_NAME -o jsonpath='{.data.tls\.crt}' | base64 -d > "$TESTDATA_DIR/ca.crt"
kubectl get secret client-cert -n $NAMESPACE --context kind-$CLUSTER_NAME -o jsonpath='{.data.tls\.crt}' | base64 -d > "$TESTDATA_DIR/test-client.crt"
kubectl get secret client-cert -n $NAMESPACE --context kind-$CLUSTER_NAME -o jsonpath='{.data.tls\.key}' | base64 -d > "$TESTDATA_DIR/test-client.key"
kubectl get secret admin-cert -n $NAMESPACE --context kind-$CLUSTER_NAME -o jsonpath='{.data.tls\.crt}' | base64 -d > "$TESTDATA_DIR/admin-client.crt"
kubectl get secret admin-cert -n $NAMESPACE --context kind-$CLUSTER_NAME -o jsonpath='{.data.tls\.key}' | base64 -d > "$TESTDATA_DIR/admin-client.key"

# Generate tenant configuration
echo "✓ Generating tenant configuration..."
cat > "$TESTDATA_DIR/tenants.yaml" << 'EOF'
tenants:
- name: auth-tenant
  id: "1610702597"
  oidc:
    clientID: observatorium-api
    clientSecret: ZXhhbXBsZS1hcHAtc2VjcmV0
    issuerURL: http://dex.proxy.svc.cluster.local:5556/dex
    redirectURL: http://localhost:8080/oidc/auth-tenant/callback
    usernameClaim: email
    paths:
    - operator: "!~"
      pattern: ".*(loki/api/v1/push|api/v1/receive).*"
  mTLS:
    caPath: /etc/certs/ca.crt
    paths:
    - operator: "=~"
      pattern: ".*(api/v1/receive).*"
    - operator: "=~"
      pattern: ".*(loki/api/v1/push).*"
EOF

# Generate RBAC configuration
echo "✓ Generating RBAC configuration..."
cat > "$TESTDATA_DIR/rbac.yaml" << 'EOF'
roles:
- name: read-write
  resources:
  - metrics
  - logs
  tenants:
  - auth-tenant
  permissions:
  - read
  - write
- name: read
  resources:
  - metrics
  - logs
  tenants:
  - auth-tenant
  permissions:
  - read
- name: write
  resources:
  - metrics
  - logs
  tenants:
  - auth-tenant
  permissions:
  - write
roleBindings:
- name: admin-user
  roles:
  - read-write
  subjects:
  - kind: user
    name: admin@example.com
- name: test-user
  roles:
  - read
  subjects:
  - kind: user
    name: test@example.com
- name: admin-client
  roles:
  - write
  subjects:
  - kind: user
    name: admin-client
EOF


# Generate Observatorium API configuration  
echo "✓ Generating Observatorium API deployment..."
CA_CERT_B64=$(cat "$TESTDATA_DIR/ca.crt" | base64 | tr -d '\n')

cat > "$TESTDATA_DIR/observatorium-api.yaml" << EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: tenant-config
  namespace: proxy
data:
  tenants.yaml: |
$(sed 's/^/    /' "$TESTDATA_DIR/tenants.yaml")
---
# CA Certificate ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: ca-cert-config
  namespace: proxy
data:
  ca.crt: |
$(sed 's/^/    /' "$TESTDATA_DIR/ca.crt")
---
# RBAC Configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: rbac-config
  namespace: proxy
data:
  rbac.yaml: |
$(sed 's/^/    /' "$TESTDATA_DIR/rbac.yaml")
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: observatorium-api
  namespace: proxy
  labels:
    app: observatorium-api
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
        image: observatorium-api-auth-test:latest
        imagePullPolicy: Never
        ports:
        - name: http
          containerPort: 8080
        - name: internal
          containerPort: 8081
        args:
        - --web.listen=0.0.0.0:8080
        - --web.internal.listen=0.0.0.0:8081
        - --tls.server.cert-file=/etc/server-certs/tls.crt
        - --tls.server.key-file=/etc/server-certs/tls.key
        - --tls.client-auth-type=RequestClientCert
        - --web.healthchecks.url=http://localhost:8081
        - --tenants.config=/etc/config/tenants.yaml
        - --rbac.config=/etc/config/rbac.yaml
        - --metrics.read.endpoint=http://api-proxy.proxy.svc.cluster.local
        - --metrics.write.endpoint=http://api-proxy.proxy.svc.cluster.local
        - --logs.read.endpoint=http://api-proxy.proxy.svc.cluster.local
        - --logs.write.endpoint=http://api-proxy.proxy.svc.cluster.local
        - --log.level=debug
        volumeMounts:
        - name: server-certs
          mountPath: /etc/server-certs
          readOnly: true
        - name: ca-cert
          mountPath: /etc/certs
          readOnly: true
        - name: tenant-config
          mountPath: /etc/config/tenants.yaml
          readOnly: true
          subPath: tenants.yaml
        - name: rbac-config
          mountPath: /etc/config/rbac.yaml
          readOnly: true
          subPath: rbac.yaml
        env:
        - name: KUBERNETES_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
      volumes:
      - name: server-certs
        secret:
          secretName: server-cert
      - name: ca-cert
        configMap:
          name: ca-cert-config
      - name: tenant-config
        configMap:
          name: tenant-config
      - name: rbac-config
        configMap:
          name: rbac-config
EOF

echo "✓ Configuration extracted to $TESTDATA_DIR/"
echo ""
echo "Files created:"
echo "  - $TESTDATA_DIR/ca.crt (CA certificate)"
echo "  - $TESTDATA_DIR/test-client.{crt,key} (Test client mTLS)"
echo "  - $TESTDATA_DIR/admin-client.{crt,key} (Admin client mTLS)" 
echo "  - $TESTDATA_DIR/tenants.yaml (Tenant configuration)"
echo "  - $TESTDATA_DIR/rbac.yaml (RBAC configuration)"
echo "  - $TESTDATA_DIR/dex.yaml (Dex deployment)"
echo "  - $TESTDATA_DIR/observatorium-api.yaml (API deployment)"
echo ""
echo "Ready to deploy with: make deploy"
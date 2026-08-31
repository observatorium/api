# Observatorium Demo Environment

This demo environment sets up a complete Observatorium API deployment on KinD (Kubernetes in Docker) for testing RBAC and mTLS functionality.

## What's Included

- **KinD Cluster**: 3-node cluster with ingress capabilities
- **Cert-Manager**: Automated certificate management
- **mTLS Setup**: Server and client certificates for authentication
- **Httpbin Backends**: Mock services for testing metrics and logs
- **RBAC Configuration**: Multiple users with different permission levels
- **Observatorium API**: Deployed in the `proxy` namespace

## Quick Start

1. **Prerequisites**:
   ```bash
   # Ensure you have the required tools
   docker --version
   kind --version
   kubectl version --client
   ```

2. **Setup the environment**:
   ```bash
   chmod +x demo/setup.sh
   ./demo/setup.sh
   ```

3. **Test RBAC**:
   ```bash
   chmod +x demo/test-rbac.sh
   ./demo/test-rbac.sh
   ```

4. **Cleanup**:
   ```bash
   chmod +x demo/cleanup.sh
   ./demo/cleanup.sh
   ```

## Architecture

```
┌─────────────────────────────────────────────┐
│               KinD Cluster                  │
│  ┌─────────────────────────────────────────┐│
│  │          proxy namespace                ││
│  │                                         ││
│  │  ┌─────────────────┐  ┌───────────────┐ ││
│  │  │ Observatorium   │  │    Httpbin    │ ││
│  │  │     API         │  │   Backends    │ ││
│  │  │                 │  │               │ ││
│  │  │ • mTLS enabled  │  │ • httpbin     │ ││
│  │  │ • RBAC config   │  │ • httpbin-    │ ││
│  │  │ • TLS certs     │  │   metrics     │ ││
│  │  │                 │  │ • httpbin-    │ ││
│  │  │                 │  │   logs        │ ││
│  │  └─────────────────┘  └───────────────┘ ││
│  └─────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────┐│
│  │        cert-manager namespace           ││
│  │                                         ││
│  │  ┌─────────────────┐                    ││
│  │  │   Cert-Manager  │                    ││
│  │  │                 │                    ││
│  │  │ • Root CA       │                    ││
│  │  │ • ClusterIssuer │                    ││
│  │  │ • Auto certs    │                    ││
│  │  └─────────────────┘                    ││
│  └─────────────────────────────────────────┘│
└─────────────────────────────────────────────┘
```

## RBAC Configuration

The demo includes three user personas for testing:

### 1. Admin User (`admin@example.com`)
- **Permissions**: Full read/write access
- **Tenants**: `tenant-a`, `tenant-b`
- **Resources**: metrics, logs, traces
- **Certificate**: `admin-client-cert`

### 2. Test User (`test@example.com`)
- **Permissions**: Read-only access
- **Tenants**: `tenant-a` only
- **Resources**: metrics, logs
- **Certificate**: `test-client-cert`

### 3. Metrics User (`metrics@example.com`)
- **Permissions**: Read/write access
- **Tenants**: `tenant-b` only
- **Resources**: metrics only
- **Certificate**: Would need to be created separately

## mTLS Configuration

The setup uses cert-manager to generate:
- Root CA certificate
- Server certificate for Observatorium API
- Client certificates for users

All communication requires valid client certificates signed by the root CA.

## Testing Commands

### Manual Testing

1. **Port forward to access the API**:
   ```bash
   kubectl port-forward -n proxy svc/observatorium-api 8080:8080
   ```

2. **Extract client certificates**:
   ```bash
   kubectl get secret -n proxy admin-client-cert -o jsonpath='{.data.tls\.crt}' | base64 -d > admin-client.crt
   kubectl get secret -n proxy admin-client-cert -o jsonpath='{.data.tls\.key}' | base64 -d > admin-client.key
   kubectl get secret -n cert-manager root-ca-secret -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt
   ```

3. **Test with curl**:
   ```bash
   # Test as admin user
   curl -v --cert admin-client.crt --key admin-client.key --cacert ca.crt \
     -H "X-Tenant: tenant-a" \
     "https://localhost:8080/api/metrics/v1/query?query=up"
   
   # Test logs endpoint
   curl -v --cert admin-client.crt --key admin-client.key --cacert ca.crt \
     -H "X-Tenant: tenant-a" \
     "https://localhost:8080/api/logs/v1/query?query={job=\"test\"}"
   ```

### Debugging

- **Check pod status**: `kubectl get pods -n proxy`
- **View API logs**: `kubectl logs -n proxy deployment/observatorium-api -f`
- **Check certificates**: `kubectl get certificates -n proxy`
- **Describe issues**: `kubectl describe certificate -n proxy observatorium-server-tls`

## Customization

### Adding New Users

1. Create a new certificate in `certificates.yaml`
2. Add the user to `rbac.yaml` with appropriate role bindings
3. Update the configmap in `observatorium-deployment.yaml`

### Modifying Permissions

Edit the roles in `rbac.yaml` to adjust:
- Resource access (metrics, logs, traces)
- Tenant access
- Permission levels (read, write)

### Backend Endpoints

The demo uses httpbin as mock backends. To use real services:
1. Deploy Prometheus, Loki, etc.
2. Update the endpoint arguments in `observatorium-deployment.yaml`

## Troubleshooting

### Common Issues

1. **Certificates not ready**:
   ```bash
   kubectl get certificates -n proxy -o wide
   kubectl describe certificate -n proxy observatorium-server-tls
   ```

2. **API not starting**:
   ```bash
   kubectl logs -n proxy deployment/observatorium-api
   kubectl describe pod -n proxy -l app=observatorium-api
   ```

3. **Connection refused**:
   - Check if port-forward is running
   - Verify certificates are extracted correctly
   - Check if API is listening on correct port

4. **Certificate errors**:
   - Ensure cert-manager is running: `kubectl get pods -n cert-manager`
   - Check if root CA is ready: `kubectl get certificate -n cert-manager root-ca`

### Useful Commands

```bash
# Check all resources
kubectl get all -n proxy

# Watch certificate creation
kubectl get certificates -n proxy -w

# Test internal endpoint (no TLS)
kubectl port-forward -n proxy svc/observatorium-api 8081:8081
curl http://localhost:8081/metrics

# Check service endpoints
kubectl get endpoints -n proxy
```
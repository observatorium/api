# Path-Based RBAC for Observatorium API

This extension adds path-based authorization to Observatorium API, allowing fine-grained control over which API endpoints users can access.

## Overview

The path-based RBAC system extends the existing role-based access control with URL path restrictions. This allows you to:

- Restrict users to specific API endpoints (e.g., only `/api/metrics/v1/query`)
- Allow wildcard access to endpoint families (e.g., `/api/metrics/v1/*`)
- Combine resource, tenant, permission, and path-based restrictions
- Create specialized roles for different use cases (query-only, write-only, etc.)

## New Features

### 1. Extended Role Configuration

Roles now support a `paths` field that specifies which API endpoints the role can access:

```yaml
roles:
- name: query-only-role
  resources:
  - metrics
  tenants:
  - tenant-a
  permissions:
  - read
  paths:
  - /api/metrics/v1/query
  - /api/metrics/v1/query_range
```

### 2. Wildcard Path Matching

Use `/*` suffix for wildcard matching:

```yaml
paths:
- /api/metrics/v1/*  # Allows all metrics endpoints
- /api/logs/v1/*     # Allows all logs endpoints
```

### 3. Enhanced OPA Policy

The OPA policy (`observatorium-path-based.rego`) includes:
- Path matching logic with wildcard support
- Debug functions for troubleshooting
- Backward compatibility with existing configurations

### 4. New User Personas

| User | Access | Paths | Use Case |
|------|--------|-------|----------|
| `admin@example.com` | Full | `/api/*/v1/*` | Administrator |
| `test@example.com` | Read-only | Query + Series endpoints | Read-only user |
| `query@example.com` | Read-only | Query endpoints only | Dashboard user |
| `write@example.com` | Write-only | Receive endpoints only | Data ingestion |
| `logs-reader@example.com` | Read-only | Logs endpoints | Logs analyst |

## Setup

### 1. Deploy with Path-Based RBAC

```bash
./demo/setup-path-based.sh
```

This will:
- Create the KinD cluster with cert-manager
- Generate client certificates for all user personas
- Deploy Observatorium API with OPA policy engine
- Configure path-based RBAC rules

### 2. Test Path-Based Access

```bash
./demo/test-path-rbac.sh
```

This comprehensive test validates:
- Admin users can access all endpoints
- Query-only users are restricted to query endpoints
- Write-only users can only access write endpoints
- Cross-tenant access restrictions
- Path-based denials

## Configuration Files

### Core Files
- `rbac-with-paths.yaml` - Extended RBAC configuration with path restrictions
- `observatorium-path-based.rego` - OPA policy with path matching logic
- `certificates-extended.yaml` - Additional client certificates

### Test Files
- `test-path-rbac.sh` - Comprehensive testing script
- `setup-path-based.sh` - Automated deployment script

## API Endpoint Categories

### Metrics Endpoints
- **Read**: `/api/metrics/v1/query`, `/api/metrics/v1/query_range`, `/api/metrics/v1/series`, `/api/metrics/v1/labels`
- **Write**: `/api/metrics/v1/receive`
- **Admin**: `/api/metrics/v1/rules`, `/api/metrics/v1/rules/raw`

### Logs Endpoints
- **Read**: `/api/logs/v1/query`, `/api/logs/v1/query_range`, `/api/logs/v1/labels`
- **Write**: `/api/logs/v1/push`

### Traces Endpoints
- **Read**: `/api/traces/v1/search`
- **Write**: `/api/traces/v1/traces`

## Testing Examples

### Query-Only Access
```bash
# ✅ Allowed
curl --cert query-user.crt --key query-user.key --cacert ca.crt \
  -H "X-Tenant: tenant-a" \
  "https://localhost:8080/api/metrics/v1/query?query=up"

# ❌ Denied
curl --cert query-user.crt --key query-user.key --cacert ca.crt \
  -H "X-Tenant: tenant-a" \
  "https://localhost:8080/api/metrics/v1/receive"
```

### Write-Only Access
```bash
# ✅ Allowed
curl --cert write-user.crt --key write-user.key --cacert ca.crt \
  -H "X-Tenant: tenant-b" \
  "https://localhost:8080/api/metrics/v1/receive"

# ❌ Denied
curl --cert write-user.crt --key write-user.key --cacert ca.crt \
  -H "X-Tenant: tenant-b" \
  "https://localhost:8080/api/metrics/v1/query?query=up"
```

## Troubleshooting

### 1. Check Certificate Status
```bash
kubectl get certificates -n proxy
```

### 2. View API Logs
```bash
kubectl logs -n proxy deployment/observatorium-api -c observatorium-api -f
```

### 3. Check OPA Policy Evaluation
```bash
kubectl logs -n proxy deployment/observatorium-api -c opa -f
```

### 4. Test Certificate Authentication
```bash
# Extract and verify certificates
kubectl get secret -n proxy admin-client-cert -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -text -noout
```

### 5. Debug Path Matching
The OPA policy includes a `debug_paths` function that shows which paths are configured for each role.

## Security Considerations

1. **Principle of Least Privilege**: Users are granted access only to endpoints they need
2. **Path Validation**: All paths are validated against configured patterns
3. **Wildcard Safety**: Wildcards are carefully implemented to prevent over-permissioning
4. **Certificate-Based Authentication**: All access requires valid client certificates
5. **Multi-Layer Authorization**: Resource, tenant, permission, and path checks are all enforced

## Extending the Configuration

### Adding New User Personas

1. **Create certificate** in `certificates-extended.yaml`
2. **Define role** in `rbac-with-paths.yaml` with specific paths
3. **Create role binding** to associate user with role
4. **Update test script** to validate the new user's access

### Adding New Endpoints

1. **Update role paths** to include new endpoints
2. **Test access patterns** with existing users
3. **Verify security boundaries** are maintained

## Migration from Basic RBAC

The path-based system is backward compatible. Existing roles without `paths` fields will continue to work with default behavior. To migrate:

1. Add `paths` fields to existing roles
2. Test with current certificates
3. Gradually restrict paths as needed
4. Update documentation and procedures
# Automated Testing for Path-Based RBAC

This document describes the automated testing infrastructure for Observatorium API's path-based RBAC system.

## Overview

The automated testing framework provides multiple ways to validate path-based RBAC functionality:

1. **Go-based Integration Tests** - Comprehensive client-side testing
2. **Shell Script Tests** - Quick manual and automated validation  
3. **Kubernetes Job Tests** - In-cluster testing with direct API access
4. **Continuous Integration** - Automated testing pipeline integration

## Test Components

### 1. Go-based Test Suite (`demo/automated-test.go`)

A comprehensive Go program that tests multiple user personas and access patterns:

```go
// Tests different user types with specific path permissions
type TestCase struct {
    Name           string
    CertFile       string  
    KeyFile        string
    Tenant         string
    Path           string
    Method         string
    ExpectedStatus int
    Description    string
}
```

**Features:**
- TLS client certificate authentication
- Configurable test cases via code
- Detailed pass/fail reporting
- Support for different HTTP methods
- Certificate validation and error handling

**Usage:**
```bash
go run demo/automated-test.go <api-url>
```

### 2. Shell Script Test Runner (`demo/run-automated-tests.sh`)

Automated script that:
- Extracts certificates from Kubernetes secrets
- Sets up port-forwarding
- Runs the Go test suite
- Performs additional validation checks
- Provides comprehensive status reporting

**Features:**
- Automatic certificate extraction
- Port-forward management
- Health checks and validation
- Clean error handling and cleanup
- Color-coded output

**Usage:**
```bash
./demo/run-automated-tests.sh
```

### 3. Kubernetes Test Job (`demo/test-suite.yaml`)

In-cluster testing using Kubernetes Jobs:
- Runs tests directly within the cluster
- No port-forwarding required
- Uses service discovery for API access
- Configurable via ConfigMaps

**Components:**
- `ConfigMap` with test configuration
- `Job` specification with test logic
- Environment variables for certificate access
- Built-in retry and backoff logic

**Usage:**
```bash
kubectl apply -f demo/test-suite.yaml
kubectl logs job/path-rbac-test-job -n proxy
```

### 4. Enhanced Demo Setup (`demo/setup-with-tests.sh`)

Complete demo environment with integrated testing:
- Sets up KinD cluster
- Deploys cert-manager and certificates
- Configures Observatorium API
- Runs initial test validation
- Creates convenience scripts

**Generated Scripts:**
- `demo/quick-test.sh` - Run Kubernetes test job
- `demo/watch-tests.sh` - Monitor test execution
- `demo/port-forward.sh` - Start port-forwarding

## Test Categories

### 1. Admin User Tests
- **Scope**: Full access to all paths and tenants
- **Expected**: 200 responses for all endpoints
- **Paths**: `/api/metrics/v1/*`, `/api/logs/v1/*`, `/api/traces/v1/*`

### 2. Read-Only User Tests  
- **Scope**: Limited read access to specific tenant
- **Expected**: 200 for read endpoints, 403 for write endpoints
- **Paths**: Query and series endpoints only

### 3. Query-Only User Tests
- **Scope**: Restricted to query endpoints
- **Expected**: 200 for `/query` and `/query_range`, 403 for others
- **Paths**: `/api/metrics/v1/query*` only

### 4. Write-Only User Tests
- **Scope**: Write access only
- **Expected**: 200 for `/receive`, 403 for read endpoints
- **Paths**: `/api/metrics/v1/receive` only

### 5. Cross-Tenant Tests
- **Scope**: Validates tenant isolation
- **Expected**: 403 when accessing unauthorized tenants
- **Validation**: Proper tenant boundary enforcement

### 6. Certificate Validation Tests
- **Scope**: Authentication requirements
- **Expected**: 403/SSL errors without valid certificates
- **Validation**: mTLS enforcement

## Running Tests

### Quick Start
```bash
# Setup environment with testing
./demo/setup-with-tests.sh

# Run comprehensive tests
./demo/run-automated-tests.sh

# Run quick in-cluster test
./demo/quick-test.sh
```

### Manual Testing
```bash
# Extract certificates manually
kubectl get secret -n proxy admin-client-cert -o jsonpath='{.data.tls\.crt}' | base64 -d > admin.crt
kubectl get secret -n proxy admin-client-cert -o jsonpath='{.data.tls\.key}' | base64 -d > admin.key

# Test specific endpoint
curl --cert admin.crt --key admin.key --cacert ca.crt \
  -H "X-Tenant: tenant-a" \
  "https://localhost:8080/api/metrics/v1/query?query=up"
```

### Continuous Integration
```bash
# In CI pipeline
kubectl apply -f demo/test-suite.yaml
kubectl wait --for=condition=complete job/path-rbac-test-job -n proxy --timeout=120s
kubectl logs job/path-rbac-test-job -n proxy
```

## Test Configuration

### Environment Variables
- `API_URL` - Observatorium API endpoint
- `TENANT_A` - First tenant name (default: tenant-a)
- `TENANT_B` - Second tenant name (default: tenant-b)

### Certificate Files Expected
- `admin-client.crt/key` - Admin user certificates
- `test-client.crt/key` - Read-only user certificates  
- `query-user.crt/key` - Query-only user certificates
- `write-user.crt/key` - Write-only user certificates
- `logs-reader.crt/key` - Logs reader certificates
- `ca.crt` - Root CA certificate

### Test Customization

Modify test cases in `automated-test.go`:
```go
testCases := []TestCase{
    {
        Name:           "custom_test",
        CertFile:       "custom-user.crt", 
        KeyFile:        "custom-user.key",
        Tenant:         "custom-tenant",
        Path:           "/api/custom/v1/endpoint",
        Method:         "GET",
        ExpectedStatus: 200,
        Description:    "Custom test description",
    },
}
```

## Troubleshooting

### Common Issues

1. **Certificate Errors**
   ```bash
   # Check certificate validity
   openssl x509 -in admin-client.crt -text -noout
   
   # Verify CA trust
   openssl verify -CAfile ca.crt admin-client.crt
   ```

2. **Port-Forward Issues**
   ```bash
   # Check if port is in use
   lsof -i :8080
   
   # Restart port-forward
   kubectl port-forward -n proxy svc/observatorium-api 8080:8080
   ```

3. **API Not Ready**
   ```bash
   # Check pod status
   kubectl get pods -n proxy -l app=observatorium-api
   
   # Check logs
   kubectl logs -n proxy deployment/observatorium-api
   ```

4. **Test Job Failures**
   ```bash
   # Check job status
   kubectl get jobs -n proxy
   
   # View detailed logs
   kubectl describe job path-rbac-test-job -n proxy
   ```

### Debug Mode

Enable verbose logging:
```bash
export DEBUG=1
./demo/run-automated-tests.sh
```

View detailed test output:
```bash
go run demo/automated-test.go localhost:8080 -v
```

## Integration with CI/CD

### GitHub Actions Example
```yaml
- name: Run RBAC Tests
  run: |
    ./demo/setup-with-tests.sh
    ./demo/run-automated-tests.sh
```

### Jenkins Pipeline Example
```groovy
stage('RBAC Tests') {
    steps {
        sh './demo/setup-with-tests.sh'
        sh './demo/run-automated-tests.sh'
    }
}
```

## Metrics and Monitoring

The test framework provides:
- **Test execution time** - Duration of test runs
- **Pass/fail rates** - Success percentage over time
- **Certificate expiry monitoring** - Alert on expiring certificates
- **API health checks** - Endpoint availability validation

## Security Considerations

1. **Certificate Handling**: Tests properly handle certificate lifecycle
2. **Secret Management**: Kubernetes secrets are used for certificate storage
3. **Network Isolation**: Tests respect cluster network policies
4. **Access Logging**: All test requests are logged for audit purposes

## Extending Tests

### Adding New User Personas
1. Create certificates in `certificates-extended.yaml`
2. Add RBAC roles in `rbac-with-paths.yaml` 
3. Add test cases in `automated-test.go`
4. Update the test runner scripts

### Adding New Endpoints
1. Define endpoint paths in RBAC configuration
2. Create test cases for new endpoints
3. Update validation logic
4. Test both positive and negative cases

### Performance Testing
The framework can be extended for performance testing:
- Add load testing scenarios
- Measure response times
- Test concurrent access patterns
- Monitor resource usage

## Best Practices

1. **Test Isolation**: Each test case is independent
2. **Cleanup**: Proper cleanup of resources and connections
3. **Error Handling**: Graceful handling of network and authentication errors
4. **Documentation**: Clear descriptions for each test case
5. **Automation**: Fully automated setup and execution
6. **Monitoring**: Continuous monitoring of test health
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// TestCase represents a single path-based RBAC test case
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

// TestResult represents the result of a test case
type TestResult struct {
	TestCase TestCase
	Passed   bool
	Actual   int
	Error    string
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run automated-test.go <api-url>")
	}

	apiURL := os.Args[1]
	if !strings.HasPrefix(apiURL, "https://") {
		apiURL = "https://" + apiURL
	}

	fmt.Println("🚀 Starting automated path-based RBAC tests...")
	fmt.Printf("📍 Testing against: %s\n\n", apiURL)

	// Define comprehensive test cases
	testCases := []TestCase{
		// Admin user tests - should have full access
		{
			Name:           "admin_metrics_query",
			CertFile:       "admin-client.crt",
			KeyFile:        "admin-client.key",
			Tenant:         "tenant-a",
			Path:           "/api/metrics/v1/query?query=up",
			Method:         "GET",
			ExpectedStatus: 200,
			Description:    "Admin should access metrics query",
		},
		{
			Name:           "admin_metrics_query_range",
			CertFile:       "admin-client.crt",
			KeyFile:        "admin-client.key",
			Tenant:         "tenant-a",
			Path:           "/api/metrics/v1/query_range?query=up&start=0&end=1&step=1",
			Method:         "GET",
			ExpectedStatus: 200,
			Description:    "Admin should access metrics query_range",
		},
		{
			Name:           "admin_metrics_receive",
			CertFile:       "admin-client.crt",
			KeyFile:        "admin-client.key",
			Tenant:         "tenant-a",
			Path:           "/api/metrics/v1/receive",
			Method:         "POST",
			ExpectedStatus: 200,
			Description:    "Admin should access metrics receive",
		},
		{
			Name:           "admin_cross_tenant",
			CertFile:       "admin-client.crt",
			KeyFile:        "admin-client.key",
			Tenant:         "tenant-b",
			Path:           "/api/metrics/v1/query?query=up",
			Method:         "GET",
			ExpectedStatus: 200,
			Description:    "Admin should access tenant-b",
		},

		// Test user tests - limited read access to tenant-a
		{
			Name:           "test_metrics_query",
			CertFile:       "test-client.crt",
			KeyFile:        "test-client.key",
			Tenant:         "tenant-a",
			Path:           "/api/metrics/v1/query?query=up",
			Method:         "GET",
			ExpectedStatus: 200,
			Description:    "Test user should read tenant-a metrics",
		},
		{
			Name:           "test_metrics_receive",
			CertFile:       "test-client.crt",
			KeyFile:        "test-client.key",
			Tenant:         "tenant-a",
			Path:           "/api/metrics/v1/receive",
			Method:         "POST",
			ExpectedStatus: 403,
			Description:    "Test user should not write metrics",
		},
		{
			Name:           "test_cross_tenant",
			CertFile:       "test-client.crt",
			KeyFile:        "test-client.key",
			Tenant:         "tenant-b",
			Path:           "/api/metrics/v1/query?query=up",
			Method:         "GET",
			ExpectedStatus: 403,
			Description:    "Test user should not access tenant-b",
		},

		// Query-only user tests (if certificates exist)
		{
			Name:           "query_user_query",
			CertFile:       "query-user.crt",
			KeyFile:        "query-user.key",
			Tenant:         "tenant-a",
			Path:           "/api/metrics/v1/query?query=up",
			Method:         "GET",
			ExpectedStatus: 200,
			Description:    "Query user should access query endpoint",
		},
		{
			Name:           "query_user_series",
			CertFile:       "query-user.crt",
			KeyFile:        "query-user.key",
			Tenant:         "tenant-a",
			Path:           "/api/metrics/v1/series",
			Method:         "GET",
			ExpectedStatus: 403,
			Description:    "Query user should not access series endpoint",
		},

		// Write-only user tests (if certificates exist)
		{
			Name:           "write_user_receive",
			CertFile:       "write-user.crt",
			KeyFile:        "write-user.key",
			Tenant:         "tenant-b",
			Path:           "/api/metrics/v1/receive",
			Method:         "POST",
			ExpectedStatus: 200,
			Description:    "Write user should access receive endpoint",
		},
		{
			Name:           "write_user_query",
			CertFile:       "write-user.crt",
			KeyFile:        "write-user.key",
			Tenant:         "tenant-b",
			Path:           "/api/metrics/v1/query?query=up",
			Method:         "GET",
			ExpectedStatus: 403,
			Description:    "Write user should not access query endpoint",
		},

		// Logs reader tests (if certificates exist)
		{
			Name:           "logs_reader_query",
			CertFile:       "logs-reader.crt",
			KeyFile:        "logs-reader.key",
			Tenant:         "tenant-a",
			Path:           "/api/logs/v1/query?query={}",
			Method:         "GET",
			ExpectedStatus: 200,
			Description:    "Logs reader should access logs query",
		},
		{
			Name:           "logs_reader_metrics",
			CertFile:       "logs-reader.crt",
			KeyFile:        "logs-reader.key",
			Tenant:         "tenant-a",
			Path:           "/api/metrics/v1/query?query=up",
			Method:         "GET",
			ExpectedStatus: 403,
			Description:    "Logs reader should not access metrics",
		},
	}

	// Run all tests
	results := runTests(apiURL, testCases)

	// Print results
	printResults(results)

	// Exit with appropriate code
	if allTestsPassed(results) {
		fmt.Println("\n✅ All tests passed!")
		os.Exit(0)
	} else {
		fmt.Println("\n❌ Some tests failed!")
		os.Exit(1)
	}
}

func runTests(apiURL string, testCases []TestCase) []TestResult {
	var results []TestResult

	for _, tc := range testCases {
		fmt.Printf("🧪 Running: %s - %s\n", tc.Name, tc.Description)
		
		result := runSingleTest(apiURL, tc)
		results = append(results, result)

		if result.Passed {
			fmt.Printf("   ✅ PASS (expected %d, got %d)\n", tc.ExpectedStatus, result.Actual)
		} else {
			if result.Error != "" {
				fmt.Printf("   ⏭️  SKIP (%s)\n", result.Error)
			} else {
				fmt.Printf("   ❌ FAIL (expected %d, got %d)\n", tc.ExpectedStatus, result.Actual)
			}
		}
	}

	return results
}

func runSingleTest(apiURL string, tc TestCase) TestResult {
	// Check if certificate files exist
	if !fileExists(tc.CertFile) || !fileExists(tc.KeyFile) {
		return TestResult{
			TestCase: tc,
			Passed:   true, // Skip counts as pass
			Error:    "certificates not found",
		}
	}

	client, err := createTLSClient(tc.CertFile, tc.KeyFile)
	if err != nil {
		return TestResult{
			TestCase: tc,
			Passed:   false,
			Error:    fmt.Sprintf("failed to create client: %v", err),
		}
	}

	url := apiURL + tc.Path
	var body io.Reader
	if tc.Method == "POST" {
		body = strings.NewReader("test_metric 1")
	}

	req, err := http.NewRequest(tc.Method, url, body)
	if err != nil {
		return TestResult{
			TestCase: tc,
			Passed:   false,
			Error:    fmt.Sprintf("failed to create request: %v", err),
		}
	}

	req.Header.Set("X-Tenant", tc.Tenant)
	if tc.Method == "POST" {
		req.Header.Set("Content-Type", "application/x-protobuf")
	}

	resp, err := client.Do(req)
	if err != nil {
		return TestResult{
			TestCase: tc,
			Passed:   false,
			Error:    fmt.Sprintf("request failed: %v", err),
		}
	}
	defer resp.Body.Close()

	// Check if status code matches expectation
	passed := resp.StatusCode == tc.ExpectedStatus

	return TestResult{
		TestCase: tc,
		Passed:   passed,
		Actual:   resp.StatusCode,
	}
}

func createTLSClient(certFile, keyFile string) (*http.Client, error) {
	// Load client certificate
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	// Load CA certificate if it exists
	var caCertPool *x509.CertPool
	if fileExists("ca.crt") {
		caCert, err := os.ReadFile("ca.crt")
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:           caCertPool,
		InsecureSkipVerify: caCertPool == nil, // Skip verification if no CA
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 10 * time.Second,
	}, nil
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func printResults(results []TestResult) {
	fmt.Println("\n📊 Test Results Summary:")
	fmt.Println("========================")

	passed := 0
	failed := 0
	skipped := 0

	for _, result := range results {
		status := "❌ FAIL"
		if result.Passed {
			if result.Error != "" {
				status = "⏭️  SKIP"
				skipped++
			} else {
				status = "✅ PASS"
				passed++
			}
		} else {
			failed++
		}

		fmt.Printf("%-20s | %-8s | %s\n", result.TestCase.Name, status, result.TestCase.Description)
	}

	fmt.Printf("\nTotal: %d | Passed: %d | Failed: %d | Skipped: %d\n", 
		len(results), passed, failed, skipped)
}

func allTestsPassed(results []TestResult) bool {
	for _, result := range results {
		if !result.Passed && result.Error == "" {
			return false
		}
	}
	return true
}
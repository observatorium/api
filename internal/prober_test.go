package internal

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/oklog/run"
)

func doGet(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s", url), nil)
	if err != nil {
		return nil, err
	}

	return http.DefaultClient.Do(req.WithContext(ctx))
}

func TestProberHealthInitialState(t *testing.T) {
	p := NewProber(log.NewNopLogger())

	if p.isHealthy() {
		t.Error("initially should not be healthy")
	}
}

func TestProberReadinessInitialState(t *testing.T) {
	p := NewProber(log.NewNopLogger())

	if p.isReady() {
		t.Error("initially should not be ready")
	}
}

func TestProberReadyStatusSetting(t *testing.T) {
	testError := fmt.Errorf("test error")
	p := NewProber(log.NewNopLogger())

	p.Ready()

	if !p.isReady() {
		t.Error("should be ready")
	}

	p.NotReady(testError)

	if p.isReady() {
		t.Error("should not be ready")
	}
}

func TestProberHealthyStatusSetting(t *testing.T) {
	testError := fmt.Errorf("test error")
	p := NewProber(log.NewNopLogger())

	p.SetHealthy()

	if !p.isHealthy() {
		t.Error("should be healthy")
	}

	p.NotHealthy(testError)

	if p.isHealthy() {
		t.Error("should not be healthy")
	}
}

func TestProberMuxRegistering(t *testing.T) {
	serverAddress := fmt.Sprintf("localhost:%d", 8081)

	l, err := net.Listen("tcp", serverAddress)
	if err != nil {
		t.Fatal("tcp initialization error")
	}

	logger := log.NewNopLogger()
	mux := http.NewServeMux()

	var g run.Group

	g.Add(func() error {
		return fmt.Errorf("serve probes %w", http.Serve(l, mux))
	}, func(err error) {
		t.Fatalf("server failed: %v", err)
	})

	healthyEndpointPath := "/-/healthy"
	readyEndpointPath := "/-/ready"

	p := NewProber(logger)
	mux.HandleFunc(healthyEndpointPath, p.HealthyHandler())
	mux.HandleFunc(readyEndpointPath, p.ReadyHandler())

	go func() { _ = g.Run() }()

	{
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		resp, err := doGet(ctx, path.Join(serverAddress, healthyEndpointPath))
		if err != nil {
			t.Fatal("doGet failed")
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Errorf("should not be healthy, response code: %d", resp.StatusCode)
		}
	}

	{
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		resp, err := doGet(ctx, path.Join(serverAddress, readyEndpointPath))
		if err != nil {
			t.Fatal("doGet failed")
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Errorf("should not be ready, response code: %d", resp.StatusCode)
		}
	}

	{
		p.SetHealthy()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		resp, err := doGet(ctx, path.Join(serverAddress, healthyEndpointPath))
		if err != nil {
			t.Fatal("doGet failed")
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("should be healthy, response code: %d", resp.StatusCode)
		}
	}

	{
		p.Ready()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		resp, err := doGet(ctx, path.Join(serverAddress, readyEndpointPath))
		if err != nil {
			t.Fatal("doGet failed")
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("should be ready, response code: %d", resp.StatusCode)
		}
	}
}

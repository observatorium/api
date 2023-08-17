package server

import (
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestInstrumentedHandlerFactory_ConcurrentAccess(t *testing.T) {
	r := prometheus.NewRegistry()
	hardcodedLabels := []string{"group", "handler"}
	extraLabels := prometheus.Labels{"group": "test", "handler": "concurrency"}
	handler := http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Duration(rand.Int63n(100) * int64(time.Millisecond)))
	})
	numRequests := 1000

	f := NewInstrumentedHandlerFactory(r, hardcodedLabels)
	h := f.NewHandler(extraLabels, handler)

	wg := &sync.WaitGroup{}
	wg.Add(numRequests)
	for i := 0; i < numRequests; i++ {
		go func() {
			defer wg.Done()

			wr := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			time.Sleep(time.Duration(rand.Int63n(100) * int64(time.Millisecond)))
			h(wr, r)
		}()
	}

	wg.Wait()
}

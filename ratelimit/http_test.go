package ratelimit_test

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/go-cmp/cmp"
	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/ratelimit"
)

const (
	testPathOne = "/test-one"
	testPathTwo = "/test-two"
	testTenant  = "test-tenant"
)

func TestWithLocalRateLimiter(t *testing.T) {
	type pathTestParams struct {
		path                    string
		waitBetween             time.Duration
		expectedOK              int
		expectedTooManyRequests int
	}

	matcherOne, err := regexp.Compile(testPathOne)
	if err != nil {
		t.Fatal(err)
	}

	matcherTwo, err := regexp.Compile(testPathTwo)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		reqNum    int
		configs   []ratelimit.Config
		pathTests []pathTestParams
	}{
		{
			name:   "no config",
			reqNum: 5,
			pathTests: []pathTestParams{
				{
					path:                    testPathOne,
					waitBetween:             1 * time.Millisecond,
					expectedOK:              5,
					expectedTooManyRequests: 0,
				},
			},
		},
		{
			name: "one rate limiter",
			configs: []ratelimit.Config{
				{
					Tenant:  testTenant,
					Matcher: matcherOne,
					Limit:   1,
					Window:  10 * time.Second,
				},
			},
			reqNum: 5,
			pathTests: []pathTestParams{
				{
					path:                    testPathOne,
					waitBetween:             1 * time.Millisecond,
					expectedOK:              1,
					expectedTooManyRequests: 4,
				},
			},
		},
		{
			name: "two rate limiters",
			configs: []ratelimit.Config{
				{
					Tenant:  testTenant,
					Matcher: matcherOne,
					Limit:   1,
					Window:  10 * time.Second,
				},
				{
					Tenant:  testTenant,
					Matcher: matcherTwo,
					Limit:   3,
					Window:  10 * time.Second,
				},
			},
			reqNum: 5,
			pathTests: []pathTestParams{
				{
					path:                    testPathOne,
					waitBetween:             1 * time.Millisecond,
					expectedOK:              1,
					expectedTooManyRequests: 4,
				},
				{
					path:                    testPathTwo,
					waitBetween:             1 * time.Millisecond,
					expectedOK:              3,
					expectedTooManyRequests: 2,
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rlmw := ratelimit.WithLocalRateLimiter(c.configs...)

			r := chi.NewMux()

			r.Group(func(r chi.Router) {
				r.Use(authentication.WithTenant)
				r.Use(rlmw)

				r.HandleFunc(testPathOne+"/{tenant}", func(res http.ResponseWriter, req *http.Request) {
					res.WriteHeader(http.StatusOK)
				})
				r.HandleFunc(testPathTwo+"/{tenant}", func(res http.ResponseWriter, req *http.Request) {
					res.WriteHeader(http.StatusOK)
				})
			})

			ts := httptest.NewServer(r)

			for _, pathTest := range c.pathTests {
				results := make(chan int)
				errCh := make(chan error)
				var wg sync.WaitGroup
				for i := 0; i < c.reqNum; i++ {
					wg.Add(1)
					time.Sleep(pathTest.waitBetween)
					go func() {
						defer wg.Done()

						req, err := http.NewRequest(
							http.MethodGet,
							ts.URL+pathTest.path+"/"+testTenant,
							nil,
						)
						if err != nil {
							errCh <- err
							return
						}

						res, err := http.DefaultClient.Do(req)
						if err != nil {
							errCh <- err
							return
						}

						results <- res.StatusCode
					}()
				}

				go func() {
					wg.Wait()
					close(errCh)
					close(results)
				}()

				select {
				case err := <-errCh:
					if err != nil {
						t.Fatal(err)
					}
				default:
				}

				var (
					gotOKs             int
					gotTooManyRequests int
				)
				for r := range results {
					switch r {
					case http.StatusOK:
						gotOKs++
					case http.StatusTooManyRequests:
						gotTooManyRequests++
					}
				}

				if out := cmp.Diff(pathTest.expectedOK, gotOKs); out != "" {
					t.Fatalf(
						"unexpected number of OK responses: wanted %v, got %v",
						pathTest.expectedOK,
						gotOKs,
					)
				}
				if out := cmp.Diff(pathTest.expectedTooManyRequests, gotTooManyRequests); out != "" {
					t.Fatalf(
						"unexpected number of Too Many Requests responses: wanted %v, got %v",
						pathTest.expectedTooManyRequests,
						gotTooManyRequests,
					)
				}
			}

		})
	}
}

func TestWithLocalSharedRateLimiter(t *testing.T) {

}

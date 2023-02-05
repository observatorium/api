package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/logger"
)

const (
	testPathOne = "/test-one"
	testPathTwo = "/test-two"
	testTenant  = "test-tenant"
)

var mockResetTime = time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

type pathTestParams struct {
	path                    string
	waitBetween             time.Duration
	expectedOK              int
	expectedTooManyRequests int
}

// nolint:dupl,funlen,scopelint
func TestWithLocalRateLimiter(t *testing.T) {
	matcherOne, matcherTwo := compileMatchers(t)
	cases := []struct {
		name      string
		reqNum    int
		configs   []Config
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
			configs: []Config{
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
			configs: []Config{
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
			rlmw := WithLocalRateLimiter(c.configs...)

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
				gotOKs, gotTooManyRequests, _ := launchTestRequests(t, ts.URL, pathTest, c.reqNum)

				if pathTest.expectedOK != gotOKs {
					t.Fatalf(
						"%v: unexpected number of OK responses: wanted %v, got %v",
						pathTest.path,
						pathTest.expectedOK,
						gotOKs,
					)
				}
				if pathTest.expectedTooManyRequests != gotTooManyRequests {
					t.Fatalf(
						"%v: unexpected number of Too Many Requests responses: wanted %v, got %v",
						pathTest.path,
						pathTest.expectedTooManyRequests,
						gotTooManyRequests,
					)
				}
			}
		})
	}
}

type mockSharedLimiter struct {
	mtx      sync.Mutex
	received int64
}

func (m *mockSharedLimiter) GetRateLimits(ctx context.Context, req *request) (remaining, resetTime int64, err error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if req.limit > m.received {
		m.received++
		return m.received, mockResetTime, nil
	}

	return m.received, mockResetTime, errOverLimit
}

func (m *mockSharedLimiter) reset() {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	m.received = 0
}

// nolint:dupl,funlen,scopelint
func TestWithSharedRateLimiter(t *testing.T) {
	matcherOne, matcherTwo := compileMatchers(t)
	cases := []struct {
		name      string
		reqNum    int
		configs   []Config
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
			configs: []Config{
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
			configs: []Config{
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
			limiter := &mockSharedLimiter{}
			logger := logger.NewLogger("debug", "logfmt", "observatorium")
			rlmw := WithSharedRateLimiter(logger, limiter, c.configs...)

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
				limiter.reset()
				gotOKs, gotTooManyRequests, gotHeaders := launchTestRequests(t, ts.URL, pathTest, c.reqNum)

				if pathTest.expectedOK != gotOKs {
					t.Fatalf(
						"%v: unexpected number of OK responses: wanted %v, got %v",
						pathTest.path,
						pathTest.expectedOK,
						gotOKs,
					)
				}
				if pathTest.expectedTooManyRequests != gotTooManyRequests {
					t.Fatalf(
						"%v: unexpected number of Too Many Requests responses: wanted %v, got %v",
						pathTest.path,
						pathTest.expectedTooManyRequests,
						gotTooManyRequests,
					)
				}

				// If no rate limiter configured, skip checking headers.
				if len(c.configs) == 0 {
					continue
				}

				if len(gotHeaders) == 0 {
					t.Fatalf("%v: no headers found", pathTest.path)
				}

				for _, hh := range gotHeaders {
					if limit := hh.Get(headerKeyLimit); limit == "" {
						t.Fatalf("%v: header with key '%v' not found", pathTest.path, headerKeyLimit)
					}
					if remaining := hh.Get(headerKeyRemaining); remaining == "" {
						t.Fatalf("%v: header with key '%v' not found", pathTest.path, headerKeyRemaining)
					}
					if reset := hh.Get(headerKeyReset); reset == "" {
						t.Fatalf("%v: header with key '%v' not found", pathTest.path, headerKeyReset)

						if reset != strconv.FormatInt(mockResetTime, 10) {
							t.Fatalf("%v: unexpected reset time header: wanted %v, got %v",
								pathTest.path,
								mockResetTime,
								reset,
							)
						}
					}
				}
			}
		})
	}
}

func launchTestRequests(t *testing.T, baseURL string, pathTest pathTestParams, reqNum int) (int, int, []http.Header) {
	type result struct {
		statusCode int
		headers    http.Header
	}

	results := make(chan result)
	errCh := make(chan error)

	var wg sync.WaitGroup

	for i := 0; i < reqNum; i++ {
		wg.Add(1)
		time.Sleep(pathTest.waitBetween)

		go func() {
			defer wg.Done()

			res, err := http.Get(baseURL + pathTest.path + "/" + testTenant)
			if err != nil {
				errCh <- err
				return
			}

			defer res.Body.Close()

			results <- result{
				res.StatusCode,
				res.Header,
			}
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
		gotHeaders         = make([]http.Header, 0, len(results))
	)

	for r := range results {
		switch r.statusCode {
		case http.StatusOK:
			gotOKs++
		case http.StatusTooManyRequests:
			gotTooManyRequests++
		}

		gotHeaders = append(gotHeaders, r.headers)
	}

	return gotOKs, gotTooManyRequests, gotHeaders
}

func compileMatchers(t *testing.T) (*regexp.Regexp, *regexp.Regexp) {
	matcherOne, err := regexp.Compile(testPathOne)
	if err != nil {
		t.Fatal(err)
	}

	matcherTwo, err := regexp.Compile(testPathTwo)
	if err != nil {
		t.Fatal(err)
	}

	return matcherOne, matcherTwo
}

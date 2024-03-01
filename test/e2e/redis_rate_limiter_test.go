package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/efficientgo/core/backoff"
	"github.com/efficientgo/core/testutil"
	"github.com/efficientgo/e2e"

	"github.com/observatorium/api/ratelimit"
)

func TestRedisRateLimiter_GetRateLimits(t *testing.T) {
	t.Parallel()
	// Start isolated environment with given ref.
	e, err := e2e.New(e2e.WithName("redis-rate-li"))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	redis := createRedisContainer(e)
	t.Cleanup(func() { _ = redis.Stop() })
	err = e2e.StartAndWaitReady(redis)
	testutil.Ok(t, err)

	type args struct {
		ctx context.Context
		req *ratelimit.Request
	}
	tests := []struct {
		name          string
		args          args
		totalHits     int64
		wantRemaining int64
		// wantResetTimeFunc is used to calculate the expected reset time just before the hits are sent to the rate limiter.
		wantResetTimeFunc func() time.Time
		wantErr           error
		// waitBeforeLastHit is used to wait the given amount of time and then make a last hit on the rate limiter.
		waitBeforeLastHit time.Duration
	}{
		{
			name: "Single hit, far from limit",
			args: args{
				ctx: context.Background(),
				req: &ratelimit.Request{
					Key:      "single-hit",
					Limit:    10,
					Duration: (10 * time.Second).Milliseconds(),
				},
			},
			totalHits:     1,
			wantRemaining: 9,
			wantResetTimeFunc: func() time.Time {
				return time.Now().Add(1 * time.Second)
			},
		},
		{
			name: "At the edge of the limit",
			args: args{
				ctx: context.Background(),
				req: &ratelimit.Request{
					Key:      "edge-hit",
					Limit:    10,
					Duration: (10 * time.Second).Milliseconds(),
				},
			},
			totalHits:     10,
			wantRemaining: 0,
			wantResetTimeFunc: func() time.Time {
				return time.Now().Add(10 * time.Second)
			},
		},
		{
			name: "Beyond the limit",
			args: args{
				ctx: context.Background(),
				req: &ratelimit.Request{
					Key:      "beyond-limit",
					Limit:    10,
					Duration: (10 * time.Second).Milliseconds(),
				},
			},
			totalHits:     11,
			wantRemaining: 0,
			wantErr:       ratelimit.ErrOverLimit,
			wantResetTimeFunc: func() time.Time {
				return time.Now().Add(10 * time.Second)
			},
		},
		{
			// The test scenario is:
			// 1. Hit the rate limiter 2 times. No big amount of time should pass between the hits.
			//    This ensures the bucket doesn't leak.
			// 2. Wait for 2 seconds. This means the bucket will leak 2 tokens.
			// 3. Hit the rate limiter 1 time. This should succeed.
			//    If the bucket didn't leak, this would get total remaining of 7.
			//    The reset time should be 3 seconds from the first hit.
			name: "Wait for 1 leak",
			args: args{
				ctx: context.Background(),
				req: &ratelimit.Request{
					Key:      "wait-for-leak",
					Limit:    10,
					Duration: (10 * time.Second).Milliseconds(),
				},
			},
			totalHits: 2,
			// Waits for 2 seconds instead of 1 because of rounding in the algorithm.
			waitBeforeLastHit: 2 * time.Second,
			wantRemaining:     9,
			wantResetTimeFunc: func() time.Time {
				return time.Now().Add(3 * time.Second)
			},
		},
	}

	for _, tt := range tests {
		tt := tt // Can be removed when Go version >= 1.22 is set in the go.mod file.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := backoff.New(context.Background(), backoff.Config{
				Min:        100 * time.Millisecond,
				Max:        1 * time.Second,
				MaxRetries: 5,
			})

			var (
				err error
				r   *ratelimit.RedisRateLimiter
			)
			for b.Reset(); b.Ongoing(); b.Wait() {
				r, err = ratelimit.NewRedisRateLimiter([]string{redis.Endpoint("http")})
			}
			testutil.Ok(t, err)
			testutil.Assert(t, r != nil)

			var gotRemaining, gotResetTime int64
			wantResetTime := tt.wantResetTimeFunc()
			for i := int64(0); i < tt.totalHits; i++ {
				gotRemaining, gotResetTime, err = r.GetRateLimits(tt.args.ctx, tt.args.req)
			}
			if tt.waitBeforeLastHit > 0 {
				time.Sleep(tt.waitBeforeLastHit)
				gotRemaining, gotResetTime, err = r.GetRateLimits(tt.args.ctx, tt.args.req)
			}

			testutil.Equals(t, tt.wantErr, err)
			testutil.Equals(t, tt.wantRemaining, gotRemaining)

			parsedGotResetTime := time.UnixMilli(gotResetTime)
			timeDifference := parsedGotResetTime.Sub(wantResetTime).Seconds()

			testutil.Assert(t, -1 <= timeDifference && timeDifference <= 1, "gotResetTime should be within 1 second of wantResetTime, it was %f seconds off", timeDifference)
		})
	}
}

func createRedisContainer(env e2e.Environment) e2e.Runnable {
	return env.Runnable("redis").WithPorts(map[string]int{"http": 6379}).Init(
		e2e.StartOptions{
			Image:     "redis",
			Readiness: e2e.NewCmdReadinessProbe(e2e.Command{Cmd: "redis-cli", Args: []string{"ping"}}),
		},
	)
}

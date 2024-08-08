package ratelimit

import (
	"context"
	_ "embed"
	"strconv"
	"time"

	"github.com/redis/rueidis"
)

//go:embed gcra_rate_limit.lua
var gcraRateLimitScript string

// RedisRateLimiter is a type that represents a rate limiter that uses Redis as its backend.
// The rate limiting is a leaky bucket implementation using the generic cell rate algorithm.
// See https://en.wikipedia.org/wiki/Generic_cell_rate_algorithm for details on how this algorithm works.
type RedisRateLimiter struct {
	client rueidis.Client
}

// Ensure RedisRateLimiter implements the SharedRateLimiter interface.
var _ SharedRateLimiter = (*RedisRateLimiter)(nil)

// NewRedisRateLimiter creates a new instance of RedisRateLimiter.
func NewRedisRateLimiter(addresses []string) (*RedisRateLimiter, error) {
	client, err := rueidis.NewClient(rueidis.ClientOption{InitAddress: addresses})
	if err != nil {
		return nil, err
	}
	return &RedisRateLimiter{client: client}, nil
}

// GetRateLimits retrieves the rate limits for a given request using a Redis Rate Limiter.
// It returns the amount of remaining requests, the reset time in milliseconds, and any error that occurred.
func (r *RedisRateLimiter) GetRateLimits(ctx context.Context, req *Request) (remaining, resetTime int64, err error) {
	inspectScript := rueidis.NewLuaScript(gcraRateLimitScript)
	rateLimitParameters := []string{
		strconv.FormatInt(time.Now().UnixMilli(), 10), // now
		strconv.FormatInt(req.Limit, 10),              // burst
		strconv.FormatInt(req.Limit, 10),              // rate
		strconv.FormatInt(req.Duration, 10),           // period
		"1",                                           // cost
	}
	result := inspectScript.Exec(ctx, r.client, []string{req.Key}, rateLimitParameters)
	limited, remaining, resetIn, err := r.parseRateLimitResult(&result)
	if err != nil {
		return 0, 0, err
	}
	resetTime = time.Now().Add(time.Duration(resetIn) * time.Millisecond).UnixMilli()
	if limited {
		return remaining, resetTime, ErrOverLimit
	}
	return remaining, resetTime, nil
}

// parseRateLimitResult parses the result of a rate limit check from Redis.
// It takes a RedisResult as input and returns the parsed rate limit values: whether the request is limited,
// the number of remaining requests, the reset time in milliseconds, and any error that occurred during parsing.
func (r *RedisRateLimiter) parseRateLimitResult(result *rueidis.RedisResult) (limited bool, remaining, resetIn int64, err error) {
	values, err := result.ToArray()
	if err != nil {
		return false, 0, 0, err
	}

	limited, err = values[0].AsBool()
	if err != nil {
		return false, 0, 0, err
	}

	remaining, err = values[1].AsInt64()
	if err != nil {
		return false, 0, 0, err
	}

	resetIn, err = values[3].AsInt64()
	if err != nil {
		return false, 0, 0, err
	}

	return limited, remaining, resetIn, nil
}

package authorization

import (
	"context"
)

type contextKey string

const (
	dataKey contextKey = "data"
)

// WithData adds authorization data to the request context.
// This data is typically used by label enforcers.
func WithData(ctx context.Context, data string) context.Context {
	return context.WithValue(ctx, dataKey, data)
}

// GetData extracts authorization data from the context.
func GetData(ctx context.Context) (string, bool) {
	value := ctx.Value(dataKey)
	if value == nil {
		return "", false
	}

	data, ok := value.(string)
	return data, ok
}

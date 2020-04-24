package authentication

import (
	"context"
	"net/http"
	"strings"
)

// Key to use when setting the request ID.
type ctxKeyUser User

// userKey is the key that holds the User in a request context.
var userKey ctxKeyUser

func GetUser(ctx context.Context) (User, bool) {
	value := ctx.Value(userKey)
	user, ok := value.(User)
	return user, ok
}

func Authenticate(next http.Handler) http.Handler {
	// Map some token to a user
	users := map[string]User{
		"62f8be5aba09a675d1eff3702036c267": {
			ID:   "7954587a-bb79-4cfa-abc0-99c0818eeb2e",
			Name: "Erika Mustermann",
		},
		"0925467e1cc53074a440dae7ae67e3e9": {
			ID:   "12ed2d0d-50d4-431d-acc0-ef166a759601",
			Name: "Max Mustermann",
		},
		"22a313110bf5b84c0a58eecc27deaa30": {
			ID:   "04c134ea-aa6b-4c5f-9bcf-1355cd2c5cc2",
			Name: "John Doe",
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := strings.Split(r.Header.Get("Authorization"), " ")
		if len(authHeader) != 2 {
			http.Error(w, "expect authorization header with bearer token", http.StatusBadRequest)
			return
		}

		user, ok := users[authHeader[1]]
		if !ok {
			http.Error(w, "failed to find user for token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r.WithContext(
			context.WithValue(r.Context(), userKey, user),
		))
	})
}

package tenant

import (
	"fmt"
	"net/http"

	"github.com/observatorium/observatorium/internal/authentication"
)

func Middleware(next http.Handler) http.Handler {
	tenants := []Tenant{{Name: "telemetry"}, {Name: "CI"}}
	usersTenants := map[string][]Tenant{
		"7954587a-bb79-4cfa-abc0-99c0818eeb2e": {tenants[0], tenants[1]}, // Erika - all
		"12ed2d0d-50d4-431d-acc0-ef166a759601": {tenants[1]},             // Max - only CI
		"04c134ea-aa6b-4c5f-9bcf-1355cd2c5cc2": {},                       // John - nothing
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := authentication.GetUser(r.Context())
		if !ok {
			http.Error(w, "lol", http.StatusInternalServerError)
			return
		}

		userTenants, ok := usersTenants[user.ID]
		if !ok {
			http.Error(w, "no tentants for you, haha", http.StatusUnauthorized)
			return
		}

		fmt.Printf("%+v\n", userTenants)

		next.ServeHTTP(w, r)
	})
}

package middlewares

import (
	"net/http"
)

func NewSwitch(condition bool) Middleware {
	return func(f http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if condition {
				http.Error(w, http.StatusText(http.StatusTeapot), http.StatusTeapot)
				return
			}
			f(w, r)
		}
	}
}

// +build tools

package mock

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/read", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// TODO:: Write some bytes
	})

	http.HandleFunc("/write", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}

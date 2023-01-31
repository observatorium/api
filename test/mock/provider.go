//go:build tools

package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/timestamp"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/promql/parser"
)

type response struct {
	Status    string      `json:"status"`
	Data      interface{} `json:"data,omitempty"`
	ErrorType string      `json:"errorType,omitempty"`
	Error     string      `json:"error,omitempty"`
	Warnings  []string    `json:"warnings,omitempty"`
}
type queryData struct {
	ResultType parser.ValueType `json:"resultType"`
	Result     parser.Value     `json:"result"`
}

var (
	data = queryData{
		ResultType: parser.ValueTypeScalar,
		Result: promql.Scalar{
			V: 0.333,
			T: timestamp.FromTime(time.Unix(0, 0).Add(123 * time.Second)),
		},
	}

	rangeData = queryData{
		ResultType: parser.ValueTypeVector,
		Result: promql.Vector{
			{
				Metric: labels.Labels{
					{
						Name:  "__name__",
						Value: "test_metric",
					},
					{
						Name:  "foo",
						Value: "bar",
					},
					{
						Name:  "replica",
						Value: "a",
					},
				},
				Point: promql.Point{
					T: 123000,
					V: 2,
				},
			},
			{
				Metric: labels.Labels{
					{
						Name:  "__name__",
						Value: "test_metric",
					},
					{
						Name:  "foo",
						Value: "bar",
					},
					{
						Name:  "a",
						Value: "a",
					},
				},
				Point: promql.Point{
					T: 123000,
					V: 2,
				},
			},
			{
				Metric: labels.Labels{
					{
						Name:  "__name__",
						Value: "test_metric",
					},
					{
						Name:  "foo",
						Value: "bar",
					},
					{
						Name:  "b",
						Value: "b",
					},
				},
				Point: promql.Point{
					T: 123000,
					V: 2,
				},
			},
		},
	}
)

func main() {
	var listen string
	flag.StringVar(&listen, "listen", ":8888", "The address on which internal server runs.")

	http.HandleFunc("/query", queryHandler(data))            // TODO: Randomize results.
	http.HandleFunc("/query_range", queryHandler(rangeData)) // TODO: Randomize results.
	http.HandleFunc("/write", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	log.Println("start listening...")
	log.Fatal(http.ListenAndServe(listen, nil))
}

func queryHandler(data queryData) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		resp := &response{
			Status: "success",
			Data:   data,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

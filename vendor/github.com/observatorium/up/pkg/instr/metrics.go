package instr

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	RemoteWriteRequests     *prometheus.CounterVec
	QueryResponses          *prometheus.CounterVec
	MetricValueDifference   prometheus.Histogram
	CustomQueryExecuted     *prometheus.CounterVec
	CustomQueryErrors       *prometheus.CounterVec
	CustomQueryLastDuration *prometheus.GaugeVec
}

func RegisterMetrics(reg *prometheus.Registry) Metrics {
	m := Metrics{
		RemoteWriteRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "up_remote_writes_total",
			Help: "Total number of remote write requests.",
		}, []string{"result"}),
		QueryResponses: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "up_queries_total",
			Help: "The total number of queries made.",
		}, []string{"result"}),
		MetricValueDifference: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "up_metric_value_difference",
			Help:    "The time difference between the current timestamp and the timestamp in the metrics value.",
			Buckets: prometheus.LinearBuckets(4, 0.25, 16), //nolint:gomnd
		}),
		CustomQueryExecuted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "up_custom_query_executed_total",
			Help: "The total number of custom specified queries executed.",
		}, []string{"query"}),
		CustomQueryErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "up_custom_query_errors_total",
			Help: "The total number of custom specified queries executed.",
		}, []string{"query"}),
		CustomQueryLastDuration: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "up_custom_query_last_duration",
			Help: "The duration of the query execution last time the query was executed successfully.",
		}, []string{"query"}),
	}
	reg.MustRegister(
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
		m.RemoteWriteRequests,
		m.QueryResponses,
		m.MetricValueDifference,
		m.CustomQueryExecuted,
		m.CustomQueryErrors,
		m.CustomQueryLastDuration,
	)

	return m
}

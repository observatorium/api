package remotewrite

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strconv"

	"github.com/go-chi/chi/middleware"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	promconfig "github.com/prometheus/common/config"
)

const (
	THANOS_ENDPOINT_NAME = "thanos-receiver"
)

type Endpoint struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
	// +optional
	ClientConfig *promconfig.HTTPClientConfig `yaml:"http_client_config,omitempty"`
}

var (
	requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "http_proxy_requests_total",
		Help:        "Counter of proxy HTTP requests.",
		ConstLabels: prometheus.Labels{"proxy": "metricsv1-write"},
	}, []string{"method"})

	remotewriteRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "remote_write_requests_total",
		Help:        "Counter of remote write requests.",
		ConstLabels: prometheus.Labels{"proxy": "metricsv1-remotewrite"},
	}, []string{"code", "name"})
)

func remoteWrite(write *url.URL, endpoints []Endpoint, logger log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.With(prometheus.Labels{"method": r.Method}).Inc()

		body, _ := ioutil.ReadAll(r.Body)
		_ = r.Body.Close()
		r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

		if write != nil {
			remotewriteUrl := url.URL{}
			remotewriteUrl.Path = path.Join(write.Path, r.URL.Path)
			remotewriteUrl.Host = write.Host
			remotewriteUrl.Scheme = write.Scheme
			endpoints[len(endpoints)-1].URL = remotewriteUrl.String()
		}

		rlogger := log.With(logger, "request", middleware.GetReqID(r.Context()))
		for _, endpoint := range endpoints {
			var client *http.Client
			var err error
			if endpoint.ClientConfig == nil {
				client = &http.Client{}
			} else {
				client, err = promconfig.NewClientFromConfig(*endpoint.ClientConfig, endpoint.Name, true)
				if err != nil {
					level.Error(rlogger).Log("failed to create a new HTTP client", "err", err)
				}
			}

			req, err := http.NewRequest(http.MethodPost, endpoint.URL, bytes.NewReader(body))
			req.Header = r.Header
			if err != nil {
				level.Error(rlogger).Log("msg", "Failed to create the forward request", "err", err, "url", endpoint.URL)
			} else {
				ep := endpoint
				go func() {
					resp, err := client.Do(req)
					if err != nil {
						remotewriteRequests.With(prometheus.Labels{"code": "<error>", "name": ep.Name}).Inc()
						level.Error(rlogger).Log("msg", "Failed to send request to the server", "err", err)
					} else {
						defer resp.Body.Close()
						remotewriteRequests.With(prometheus.Labels{"code": strconv.Itoa(resp.StatusCode), "name": ep.Name}).Inc()
						if resp.StatusCode >= 300 || resp.StatusCode < 200 {
							responseBody, err := ioutil.ReadAll(resp.Body)
							if err != nil {
								level.Error(rlogger).Log("msg", "Failed to read response of the forward request", "err", err, "return code", resp.Status, "url", ep.URL)
							} else {
								level.Error(rlogger).Log("msg", "Failed to forward metrics", "return code", resp.Status, "response", string(responseBody), "url", ep.URL)
							}
						} else {
							level.Debug(rlogger).Log("msg", "Metrics forwarded successfully", "url", ep.URL)
						}
					}
				}()
			}
		}
	})
}

func Proxy(write *url.URL, endpoints []Endpoint, logger log.Logger, r *prometheus.Registry) http.Handler {

	r.MustRegister(requests)
	r.MustRegister(remotewriteRequests)

	if endpoints == nil {
		endpoints = []Endpoint{}
	}

	if write != nil {
		endpoints = append(endpoints, Endpoint{
			URL:  write.String(),
			Name: THANOS_ENDPOINT_NAME,
		})
	}

	return remoteWrite(write, endpoints, logger)
}

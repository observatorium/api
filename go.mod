module github.com/observatorium/api

go 1.16

require (
	github.com/HdrHistogram/hdrhistogram-go v1.1.2 // indirect
	github.com/brancz/kube-rbac-proxy v0.11.0
	github.com/cloudflare/cfssl v1.6.1
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/deepmap/oapi-codegen v1.9.1
	github.com/efficientgo/e2e v0.11.1
	github.com/efficientgo/tools/core v0.0.0-20210731122119-5d4a0645ce9a
	github.com/ghodss/yaml v1.0.0
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-chi/chi/v5 v5.0.7
	github.com/go-chi/httprate v0.5.3
	github.com/go-kit/log v0.2.0
	github.com/golang-jwt/jwt/v4 v4.3.0
	github.com/golang/protobuf v1.5.2
	github.com/gorilla/websocket v1.5.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.0.0-rc.2.0.20211207221722-a5b9e0b0458c
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/metalmatze/signal v0.0.0-20210307161603-1c9aa721a97a
	github.com/mitchellh/mapstructure v1.4.3
	github.com/mwitkow/grpc-proxy v0.0.0-20181017164139-0f1106ef9c76
	github.com/oklog/run v1.1.0
	github.com/onsi/ginkgo v1.16.3 // indirect
	github.com/onsi/gomega v1.13.0 // indirect
	github.com/open-policy-agent/opa v0.23.2
	github.com/pkg/errors v0.9.1
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/prometheus-community/prom-label-proxy v0.3.1-0.20210623095334-9d425172d7bb
	github.com/prometheus/client_golang v1.12.1
	github.com/prometheus/common v0.32.1
	github.com/prometheus/prometheus v1.8.2-0.20210621150501-ff58416a0b02
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.18.0
	go.opentelemetry.io/contrib/propagators v0.18.0
	go.opentelemetry.io/otel v0.18.0
	go.opentelemetry.io/otel/exporters/trace/jaeger v0.18.0
	go.opentelemetry.io/otel/sdk v0.18.0
	go.opentelemetry.io/otel/trace v0.18.0
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/automaxprocs v1.4.0
	go.uber.org/goleak v1.1.11-0.20210813005559-691160354723 // indirect
	golang.org/x/net v0.0.0-20210917221730-978cfadd31cf // indirect
	golang.org/x/oauth2 v0.0.0-20210514164344-f6687ab2804c
	golang.org/x/time v0.0.0-20210723032227-1f47c861a9ac // indirect
	google.golang.org/genproto v0.0.0-20210917145530-b395a37504d4
	google.golang.org/grpc v1.44.0
	google.golang.org/protobuf v1.27.1
	gopkg.in/square/go-jose.v2 v2.4.1 // indirect
	k8s.io/apimachinery v0.21.1
	k8s.io/apiserver v0.21.1
	k8s.io/client-go v0.21.1
	k8s.io/component-base v0.21.1
)

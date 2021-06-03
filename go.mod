module github.com/observatorium/api

go 1.14

require (
	github.com/brancz/kube-rbac-proxy v0.5.0
	github.com/cloudflare/cfssl v1.4.1
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/ghodss/yaml v1.0.0
	github.com/go-chi/chi v4.0.2+incompatible
	github.com/go-chi/httprate v0.4.0
	github.com/go-kit/kit v0.10.0
	github.com/golang/protobuf v1.4.3
	github.com/grpc-ecosystem/go-grpc-middleware v1.0.1-0.20190118093823-f849b5445de4
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/lib/pq v1.3.0 // indirect
	github.com/metalmatze/signal v0.0.0-20201002154727-d0c16e42a3cf
	github.com/oklog/run v1.1.0
	github.com/open-policy-agent/opa v0.23.2
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/prometheus-community/prom-label-proxy v0.3.0
	github.com/prometheus/client_golang v1.5.1
	github.com/prometheus/common v0.9.1
	github.com/prometheus/prometheus v1.8.2-0.20200507164740-ecee9c8abfd1
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.16.0
	go.opentelemetry.io/contrib/propagators v0.16.0
	go.opentelemetry.io/otel v0.16.0
	go.opentelemetry.io/otel/exporters/trace/jaeger v0.16.0
	go.opentelemetry.io/otel/sdk v0.16.0
	go.uber.org/automaxprocs v1.2.0
	golang.org/x/oauth2 v0.0.0-20201208152858-08078c50e5b5
	google.golang.org/api v0.39.0 // indirect
	google.golang.org/genproto v0.0.0-20201214200347-8c77b98c765d
	google.golang.org/grpc v1.34.0
	google.golang.org/protobuf v1.25.0
	gopkg.in/square/go-jose.v2 v2.4.1 // indirect
	gopkg.in/yaml.v2 v2.3.0 // indirect
	k8s.io/component-base v0.18.0
)

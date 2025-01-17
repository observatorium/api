module github.com/observatorium/observatorium

go 1.21

require (
	github.com/brancz/kube-rbac-proxy v0.5.0
	github.com/cloudflare/cfssl v1.4.1
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/ghodss/yaml v1.0.0
	github.com/go-chi/chi v4.0.2+incompatible
	github.com/go-kit/kit v0.10.0
	github.com/golang/protobuf v1.4.3 // indirect
	github.com/metalmatze/signal v0.0.0-20200616171423-be84551ba3ce
	github.com/oklog/run v1.1.0
	github.com/prometheus/client_golang v1.11.1
	github.com/prometheus/common v0.30.0
	github.com/prometheus/procfs v0.6.0 // indirect
	github.com/prometheus/prometheus v1.8.2-0.20200305080338-7164b58945bb
	go.uber.org/automaxprocs v1.2.0
	golang.org/x/net v0.34.0 // indirect
	golang.org/x/oauth2 v0.0.0-20210514164344-f6687ab2804c
	golang.org/x/sys v0.29.0 // indirect
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/component-base v0.18.0
)

require github.com/mwitkow/go-conntrack v0.0.0-20190716064945-2f068394615f // indirect

require (
	github.com/OneOfOne/xxhash v1.2.6 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash v1.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.1.1 // indirect
	github.com/edsrzf/mmap-go v1.0.0 // indirect
	github.com/go-logfmt/logfmt v0.5.0 // indirect
	github.com/golang/snappy v0.0.3 // indirect
	github.com/google/certificate-transparency-go v1.0.21 // indirect
	github.com/jpillora/backoff v1.0.0 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/opentracing/opentracing-go v1.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/weppos/publicsuffix-go v0.5.0 // indirect
	github.com/zmap/zcrypto v0.0.0-20190729165852-9051775e6a2e // indirect
	github.com/zmap/zlint v0.0.0-20190806154020-fd021b4cfbeb // indirect
	golang.org/x/crypto v0.32.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/appengine v1.6.6 // indirect
	google.golang.org/protobuf v1.26.0-rc.1 // indirect
	gopkg.in/square/go-jose.v2 v2.4.1 // indirect
	k8s.io/apimachinery v0.18.0 // indirect
	k8s.io/klog v1.0.0 // indirect
)

replace (
	// fix CVE-2022-24450
	github.com/nats-io/nats-server/v2 => github.com/nats-io/nats-server/v2 v2.7.2
	go.etcd.io/etcd => go.etcd.io/etcd v0.5.0-alpha.5.0.20200329194405-dd816f0735f8
	google.golang.org/grpc => google.golang.org/grpc v1.27.0
)

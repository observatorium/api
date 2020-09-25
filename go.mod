module github.com/observatorium/observatorium

go 1.14

require (
	github.com/brancz/gojsontoyaml v0.0.0-20191212081931-bf2969bbd742
	github.com/brancz/kube-rbac-proxy v0.5.0
	github.com/campoy/embedmd v1.0.0
	github.com/cloudflare/cfssl v1.4.1
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/dexidp/dex v0.0.0-20200512115545-709d4169d646
	github.com/ghodss/yaml v1.0.0
	github.com/go-chi/chi v4.0.2+incompatible
	github.com/go-kit/kit v0.10.0
	github.com/go-pluto/styx v0.0.0-20200109161911-78a77eb717b4
	github.com/golang/protobuf v1.4.0 // indirect
	github.com/google/go-jsonnet v0.15.1-0.20200310221949-724650d358b6
	github.com/grpc-ecosystem/grpc-gateway v1.14.3 // indirect
	github.com/instrumenta/kubeval v0.0.0-20200515185822-7721cbec724c
	github.com/jsonnet-bundler/jsonnet-bundler v0.3.1
	github.com/metalmatze/signal v0.0.0-20200616171423-be84551ba3ce
	github.com/observatorium/up v0.0.0-20200603110215-8a20b4e48ac0
	github.com/oklog/run v1.1.0
	github.com/open-policy-agent/opa v0.23.2
	github.com/prometheus/client_golang v1.5.1
	github.com/prometheus/common v0.9.1
	github.com/prometheus/procfs v0.0.11 // indirect
	github.com/prometheus/prometheus v1.8.2-0.20200305080338-7164b58945bb
	github.com/urfave/cli v1.22.2 // indirect
	go.uber.org/automaxprocs v1.2.0
	golang.org/x/net v0.0.0-20200324143707-d3edc9973b7e // indirect
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/sys v0.0.0-20200413165638-669c56c373c4 // indirect
	google.golang.org/genproto v0.0.0-20200413115906-b5235f65be36 // indirect
	k8s.io/component-base v0.18.0
)

replace go.etcd.io/etcd => go.etcd.io/etcd v0.5.0-alpha.5.0.20200329194405-dd816f0735f8

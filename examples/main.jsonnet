local api = (import '../jsonnet/lib/observatorium-api.libsonnet') {
  config+:: {
    local cfg = self,
    name: 'observatorium-api',
    namespace: 'observatorium',
    version: 'master-2020-05-04-v0.1.1-21-gabb9864',
    image: 'quay.io/observatorium/observatorium:' + cfg.version,
    replicas: 3,
    metrics:{
      readEndpoint: 'http://127.0.0.1:9091',
      writeEndpoint: 'http://127.0.0.1:19291',
    },
    logs:{
      readEndpoint: 'http://127.0.0.1:3100',
      writeEndpoint: 'http://127.0.0.1:3100',
    },
  },
};

local apiWithTLS = api + api.withTLS {
  config+:: {
    tls+: {
      certFile: './tmp/certs/server.pem',
      privateKeyFile: './tmp/certs/ca.pem',
      clientCAFile: './tmp/certs/server.key',
    },
  },
};

{ [name]: api[name] for name in std.objectFields(api) } +
{ ['%s-with-tls' % name]: apiWithTLS[name] for name in std.objectFields(api) }

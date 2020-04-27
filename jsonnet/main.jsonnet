local api = (import 'lib/observatorium-api.libsonnet') {
  config+:: {
    local cfg = self,
    name: 'observatorium-api',
    namespace: 'observatorium',
    version: 'master-2020-01-28-e009b4a',
    image: 'quay.io/observatorium/observatorium:' + cfg.version,
    replicas: 3,
    uiEndpoint: 'http://127.0.0.1:9091/',
    readEndpoint: 'http://127.0.0.1:9091/api/v1',
    writeEndpoint: 'http://127.0.0.1:19291/api/v1/receive',
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

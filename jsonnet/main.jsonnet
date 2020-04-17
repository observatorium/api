local gateway = (import 'lib/observatorium-api.libsonnet') {
  config+:: {
    local cfg = self,
    name: 'observatorium-api-gateway',
    namespace: 'observatorium',
    version: 'master-2020-01-28-e009b4a',
    image: 'quay.io/observatorium/observatorium:' + cfg.version,
    replicas: 3,
    uiEndpoint: 'http://127.0.0.1:9091/',
    readEndpoint: 'http://127.0.0.1:9091/api/v1',
    writeEndpoint: 'http://127.0.0.1:19291/api/v1/receive',
  },
};

local gatewayWithTLS = gateway + gateway.withTLS {
  config+:: {
    tls+: {
      certFile: './tmp/certs/server.pem',
      privateKeyFile: './tmp/certs/ca.pem',
      clientCAFile: './tmp/certs/server.key',
    },
  },
};

{ [name]: gateway[name] for name in std.objectFields(gateway) } +
{ ['%s-with-tls' % name]: gatewayWithTLS[name] for name in std.objectFields(gateway) }

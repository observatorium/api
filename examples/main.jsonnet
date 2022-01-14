local config = {
  local cfg = self,
  name: 'observatorium-api',
  namespace: 'observatorium',
  version: 'master-2020-09-04-v0.1.1-131-ga4c5a9c',
  image: 'quay.io/observatorium/api:' + cfg.version,
  imagePullPolicy: 'IfNotPresent',
  replicas: 3,
  metrics: {
    readEndpoint: 'http://127.0.0.1:9091',
    writeEndpoint: 'http://127.0.0.1:19291',
  },
  logs: {
    readEndpoint: 'http://127.0.0.1:3100',
    tailEndpoint: 'http://127.0.0.1:3100',
    writeEndpoint: 'http://127.0.0.1:3100',
  },
  rbac: {
    roles: [
      {
        name: 'read-write',
        resources: [
          'metrics',
        ],
        tenants: [
          'telemeter',
        ],
        permissions: [
          'read',
          'write',
        ],
      },
    ],
    roleBindings: [
      {
        name: 'telemeter',
        roles: [
          'read-write',
        ],
        subjects: [
          {
            name: 'admin@example.com',
            kind: 'user',
          },
        ],
      },
    ],
  },
  tenants: {
    tenants: [
      {
        name: 'telemeter',
        id: 'FB870BF3-9F3A-44FF-9BF7-D7A047A52F43',
        oidc: {
          clientID: 'telemeter',
          clientSecret: 'ov7zikeipai4neih7Chahcae',
          issuerURL: 'http://127.0.0.1:5556/dex',
          redirectURL: 'http://localhost:8080/oidc/telemeter/callback',
          usernameClaim: 'email',
        },
      },
    ],
  },
};
local api = (import '../jsonnet/lib/observatorium-api.libsonnet')(config);

local apiWithTLS = (import '../jsonnet/lib/observatorium-api.libsonnet')(config {
  tls: {
    certKey: 'cert',
    keyKey: 'key',
    secretName: 'observatorium-api-tls',
    configMapName: 'observatorium-api-tls',
    caKey: 'ca',
    reloadInterval: '1m',
    serverName: 'example.com',
  },
});

{
  [name]: api[name]
  for name in std.objectFields(api)
  if api[name] != null
} +
{
  ['%s-with-tls' % name]: apiWithTLS[name]
  for name in std.objectFields(api)
  if apiWithTLS[name] != null
}

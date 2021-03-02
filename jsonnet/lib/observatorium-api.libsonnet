// These are the defaults for this components configuration.
// When calling the function to generate the component's manifest,
// you can pass an object structured like the default to overwrite default values.
local defaults = {
  local defaults = self,
  name: error 'must provide name',
  namespace: error 'must provide namespace',
  version: error 'must provide version',
  image: error 'must provide image',
  replicas: error 'must provide replicas',
  metrics: {
    readEnpoint: error 'must provide metrics readEnpoint',
    writeEndpoint: error 'must provide metrics writeEndpoint',
  },
  ports: {
    public: 8080,
    internal: 8081,
  },
  resources: {},
  serviceMonitor: false,
  logs: {},
  rbac: {},
  tenants: {},
  tls: {},
  rateLimiter: {},
  internal: {},

  commonLabels:: {
    'app.kubernetes.io/name': 'observatorium-api',
    'app.kubernetes.io/instance': defaults.name,
    'app.kubernetes.io/version': defaults.version,
    'app.kubernetes.io/component': 'api',
  },

  podLabelSelector:: {
    [labelName]: defaults.commonLabels[labelName]
    for labelName in std.objectFields(defaults.commonLabels)
    if !std.setMember(labelName, ['app.kubernetes.io/version'])
  },
};

function(params) {
  local api = self,

  // Combine the defaults and the passed params to make the component's config.
  config:: defaults + params,
  // Safety checks for combined config of defaults and params
  assert std.isNumber(api.config.replicas) && api.config.replicas >= 0 : 'observatorium api replicas has to be number >= 0',
  assert std.isObject(api.config.resources),
  assert std.isBoolean(api.config.serviceMonitor),

  serviceAccount: {
    apiVersion: 'v1',
    kind: 'ServiceAccount',
    metadata: {
      name: api.config.name,
      namespace: api.config.namespace,
      labels: api.config.commonLabels,
    },
  },

  service: {
    apiVersion: 'v1',
    kind: 'Service',
    metadata: {
      name: api.config.name,
      namespace: api.config.namespace,
      labels: api.config.commonLabels,
    },
    spec: {
      selector: api.config.podLabelSelector,
      ports: [
        {
          name: name,
          port: api.config.ports[name],
          targetPort: api.config.ports[name],
        }
        for name in std.objectFields(api.config.ports)
      ],
    },
  },

  deployment: {
    apiVersion: 'apps/v1',
    kind: 'Deployment',
    metadata: {
      name: api.config.name,
      namespace: api.config.namespace,
      labels: api.config.commonLabels,
    },
    spec: {
      replicas: api.config.replicas,
      selector: { matchLabels: api.config.podLabelSelector },
      strategy: {
        rollingUpdate: {
          maxSurge: 0,
          maxUnavailable: 1,
        },
      },
      template: {
        metadata: { labels: api.config.commonLabels },
        spec: {
          serviceAccountName: api.serviceAccount.metadata.name,
          containers: [
            {
              name: 'observatorium-api',
              image: api.config.image,
              args: [
                '--web.listen=0.0.0.0:%s' % api.config.ports.public,
                '--web.internal.listen=0.0.0.0:%s' % api.config.ports.internal,
                '--metrics.read.endpoint=' + api.config.metrics.readEndpoint,
                '--metrics.write.endpoint=' + api.config.metrics.writeEndpoint,
                '--log.level=warn',
              ] + (
                if api.config.logs != {} then
                  [
                    '--logs.read.endpoint=' + api.config.logs.readEndpoint,
                    '--logs.tail.endpoint=' + api.config.logs.tailEndpoint,
                    '--logs.write.endpoint=' + api.config.logs.writeEndpoint,
                  ] else []
              ) + (
                if api.config.rbac != {} then ['--rbac.config=/etc/observatorium/rbac.yaml'] else []
              ) + (
                if api.config.tenants != {} then ['--tenants.config=/etc/observatorium/tenants.yaml'] else []
              ) + (
                if api.config.tls != {} then
                  [
                    '--web.healthchecks.url=https://127.0.0.1:%s' % api.config.ports.public,
                    '--tls.server.cert-file=/var/run/tls/' + api.config.tls.certKey,
                    '--tls.server.key-file=/var/run/tls/' + api.config.tls.keyKey,
                  ] + (
                    if std.objectHas(api.config.tls, 'caKey') then [
                      '--tls.healthchecks.server-ca-file=/var/run/tls/' + api.config.tls.caKey,
                    ]
                    else []
                  ) + (
                    if std.objectHas(api.config.tls, 'reloadInterval') then
                      [
                        '--tls.reload-interval=' + api.config.tls.reloadInterval,
                      ]
                    else []
                  ) + (
                    if std.objectHas(api.config.tls, 'serverName') then
                      [
                        '--tls.healthchecks.server-name=' + api.config.tls.serverName,
                      ]
                    else []
                  )
                else []
              ) + (
                if std.objectHas(api.config.rateLimiter, 'grpcAddress') then
                  ['--middleware.rate-limiter.grpc-address=' + api.config.rateLimiter.grpcAddress]
                else []
              ) + (
                if std.objectHas(api.config.internal, 'tracing') then
                  [] + (
                    if std.objectHas(api.config.internal.tracing, 'endpoint') then
                      [
                        '--internal.tracing.endpoint=' + api.config.internal.tracing.endpoint,
                      ]
                    else []
                  ) + (
                    if std.objectHas(api.config.internal.tracing, 'samplingFraction') then
                      [
                        '--internal.tracing.sampling-fraction=' + api.config.internal.tracing.samplingFraction,
                      ]
                    else []
                  ) + (
                    if std.objectHas(api.config.internal.tracing, 'serviceName') then
                      [
                        '--internal.tracing.service-name=' + api.config.internal.tracing.serviceName,
                      ]
                    else []
                  )
                else []
              ),
              ports: [
                { name: name, containerPort: api.config.ports[name] }
                for name in std.objectFields(api.config.ports)
              ],
              resources: if api.config.resources != {} then api.config.resources else {},
              livenessProbe: {
                failureThreshold: 10,
                periodSeconds: 30,
                httpGet: {
                  path: '/live',
                  port: api.config.ports.internal,
                  scheme: 'HTTP',
                },
              },
              readinessProbe: {
                failureThreshold: 12,
                periodSeconds: 5,
                httpGet: {
                  path: '/ready',
                  port: api.config.ports.internal,
                  scheme: 'HTTP',
                },
              },
              volumeMounts:
                (if std.length(api.config.rbac) != 0 then [{
                   name: 'rbac',
                   mountPath: '/etc/observatorium/rbac.yaml',
                   subPath: 'rbac.yaml',
                   readOnly: true,
                 }] else []) +
                (if std.length(api.config.tenants) != 0 then [{
                   name: 'tenants',
                   mountPath: '/etc/observatorium/tenants.yaml',
                   subPath: 'tenants.yaml',
                   readOnly: true,
                 }] else []) +
                (if std.objectHas(api.config.tenants, 'tenants') then [
                   {
                     name: tenant.name + '-mtls-%s' % (if std.objectHas(tenant.mTLS, 'configMapName') then 'configmap' else 'secret'),
                     mountPath: '/var/run/mtls/' + tenant.name + '/' + tenant.mTLS.caKey,
                     subPath: tenant.mTLS.caKey,
                     readOnly: true,
                   }
                   for tenant in api.config.tenants.tenants
                   if std.objectHas(tenant, 'mTLS')
                   if std.objectHas(tenant.mTLS, 'caKey')
                 ] else []) +
                (if std.objectHas(api.config.tenants, 'tenants') then [
                   {
                     name: tenant.name + '-tls-configmap',
                     mountPath: tenant.oidc.issuerCAPath,
                     subPath: tenant.oidc.caKey,
                     readOnly: true,
                   }
                   for tenant in api.config.tenants.tenants
                   if std.objectHas(tenant, 'oidc')
                   if std.objectHasAll(tenant.oidc, 'caKey')
                 ] else []) +
                (if api.config.tls != {} then [
                   {
                     name: 'tls-secret',
                     mountPath: '/var/run/tls/' + api.config.tls.certKey,
                     subPath: api.config.tls.certKey,
                     readOnly: true,
                   },
                   {
                     name: 'tls-secret',
                     mountPath: '/var/run/tls/' + api.config.tls.keyKey,
                     subPath: api.config.tls.keyKey,
                     readOnly: true,
                   },
                 ] + (
                   if std.objectHas(api.config.tls, 'caKey') then [
                     {
                       name: 'tls-%s' % (if std.objectHas(api.config.tls, 'configMapName') then 'configmap' else 'secret'),
                       mountPath: '/var/run/tls/' + api.config.tls.caKey,
                       subPath: api.config.tls.caKey,
                       readOnly: true,
                     },
                   ] else []
                 ) else []),
            },
          ],
          volumes:
            (if api.config.rbac != {} then [
               {
                 configMap: {
                   name: api.config.name,
                 },
                 name: 'rbac',
               },
             ] else []) +
            (if api.config.tenants != {} then [
               {
                 secret: {
                   secretName: api.config.name,
                 },
                 name: 'tenants',
               },
             ] else []) +
            (if std.objectHas(api.config.tenants, 'tenants') then [
               if std.objectHas(tenant.mTLS, 'secretName') then {
                 secret: {
                   secretName: tenant.mTLS.secretName,
                 },
                 name: tenant.name + '-mtls-secret',
               } else if std.objectHas(tenant.mTLS, 'configMapName') then {
                 configMap: {
                   name: tenant.mTLS.configMapName,
                 },
                 name: tenant.name + '-mtls-configmap',
               }
               for tenant in api.config.tenants.tenants
               if std.objectHas(tenant, 'mTLS')
             ] else []) +
            (if std.objectHas(api.config.tenants, 'tenants') then [
               {
                 configMap: {
                   name: tenant.oidc.configMapName,
                 },
                 name: tenant.name + '-tls-configmap',
               }
               for tenant in api.config.tenants.tenants
               if std.objectHas(tenant, 'oidc')
               if std.objectHasAll(tenant.oidc, 'configMapName')
             ] else []) +
            (if api.config.tls != {} then [
               {
                 secret: {
                   secretName: api.config.tls.secretName,
                 },
                 name: 'tls-secret',
               },
             ] + (
               if std.objectHas(api.config.tls, 'configMapName') then [
                 {
                   configMap: {
                     name: api.config.tls.configMapName,
                   },
                   name: 'tls-configmap',
                 },
               ] else []
             ) else []),
        },
      },
    },
  },

  configmap: if std.length(api.config.rbac) != 0 then {
    apiVersion: 'v1',
    kind: 'ConfigMap',
    metadata: {
      labels: api.config.commonLabels,
      name: api.config.name,
      namespace: api.config.namespace,
    },
    data: {
      'rbac.yaml': std.manifestYamlDoc(api.config.rbac),
    },
  } else null,

  secret: if api.config.tenants != {} then {
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: {
      labels: api.config.commonLabels,
      name: api.config.name,
      namespace: api.config.namespace,
    },

    local tenants = {
      tenants: [
        {
          id: tenant.id,
          name: tenant.name,
          mTLS: {
            caPath: '/var/run/mtls/' + tenant.name + '/' + tenant.mTLS.caKey,
          },
        }
        for tenant in api.config.tenants.tenants
        if std.objectHas(tenant, 'mTLS')
      ] + [
        tenant
        for tenant in api.config.tenants.tenants
        if std.objectHas(tenant, 'oidc')
      ],
    },
    stringData: {
      'tenants.yaml': std.manifestYamlDoc(tenants),
    },
  } else null,


  serviceMonitor: if api.config.serviceMonitor == true then {
    apiVersion: 'monitoring.coreos.com/v1',
    kind: 'ServiceMonitor',
    metadata+: {
      name: api.config.name,
      namespace: api.config.namespace,
    },
    spec: {
      selector: {
        matchLabels: api.config.commonLabels,
      },
      endpoints: [{ port: 'internal' }],
    },
  },
}

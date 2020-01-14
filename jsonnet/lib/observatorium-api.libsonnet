local k = import 'ksonnet/ksonnet.beta.4/k.libsonnet';

{
  observatorium+:: {
    namespace:: error 'must set namespace',

    api+: {
      local api = self,

      name:: 'observatorium-api',
      namespace:: $.observatorium.namespace,
      image:: 'quay.io/observatorium/observatorium:latest',
      replicas:: 3,
      labels+:: {
        'app.kubernetes.io/name': api.name,
      },

      service+:
        local service = k.core.v1.service;
        local ports = service.mixin.spec.portsType;

        service.new(api.name, api.labels, [
          ports.newNamed('http', 8080, 8080),
        ]),

      deployment:
        local deployment = k.apps.v1.deployment;
        local container = deployment.mixin.spec.template.spec.containersType;
        local containerPort = container.portsType;
        local env = container.envType;
        local mount = container.volumeMountsType;
        local volume = k.apps.v1.statefulSet.mixin.spec.template.spec.volumesType;

        local c =
          container.new($.observatorium.api.deployment.metadata.name, $.observatorium.api.image) +
          container.withArgs([
            '--web.listen=0.0.0.0:8080',
            '--metrics.ui.endpoint=http://127.0.0.1:9091/',
            '--metrics.query.endpoint=http://127.0.0.1:9091/api/v1/query',
            '--metrics.write.endpoint=http://127.0.0.1:19291/api/v1/receive',
            '--log.level=warn',
          ]) +
          container.withPorts(
            [
              containerPort.newNamed(8080, 'http'),
            ],
          ) +
          container.mixin.readinessProbe.withFailureThreshold(3) +
          container.mixin.readinessProbe.withPeriodSeconds(30) +
          container.mixin.readinessProbe.withInitialDelaySeconds(10) +
          container.mixin.readinessProbe.httpGet.withPath('/-/ready').withPort(8080).withScheme('HTTP') +
          container.mixin.livenessProbe.withPeriodSeconds(30) +
          container.mixin.livenessProbe.withFailureThreshold(4) +
          container.mixin.livenessProbe.httpGet.withPath('/-/healthy').withPort(8080).withScheme('HTTP') +
          container.mixin.resources.withRequests({ cpu: '1', memory: '256Mi' }) +
          container.mixin.resources.withLimits({ cpu: '2', memory: '1Gi' });

        deployment.new($.observatorium.api.name, $.observatorium.api.replicas, c, $.observatorium.api.deployment.metadata.labels) +
        deployment.mixin.metadata.withNamespace($.observatorium.api.namespace) +
        deployment.mixin.metadata.withLabels({ 'app.kubernetes.io/name': $.observatorium.api.deployment.metadata.name }) +
        deployment.mixin.spec.selector.withMatchLabels($.observatorium.api.deployment.metadata.labels) +
        deployment.mixin.spec.strategy.rollingUpdate.withMaxSurge(0) +
        deployment.mixin.spec.strategy.rollingUpdate.withMaxUnavailable(1),
    },
  },
}

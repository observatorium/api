local sloError = import 'slo-libsonnet/error-burn.libsonnet';
local sloLatency = import 'slo-libsonnet/latency-burn.libsonnet';

{
  local metricLatency = 'http_request_duration_seconds',
  local metricError = 'http_requests_total',

  local writeSLO = {
    selectors: ['handler="write"'],
  },

  local querySLO = {
    selectors: ['handler="query"'],
  },

  local queryRangeSLO = {
    selectors: ['handler="query"'],
  },

  local burn = [
    sloLatency.latencyburn(writeSLO { metric: metricLatency, latencyTarget: '1', latencyBudget: 1 - 0.99 }),
    sloLatency.latencyburn(writeSLO { metric: metricLatency, latencyTarget: '0.2', latencyBudget: 1 - 0.95 }),
    sloError.errorburn(writeSLO { metric: metricError, errorBudget: 1 - 0.99 }),

    sloLatency.latencyburn(querySLO { metric: metricLatency, latencyTarget: '2.5', latencyBudget: 1 - 0.99 }),
    sloLatency.latencyburn(querySLO { metric: metricLatency, latencyTarget: '1', latencyBudget: 1 - 0.95 }),
    sloError.errorburn(querySLO { metric: metricError, errorBudget: 1 - 0.95 }),

    sloLatency.latencyburn(queryRangeSLO { metric: metricLatency, latencyTarget: '1', latencyBudget: 1 - 0.90 }),
    sloLatency.latencyburn(queryRangeSLO { metric: metricLatency, latencyTarget: '5', latencyBudget: 1 - 0.95 }),
    sloError.errorburn(queryRangeSLO { metric: metricError, errorBudget: 1 - 0.90 }),
  ],

  prometheusAlerts+:: {
    recordingrule: [
      l.recordingrules
      for l in burn
    ],
    alerts: [
      l.alerts
      for l in burn
    ],
  },
}

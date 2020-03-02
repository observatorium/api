local latency = import 'slo-libsonnet/latency-burn.libsonnet';

{
  local write = latency.burn({
    metric: 'http_request_duration_seconds',
    selectors: ['handler="write"'],
    # How much responce delay is too much.
    latencyTarget: "1",
    # The 30 days SLO promise.
    # When the promise is 99% that means that
    # in 30d can only have 1% queries above the latencyTarget.
    latencyBudget: 1-0.99,
  }),

  prometheusAlerts+:: {
    // The actual output results.
    recordingrule: write.recordingrules,
    alerts: write.alerts,
  }
}

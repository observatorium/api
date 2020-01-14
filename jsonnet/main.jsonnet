local app = (import 'lib/observatorium-api.libsonnet') {
  observatorium+:: {
    namespace:: 'observatorium',
  },
};

{ [name]: app.observatorium.api[name] for name in std.objectFields(app.observatorium.api) }

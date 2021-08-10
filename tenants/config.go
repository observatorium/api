package tenants

import "net/url"

type MetricsConfig struct {
	ReadEndpoint  *url.URL
	WriteEndpoint *url.URL
	TenantHeader  string
	TenantLabel   string
}

type LogsConfig struct {
	ReadEndpoint  *url.URL
	WriteEndpoint *url.URL
	TailEndpoint  *url.URL
	TenantHeader  string
	// enable logs at least one {read,write,tail}Endpoint} is provided.
	Enabled bool
}

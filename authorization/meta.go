package authorization

import (
	"strings"
)

var (
	metaAbsolutePaths = map[string]bool{
		"/loki/api/v1/label":  true,
		"/loki/api/v1/labels": true,
		"/loki/api/v1/series": true,
		"/api/prom/label":     true,
		"/api/prom/series":    true,
	}

	metaPathLabelValuesNewPrefix = "/loki/api/v1/label/"
	metaPathLabelValuesOldPrefix = "/api/prom/label/"
	metaPathLabelValuesSuffix    = "/values"
)

func isMetadataRequest(path string) bool {
	if absolutePath := metaAbsolutePaths[path]; absolutePath {
		return true
	}

	if (strings.HasPrefix(path, metaPathLabelValuesOldPrefix) || strings.HasPrefix(path, metaPathLabelValuesNewPrefix)) &&
		strings.HasSuffix(path, metaPathLabelValuesSuffix) {
		return true
	}

	return false
}

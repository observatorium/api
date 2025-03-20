package authorization

import (
	"fmt"
	"net/url"
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

func extractMatchersSelectors(selectorNames map[string]bool, values url.Values) (*SelectorsInfo, error) {
	match := values.Get("match")
	fmt.Printf("extractMatchersSelectors -> match: %v\n", match)
	selectors, hasWildcard, err := parseLogStreamSelectors(selectorNames, match)
	if err != nil {
		return nil, fmt.Errorf("error extracting selectors from match %#q: %w", match, err)
	}

	return &SelectorsInfo{
		Selectors:   selectors,
		HasWildcard: hasWildcard,
	}, nil
}

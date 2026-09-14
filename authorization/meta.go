package authorization

// SelectorsInfo contains information about selectors extracted from a query.
type SelectorsInfo struct {
	Selectors   map[string][]string
	HasWildcard bool
}

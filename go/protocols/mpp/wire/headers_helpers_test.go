package wire

import "sort"

// SortedHeaderParams renders a param map as sorted "key=value" strings for
// deterministic comparisons in tests. It is test-only and lives here rather
// than in production headers.go.
func SortedHeaderParams(params map[string]string) []string {
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+params[key])
	}
	return out
}

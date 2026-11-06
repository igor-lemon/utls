package behavior

import (
	"fmt"
	"strings"
)

// What a browser's HTTP cache keeps and how long, as Chromium's says it
// (http_cache_transaction.cc, http_response_headers.cc, measured on Chrome
// 156): cache.store_any_status keeps a response of any final status but 304
// that says it may be, where a cache of none of these keys keeps 200, 206, 301,
// 302, 307 and 308 alone; cache.validated_statuses are the statuses of a kept
// response a request is made conditional on (Chromium's ConditionalizeRequest
// does it of a 200 alone); cache.response_pragma_no_cache reads a response's
// Pragma: no-cache as its Cache-Control: no-cache, as a request's always is;
// cache.request_no_cache says what a request's no-cache asks: "validate", a
// conditional request, or "bypass", the network and no condition, its answer
// kept (LOAD_BYPASS_CACHE of kForceFetchHeaders); and a response with no
// freshness of its own is fresh for cache.heuristic_percent of the time from
// its Last-Modified to its Date when its status is one of
// cache.heuristic_statuses (and, unless cache.heuristic_with_must_revalidate,
// it does not say must-revalidate), and for ever when it is one of
// cache.implicit_fresh_statuses.

// cacheHeuristic are the keys of heuristic freshness, said together.
var cacheHeuristic = []string{"cache.heuristic_percent", "cache.heuristic_statuses", "cache.heuristic_with_must_revalidate"}

// validateCacheStatuses holds the cache's lists of statuses to final ones,
// each once, and the keys of heuristic freshness to each other.
func validateCacheStatuses(p Policy) error {
	for _, k := range []string{"cache.validated_statuses", "cache.heuristic_statuses", "cache.implicit_fresh_statuses"} {
		seen := map[uint64]bool{}
		for _, s := range p.Numbers(k) {
			if s < 200 || s > 599 || seen[s] {
				return fmt.Errorf("%s holds %d, which is not a final status said once", k, s)
			}
			seen[s] = true
		}
	}
	said := 0
	for _, k := range cacheHeuristic {
		if p.Has(k) {
			said++
		}
	}
	if said != 0 && said != len(cacheHeuristic) {
		return fmt.Errorf("heuristic freshness needs %s together", strings.Join(cacheHeuristic, ", "))
	}
	return nil
}

package behavior

import "slices"

// SendContentLength derives framing from the actual request. Profile data owns
// zero-body method selection, explicit empty uploads and the H1 identity case.
// Unknown-length streams must never acquire a fabricated numeric length.
func (p Policy) SendContentLength(method string, length int64, bodyProvided, identity bool) bool {
	if length > 0 {
		return true
	}
	if length < 0 {
		return false
	}
	if p == nil {
		p = Generic()
	}
	if bodyProvided && p.Flag("http.content_length_empty_body") {
		return true
	}
	if slices.Contains(p.Strings("http.zero_content_length_methods"), method) {
		return true
	}
	return identity && p.Flag("h1.zero_length_identity") && !slices.Contains(p.Strings("h1.zero_length_identity_excluded_methods"), method)
}

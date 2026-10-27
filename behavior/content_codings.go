package behavior

import (
	"encoding/json"
	"fmt"
	"slices"
)

// MaxContentCodings is a hard resource ceiling for an implemented decoder
// chain, independent of the browser's lower limit in its profile.
const MaxContentCodings = 64

func validateContentCodings(p Policy) error {
	if p.Has("http.ignored_content_codings") {
		ignored := p.Strings("http.ignored_content_codings")
		if len(ignored) > 1 || len(ignored) == 1 && ignored[0] != "identity" {
			return fmt.Errorf("http.ignored_content_codings only supports identity once")
		}
	}
	if p.Has("http.max_content_codings") != p.Has("http.content_coding_overflow") {
		return fmt.Errorf("http.max_content_codings and http.content_coding_overflow must be supplied together")
	}
	return nil
}

// migrationAdditions materializes data-owned choices introduced in the current
// unpublished engine. The original legacy source JSON remains immutable.
func migrationAdditions(p Policy, data []byte) Policy {
	var additions Policy
	if err := json.Unmarshal(data, &additions); err != nil {
		panic(err)
	}
	for key, value := range additions {
		p[key] = slices.Clone(value)
	}
	return p
}

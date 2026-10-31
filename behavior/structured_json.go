package behavior

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

// validateJSONChoices rejects lossy JSON representations before typed zero
// values, replacement characters or last-wins objects become policy choices.
func validateJSONChoices(raw []byte) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("policy JSON must be UTF-8")
	}
	trimmed := bytes.TrimSpace(raw)
	if !json.Valid(raw) {
		return fmt.Errorf("policy field requires one valid JSON value")
	}
	if bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf("policy JSON value must not be null")
	}
	// Typed scalar decoders already reject ambiguous values. Only containers
	// can hide nested nulls or repeated object keys; keep scalar validation cheap.
	if trimmed[0] != '[' && trimmed[0] != '{' {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := consumeJSONChoices(d); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values in policy field")
		}
		return err
	}
	return nil
}

func consumeJSONChoices(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return fmt.Errorf("policy JSON value must not be null")
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	if delimiter == '{' {
		seen := make(map[string]bool)
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return fmt.Errorf("policy JSON object requires string keys")
			}
			if seen[name] {
				return fmt.Errorf("duplicate policy JSON field %q", name)
			}
			seen[name] = true
			if err := consumeJSONChoices(d); err != nil {
				return err
			}
		}
	} else if delimiter == '[' {
		for d.More() {
			if err := consumeJSONChoices(d); err != nil {
				return err
			}
		}
	} else {
		return fmt.Errorf("unexpected policy JSON delimiter")
	}
	_, err = d.Token() // The decoder checks the matching closing delimiter.
	return err
}

func decodeSettings(raw []byte) ([]Setting, error) {
	var records []json.RawMessage
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, err
	}
	settings := make([]Setting, len(records))
	for i, record := range records {
		d := json.NewDecoder(bytes.NewReader(record))
		d.DisallowUnknownFields()
		if err := d.Decode(&settings[i]); err != nil {
			return nil, err
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(record, &fields); err != nil {
			return nil, err
		}
		for name := range fields {
			if name != "id" && name != "value" {
				return nil, fmt.Errorf("unknown field %q", name)
			}
		}
		for _, name := range []string{"id", "value"} {
			value, present := fields[name]
			if !present || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return nil, fmt.Errorf("HTTP3 setting requires non-null %s", name)
			}
		}
	}
	return settings, nil
}

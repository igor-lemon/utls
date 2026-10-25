package behavior

import (
	"encoding/json"
	"strings"
	"testing"
)

// chromeALPS is Chrome 155's ALPS for HTTP/3 (bench/h3alps, quiche at its
// DEPS revision), laid over the frozen Chromium data with 17613 kept.
const chromeALPS = `{"quic.preserve_extensions": [0, 65037, 27, 45, 51764, 10, 13, 51, 16, 43, 41, 17613],
 "quic.alps_protocols": ["h3"], "quic.close_early_application": "application",
 "h3.alps_reader": "quiche", "h3.alps_origin_frames": "abandon", "h3.alps_close_space": "transport",
 "h3.alps_close_code": 10, "h3.alps_close_frame_type": 6, "h3.alps_close_reason": "28:Error processing ALPS data: {detail}",
 "h3.alps_errors": {"data": "DATA frame forbidden", "headers": "HEADERS frame forbidden", "goaway": "GOAWAY frame forbidden",
  "max_push_id": "MAX_PUSH_ID frame forbidden", "priority_update": "PRIORITY_UPDATE frame forbidden",
  "metadata": "METADATA frame forbidden", "settings_twice": "multiple SETTINGS frames", "incomplete": "incomplete HTTP/3 frame",
  "too_large": "Frame is too large.", "setting_id": "Unable to read setting identifier.",
  "setting_value": "Unable to read setting value.", "setting_twice": "Duplicate setting identifier.",
  "goaway_id": "Unable to read GOAWAY ID.", "goaway_extra": "Superfluous data in GOAWAY frame.",
  "max_push_id_id": "Unable to read MAX_PUSH_ID push_id.", "max_push_id_extra": "Superfluous data in MAX_PUSH_ID frame.",
  "priority_update_id": "Unable to read prioritized element id.", "accept_ch_origin": "Unable to read ACCEPT_CH origin.",
  "accept_ch_value": "Unable to read ACCEPT_CH value.", "origin_origin": "Unable to read ORIGIN origin.",
  "http2_frame": "HTTP/2 frame received in a HTTP/3 connection: {type}", "cancel_push": "CANCEL_PUSH frame received.",
  "push_promise": "PUSH_PROMISE frame received."},
 "h3.peer_settings": "quiche", "h3.settings_close_space": "application", "h3.settings_close_code": 265,
 "h3.settings_errors": {"http2": "169:received HTTP/2 specific setting in HTTP/3 session: {id}",
  "boolean": "207:Received {name} with invalid value {value}",
  "capacity": "164:Server sent an SETTINGS_QPACK_MAX_TABLE_CAPACITY: {value} while current value is: {current}",
  "field_section": "164:Server sent an SETTINGS_MAX_FIELD_SECTION_SIZE: {value} which reduces current value: {current}",
  "blocked": "164:Server sent an SETTINGS_QPACK_BLOCKED_STREAMS: {value} which reduces current value: {current}",
  "omitted_field_section": "164:Server accepted 0-RTT but omitted non-default SETTINGS_MAX_FIELD_SECTION_SIZE",
  "omitted_blocked": "164:Server accepted 0-RTT but omitted non-default SETTINGS_QPACK_BLOCKED_STREAMS",
  "omitted_capacity": "164:Server accepted 0-RTT but omitted non-default SETTINGS_QPACK_MAX_TABLE_CAPACITY"},
 "h3.settings_http2": [2, 3, 4, 5], "h3.settings_boolean": [8, 51],
 "h3.settings_boolean_names": ["SETTINGS_ENABLE_CONNECT_PROTOCOL", "SETTINGS_H3_DATAGRAM"]}`

// withALPS is the frozen Chromium data with chromeALPS over it, each change
// (a key's new value, or "" to leave it out) laid over that.
func withALPS(t *testing.T, changes map[string]string) Policy {
	t.Helper()
	p := Legacy()
	var over Policy
	if err := json.Unmarshal([]byte(chromeALPS), &over); err != nil {
		t.Fatal(err)
	}
	for k, v := range over {
		p[k] = v
	}
	for k, v := range changes {
		if v == "" {
			delete(p, k)
		} else {
			p[k] = json.RawMessage(v)
		}
	}
	return p
}

func TestALPSPolicyIsTypedAndCoherent(t *testing.T) {
	if err := withALPS(t, nil).Validate(); err != nil {
		t.Fatalf("Chrome's: %v", err)
	}
	var over Policy
	if err := json.Unmarshal([]byte(chromeALPS), &over); err != nil {
		t.Fatal(err)
	}
	none := map[string]string{"quic.preserve_extensions": "[0, 65037, 27, 45, 51764, 10, 13, 51, 16, 43, 41]"}
	for k := range over {
		if k != "quic.preserve_extensions" {
			none[k] = ""
		}
	}
	errs := func(cond string, text string) map[string]string {
		var m map[string]string
		if err := json.Unmarshal(over["h3.alps_errors"], &m); err != nil {
			t.Fatal(err)
		}
		if text == "" {
			delete(m, cond)
		} else {
			m[cond] = text
		}
		b, _ := json.Marshal(m)
		return map[string]string{"h3.alps_errors": string(b)}
	}
	for _, tc := range []struct {
		name    string
		changes map[string]string
		err     string
	}{
		{"none of it", none, ""},
		{"the old codepoint", map[string]string{"quic.preserve_extensions": "[0, 16, 43, 17513]"}, ""},
		{"both codepoints", map[string]string{"quic.preserve_extensions": "[0, 16, 43, 17513, 17613]"}, "keeps both ALPS codepoints"},
		{"ALPS kept for no protocol", map[string]string{"quic.alps_protocols": ""}, "quic.alps_protocols goes with"},
		{"ALPS kept for an empty list", map[string]string{"quic.alps_protocols": "[]"}, "quic.alps_protocols goes with"},
		{"protocols with ALPS not kept", map[string]string{"quic.preserve_extensions": "[0, 16]"}, "quic.alps_protocols goes with"},
		{"a protocol ALPN does not offer", map[string]string{"quic.alps_protocols": `["h3", "h3-29"]`}, "is no protocol of quic.alpn"},
		{"a protocol twice", map[string]string{"quic.alpn": `["h3", "h3-29"]`, "quic.alps_protocols": `["h3", "h3"]`}, "said twice"},
		{"two protocols", map[string]string{"quic.alpn": `["h3", "h3-29"]`, "quic.alps_protocols": `["h3", "h3-29"]`}, ""},
		{"no reader", map[string]string{"h3.alps_reader": ""}, "h3.alps_reader goes with ALPS offered"},
		{"an unknown reader", map[string]string{"h3.alps_reader": `"boringssl"`}, "unsupported primitive"},
		{"a reader of no ALPS", map[string]string{"quic.preserve_extensions": "[0, 16]", "quic.alps_protocols": ""},
			"h3.alps_reader goes with ALPS offered"},
		{"no close code", map[string]string{"h3.alps_close_code": ""}, "h3.alps_close_code goes with h3.alps_reader"},
		{"no origin rule", map[string]string{"h3.alps_origin_frames": ""}, "h3.alps_origin_frames goes with h3.alps_reader"},
		{"ORIGIN frames read", map[string]string{"h3.alps_origin_frames": `"read"`}, ""},
		{"ORIGIN frames passed over", map[string]string{"h3.alps_origin_frames": `"skip"`}, ""},
		{"ORIGIN frames a boolean", map[string]string{"h3.alps_origin_frames": "true"}, "behavior h3.alps_origin_frames"},
		{"an application close of ALPS", map[string]string{"h3.alps_close_space": `"application"`, "h3.alps_close_frame_type": ""}, ""},
		{"an application close that says a frame", map[string]string{"h3.alps_close_space": `"application"`},
			"h3.alps_close_frame_type goes with a transport close"},
		{"a transport close that says no frame", map[string]string{"h3.alps_close_frame_type": ""},
			"h3.alps_close_frame_type goes with a transport close"},
		{"a code past QUIC's integers", map[string]string{"h3.alps_close_code": "4611686018427387904"}, "must be in"},
		{"a reason with no detail", map[string]string{"h3.alps_close_reason": `"bad ALPS"`}, ""},
		{"a reason with an unknown placeholder", map[string]string{"h3.alps_close_reason": `"{frame}: {detail}"`}, "unsupported diagnostic placeholder {frame}"},
		{"a reason of a lone brace", map[string]string{"h3.alps_close_reason": `"{detail"`}, "unsupported diagnostic placeholder"},
		{"a reason with a newline", map[string]string{"h3.alps_close_reason": `"a\nb"`}, "control byte"},
		{"a reason that is no text", map[string]string{"h3.alps_close_reason": "1"}, "cannot unmarshal"},
		{"a reason past 1024 bytes", map[string]string{"h3.alps_close_reason": `"` + strings.Repeat("a", 1025) + `"`}, "text exceeds 1024 bytes"},
		{"no text for a condition", errs("data", ""), `no template for "data"`},
		{"a text for an unknown condition", errs("unknown", "x"), `no condition "unknown"`},
		{"a detail with a placeholder its condition has not", errs("data", "{type} frame forbidden"), "unsupported diagnostic placeholder {type}"},
		{"a detail with its placeholder", errs("http2_frame", "{type}"), ""},
		{"a detail with a newline", errs("data", "a\rb"), "control byte"},
		{"a detail past 1024 bytes", errs("data", strings.Repeat("a", 1025)), "text exceeds 1024 bytes"},
		{"details that are no object", map[string]string{"h3.alps_errors": `["x"]`}, "templates are an object of texts"},
		{"details that are no JSON", map[string]string{"h3.alps_errors": `x`}, "templates are an object of texts"},
		{"a condition that is no text", map[string]string{"h3.alps_errors": `{1: "x"}`}, "invalid character"},
		{"a detail that is no text", map[string]string{"h3.alps_errors": `{"data": 1}`}, "cannot unmarshal"},
		{"a condition said twice", map[string]string{"h3.alps_errors": strings.Replace(string(over["h3.alps_errors"]),
			`"data":"DATA frame forbidden",`, `"data":"a","data":"DATA frame forbidden",`, 1)}, `"data" said twice`},
		{"details cut short", map[string]string{"h3.alps_errors": `{"data": "a"`}, "EOF"},
		{"no settings rule", map[string]string{"h3.peer_settings": "", "h3.settings_close_space": "", "h3.settings_close_code": "",
			"h3.settings_errors": "", "h3.settings_http2": "", "h3.settings_boolean": "", "h3.settings_boolean_names": ""},
			"h3.peer_settings goes with h3.alps_reader"},
		{"settings of no ALPS, as quiche takes them", map[string]string{"quic.preserve_extensions": "[0, 16]", "quic.alps_protocols": "",
			"h3.alps_reader": "", "h3.alps_origin_frames": "", "h3.alps_close_space": "", "h3.alps_close_code": "",
			"h3.alps_close_frame_type": "", "h3.alps_close_reason": "", "h3.alps_errors": ""},
			"h3.peer_settings goes with h3.alps_reader"},
		{"a settings key alone", map[string]string{"h3.settings_close_code": ""}, "h3.settings_close_code goes with h3.peer_settings"},
		{"a boolean unnamed", map[string]string{"h3.settings_boolean_names": `["SETTINGS_ENABLE_CONNECT_PROTOCOL"]`},
			"names each of h3.settings_boolean"},
		{"a boolean twice", map[string]string{"h3.settings_boolean": "[8, 8]"}, "setting 8 said twice"},
		{"a boolean that is HTTP/2's", map[string]string{"h3.settings_boolean": "[8, 4]"}, "setting 4 said twice"},
		{"an empty name", map[string]string{"h3.settings_boolean_names": `["", "SETTINGS_H3_DATAGRAM"]`}, "is no name"},
		{"a name with a brace", map[string]string{"h3.settings_boolean_names": `["{x}", "SETTINGS_H3_DATAGRAM"]`}, "is no name"},
		{"an HTTP/2 setting twice", map[string]string{"h3.settings_http2": "[2, 2]"}, "setting 2 said twice"},
		{"no boolean, no HTTP/2 setting", map[string]string{"h3.settings_http2": "[]", "h3.settings_boolean": "[]",
			"h3.settings_boolean_names": "[]"}, ""},
		{"a reading key of no reader", func() map[string]string {
			m := map[string]string{}
			for k, v := range none {
				m[k] = v
			}
			m["h3.alps_close_code"] = "10"
			return m
		}(), "h3.alps_close_code goes with h3.alps_reader"},
		{"a settings key of no settings rule", func() map[string]string {
			m := map[string]string{}
			for k, v := range none {
				m[k] = v
			}
			m["h3.settings_close_code"] = "265"
			return m
		}(), "h3.settings_close_code goes with h3.peer_settings"},
		{"more names than booleans", map[string]string{"h3.settings_boolean_names": `["A", "B", "C"]`}, "names each of h3.settings_boolean"},
		{"an unknown early close", map[string]string{"quic.close_early_application": `"silent"`}, "unsupported primitive"},
		{"the RFC's early close", map[string]string{"quic.close_early_application": `"transport"`}, ""},
	} {
		err := withALPS(t, tc.changes).Validate()
		if tc.err == "" && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.err)
		}
	}
}

func TestATemplateIsWrittenWithItsValues(t *testing.T) {
	for _, tc := range []struct {
		template string
		values   map[string]string
		want     string
		err      bool
	}{
		{"28:Error processing ALPS data: {detail}", map[string]string{"detail": "DATA frame forbidden"},
			"28:Error processing ALPS data: DATA frame forbidden", false},
		{"{a}{b}{a}", map[string]string{"a": "1", "b": "2"}, "121", false},
		{"{{literal}} {a}", map[string]string{"a": "x"}, "{literal} x", false},
		{"no holes", nil, "no holes", false},
		{"", nil, "", false},
		{"{a}", nil, "", true},
		{"{a", map[string]string{"a": "1"}, "", true},
		{"a}", nil, "", true},
		{"{}", map[string]string{"a": "1"}, "", true},
	} {
		got, err := Template(tc.template, tc.values)
		if (err != nil) != tc.err || got != tc.want {
			t.Errorf("%q with %v: %q, %v", tc.template, tc.values, got, err)
		}
	}
	p := withALPS(t, nil)
	if got := p.Templates("h3.alps_errors")["http2_frame"]; got != "HTTP/2 frame received in a HTTP/3 connection: {type}" {
		t.Errorf("the set read %q", got)
	}
	if got := p.Templates("h3.missing"); got != nil {
		t.Errorf("no set read %v", got)
	}
}

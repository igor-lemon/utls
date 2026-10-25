package behavior

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// ALPS for HTTP/3 (Chromium's, draft-vvv-tls-alps): the protocols a QUIC
// ClientHello offers it for (quic.alps_protocols, under the codepoint of the
// application_settings extension quic.preserve_extensions keeps), how the
// HTTP/3 frames a server gives in it are read (h3.alps_reader: "quiche",
// QuicSpdySession::OnAlpsData's HttpDecoder and AlpsFrameDecoder), and how
// the settings among them are taken, then those of the server's control
// stream against them (h3.peer_settings: "quiche", QuicSpdySession::
// OnSetting). Each refusal closes the connection with the code, space and
// reason a profile says.

// alpsErrors are the conditions quiche's ALPS reader refuses a server's
// ALPS for, the detail of h3.alps_close_reason each says, and their
// placeholders: a frame ALPS may not carry, a SETTINGS frame after the
// first, a frame cut short or longer than its type may be, a field of a
// frame that does not read, an HTTP/2 frame (its type), a push frame. (An
// ORIGIN frame is read, passed over or ends the connection without a word,
// as h3.alps_origin_frames says: Chrome 155's network service crashes on
// one, NOTREACHED in AlpsFrameDecoder::OnOriginFrameStart.)
var alpsErrors = map[string][]string{
	"data": nil, "headers": nil, "goaway": nil, "max_push_id": nil, "priority_update": nil, "metadata": nil,
	"settings_twice": nil, "incomplete": nil, "too_large": nil,
	"setting_id": nil, "setting_value": nil, "setting_twice": nil,
	"goaway_id": nil, "goaway_extra": nil, "max_push_id_id": nil, "max_push_id_extra": nil,
	"priority_update_id": nil, "accept_ch_origin": nil, "accept_ch_value": nil, "origin_origin": nil,
	"http2_frame": {"type"}, "cancel_push": nil, "push_promise": nil,
}

// settingsErrors are the conditions under which a server's setting is
// refused, the reason each says and their placeholders: an HTTP/2 setting
// (its identifier), a setting that is a boolean said otherwise (its name
// and value), and one the control stream says otherwise than ALPS did: the
// QPACK table's capacity changed, the field section or the blocked streams
// made smaller (the value and the one it replaces), or one of the three
// not said again (QuicSpdyClientSessionBase::OnSettingsFrame).
var settingsErrors = map[string][]string{
	"http2": {"id"}, "boolean": {"name", "value"},
	"capacity": {"value", "current"}, "field_section": {"value", "current"}, "blocked": {"value", "current"},
	"omitted_field_section": nil, "omitted_blocked": nil, "omitted_capacity": nil,
}

// alpsReading are the keys that say how a server's ALPS is read and
// refused; settingsTaking those that say how its settings are taken.
var alpsReading = []string{"h3.alps_origin_frames", "h3.alps_close_space", "h3.alps_close_code", "h3.alps_close_reason", "h3.alps_errors"}
var settingsTaking = []string{"h3.settings_close_space", "h3.settings_close_code", "h3.settings_errors",
	"h3.settings_http2", "h3.settings_boolean", "h3.settings_boolean_names"}

// validTemplates holds a template, or a set of them, to the placeholders
// its spec has: a set says every condition and no other.
func validTemplates(raw json.RawMessage, s spec) error {
	var set map[string]string
	if s.kind == "template" {
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		set = map[string]string{"": v}
	} else {
		var err error
		if set, err = templatesOf(raw); err != nil {
			return err
		}
		for k := range set {
			if _, ok := s.holes[k]; !ok {
				return fmt.Errorf("no condition %q", k)
			}
		}
	}
	for k, holes := range s.holes {
		v, ok := set[k]
		if !ok {
			return fmt.Errorf("no template for %q", k)
		}
		if uint64(len(v)) > s.max {
			return fmt.Errorf("text exceeds %d bytes", s.max)
		}
		if strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("control byte in behavior text")
		}
		values := map[string]string{}
		for _, h := range holes {
			values[h] = ""
		}
		if _, err := Template(v, values); err != nil {
			return err
		}
	}
	return nil
}

// templatesOf reads a set of templates, a JSON object of texts, refusing a
// condition named twice, which decoding into a map would take the last of
// without a word.
func templatesOf(raw json.RawMessage) (map[string]string, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return nil, fmt.Errorf("templates are an object of texts")
	}
	set := map[string]string{}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return nil, err
		}
		k := t.(string) // an object's keys are its decoder's strings
		var v string
		if err := d.Decode(&v); err != nil {
			return nil, err
		}
		if _, ok := set[k]; ok {
			return nil, fmt.Errorf("%q said twice", k)
		}
		set[k] = v
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	return set, nil
}

// Template writes template with values: {name} is the value of name, {{
// and }} a brace. A placeholder values has none of is refused, and so is any
// other brace, so a profile's template is held to it before anything is sent.
func Template(template string, values map[string]string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(template); i++ {
		c := template[i]
		switch {
		case c == '{' && strings.HasPrefix(template[i:], "{{"):
			b.WriteByte('{')
			i++
		case c == '}' && strings.HasPrefix(template[i:], "}}"):
			b.WriteByte('}')
			i++
		case c == '{':
			end := strings.IndexByte(template[i:], '}')
			if end < 0 {
				return "", fmt.Errorf("unsupported diagnostic placeholder")
			}
			v, ok := values[template[i+1:i+end]]
			if !ok {
				return "", fmt.Errorf("unsupported diagnostic placeholder %s", template[i:i+end+1])
			}
			b.WriteString(v)
			i += end
		case c == '}':
			return "", fmt.Errorf("unsupported diagnostic placeholder")
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

// validateALPS holds the keys of ALPS for HTTP/3 to what the engine does: a
// QUIC hello that keeps an application_settings extension, of one codepoint,
// offers it for protocols it offers ALPN for, and says how what a server
// gives in it is read and its settings taken, every key of each said; a
// hello that keeps none says none of them. Only a transport close says a
// frame type.
func validateALPS(p Policy) error {
	preserved := p.Numbers("quic.preserve_extensions")
	offered := slices.Contains(preserved, 17513) || slices.Contains(preserved, 17613)
	if slices.Contains(preserved, 17513) && slices.Contains(preserved, 17613) {
		return fmt.Errorf("quic.preserve_extensions keeps both ALPS codepoints")
	}
	protocols := p.Strings("quic.alps_protocols")
	if offered != (len(protocols) > 0) {
		return fmt.Errorf("quic.alps_protocols goes with an application_settings extension quic.preserve_extensions keeps")
	}
	for i, proto := range protocols {
		if !slices.Contains(p.Strings("quic.alpn"), proto) || slices.Contains(protocols[:i], proto) {
			return fmt.Errorf("quic.alps_protocols: %q is no protocol of quic.alpn, or is said twice", proto)
		}
	}
	if offered != p.Has("h3.alps_reader") {
		return fmt.Errorf("h3.alps_reader goes with ALPS offered")
	}
	reading := p.Has("h3.alps_reader")
	for _, k := range alpsReading {
		if reading != p.Has(k) {
			return fmt.Errorf("%s goes with h3.alps_reader", k)
		}
	}
	if reading != p.Has("h3.peer_settings") {
		return fmt.Errorf("h3.peer_settings goes with h3.alps_reader: ALPS's settings are taken")
	}
	transport := p.Text("h3.alps_close_space") == "transport"
	if transport != p.Has("h3.alps_close_frame_type") {
		return fmt.Errorf("h3.alps_close_frame_type goes with a transport close")
	}
	taking := p.Has("h3.peer_settings")
	for _, k := range settingsTaking {
		if taking != p.Has(k) {
			return fmt.Errorf("%s goes with h3.peer_settings", k)
		}
	}
	booleans, names := p.Numbers("h3.settings_boolean"), p.Strings("h3.settings_boolean_names")
	if len(booleans) != len(names) {
		return fmt.Errorf("h3.settings_boolean_names names each of h3.settings_boolean")
	}
	for i, id := range booleans {
		if slices.Contains(booleans[:i], id) || slices.Contains(p.Numbers("h3.settings_http2"), id) {
			return fmt.Errorf("h3.settings_boolean: setting %d said twice", id)
		}
		if names[i] == "" || strings.ContainsAny(names[i], "\r\n\x00{}") {
			return fmt.Errorf("h3.settings_boolean_names: %q is no name", names[i])
		}
	}
	http2 := p.Numbers("h3.settings_http2")
	for i, id := range http2 {
		if slices.Contains(http2[:i], id) {
			return fmt.Errorf("h3.settings_http2: setting %d said twice", id)
		}
	}
	return nil
}

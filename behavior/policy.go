// Package behavior carries declarative browser policy across transport layers.
// Keys select implemented primitives; certificate validation, authenticated TLS
// state and protocol/resource bounds cannot be disabled through this data.
package behavior

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Policy is the JSON behavior section of a browser profile. Dotted keys keep
// overrides and diffs explicit; unknown keys and wrong types fail validation.
// Treat a policy as immutable after client construction. Clone at ownership boundaries.
type Policy map[string]json.RawMessage
type Setting struct {
	ID    uint64 `json:"id"`
	Value uint64 `json:"value"`
}
type spec struct {
	kind     string
	min, max uint64
	choices  []string
}

var supported = map[string]spec{
	"h2.read_loop_start":                           {kind: "text", choices: []string{"connection", "first-headers"}},
	"h3.grease_payload_lengths":                    {kind: "numbers"},
	"h3.control_order":                             {kind: "texts"},
	"h3.priority_updates":                          {kind: "text", choices: []string{"initial", "per-request", "disabled"}},
	"h3.priority_source":                           {kind: "text", choices: []string{"profile", "header"}},
	"h3.qpack.error_invalid_relative_index_reason": {kind: "qpack-reason-stream", max: 1024},
	"h3.qpack.error_capacity_exceeded_reason":      {kind: "qpack-reason", max: 1024},
	"h3.qpack.error_zero_increment_reason":         {kind: "qpack-reason", max: 1024},
	"h3.qpack.error_decompression_reason":          {kind: "qpack-reason-stream", max: 1024},
	"h3.qpack.error_encoder_reason":                {kind: "qpack-reason", max: 1024},
	"h3.qpack.error_decoder_reason":                {kind: "qpack-reason", max: 1024},
	"h3.qpack.error_stream_unavailable_reason":     {kind: "qpack-reason", max: 1024},
	"h3.qpack.error_stream_write_reason":           {kind: "qpack-reason", max: 1024},
	"h3.qpack.error_queue_exhausted_reason":        {kind: "qpack-reason", max: 1024},
	"h3.qpack.critical_close_frame_type":           {kind: "number", max: 4294967295},
	"h3.qpack.critical_close_reason":               {kind: "text", max: 1024},
	"h3.qpack.draining_percent":                    {kind: "number", max: 100},
	"h3.qpack.critical_close_space":                {kind: "text", choices: []string{"application", "transport"}},
	"h3.qpack.critical_close_code":                 {kind: "number", max: 4294967295},
	"h3.retry_unprocessed_attempts":                {kind: "number", min: 1, max: 16},
	"h3.retry_attempts":                            {kind: "number", min: 1, max: 16},
	"h3.retry_methods":                             {kind: "texts"},
	"h3.retry_application_errors":                  {kind: "numbers", max: 4294967295},
	"h3.retry_transport_errors":                    {kind: "numbers", max: 4294967295},
	"h3.qpack.encoder_table_bytes":                 {kind: "number", max: 1 << 20},
	"h3.qpack.encoder_warmup_sections":             {kind: "number", max: 1024},
	"h3.qpack.reference_base":                      {kind: "text", choices: []string{"required", "insert-count"}},
	"h3.qpack.stream_order":                        {kind: "numbers", max: 3},
	"h3.qpack.encoder_strategy":                    {kind: "text", choices: []string{"disabled", "reuse", "insert"}},
	"h3.qpack.decoder_feedback":                    {kind: "text", choices: []string{"on-insert", "on-section"}},
	"h3.qpack.never_index":                         {kind: "texts"},
	"h3.qpack.streams":                             {kind: "text", choices: []string{"eager", "lazy", "deferred"}},
	"h3.qpack.huffman_names":                       {kind: "text", max: 32, choices: []string{"always", "shorter", "never"}},
	"h3.qpack.huffman_values":                      {kind: "text", max: 32, choices: []string{"always", "shorter", "never"}},
	"headers.form_cache_control":                   {kind: "text", max: 1<<32 - 1},
	"headers.range_cache_control":                  {kind: "text", max: 1<<32 - 1},
	"headers.range_accept_encoding":                {kind: "text", max: 1<<32 - 1},
	"headers.navigation_fetch_user":                {kind: "text", max: 1<<32 - 1},
	"headers.storage_access":                       {kind: "text", max: 1<<32 - 1},
	"headers.cookie_after":                         {kind: "text", max: 1<<32 - 1},
	"headers.redirected_hints_after":               {kind: "text", max: 1<<32 - 1},
	"headers.h1_connection_default":                {kind: "text", max: 1<<32 - 1},
	"http.idle_connection_timeout_ms":              {kind: "number", max: 1<<32 - 1},
	"http.negotiate_auth":                          {kind: "boolean"},
	"http.digest_cnonce_bytes":                     {kind: "number", min: 1, max: 64},
	"http.digest_algorithms":                       {kind: "texts"},
	"headers.accept_preflight":                     {kind: "text"},
	"h2.alps_settings":                             {kind: "numbers"},
	"tls.unsolicited_extension_alert":              {kind: "number", max: 255, choices: nil},
	"tls.duplicate_extension_alert":                {kind: "number", max: 255, choices: nil},
	"tls.malformed_extension_alert":                {kind: "number", max: 255, choices: nil},
	"tls.resumption":                               {kind: "boolean", max: 255, choices: nil},
	"tls.trust_anchor_order":                       {kind: "text", max: 255, choices: []string{"legacy-auto", "captured", "sorted", "process-shuffle"}},
	"h2.window_update_denominator":                 {kind: "number", max: 255, choices: nil},
	"h3.body_copy_bytes":                           {kind: "number", min: 1, max: 1 << 24},
	"url.blocked_ports":                            {kind: "numbers", max: 1<<62 - 1},
	"h3.grease_setting_n_min":                      {kind: "number", max: 1<<62 - 1},
	"h3.grease_setting_n_max":                      {kind: "number", max: 1<<62 - 1},
	"h3.grease_setting_nonzero":                    {kind: "boolean", max: 1<<62 - 1},
	"h3.grease_frame_n_bits":                       {kind: "number", max: 1<<62 - 1},
	"h3.priority_value":                            {kind: "text", max: 1<<62 - 1},
	"headers.browser_base_fields":                  {kind: "texts", max: 1<<62 - 1},
	"headers.untrusted_prefixes":                   {kind: "texts", max: 1<<62 - 1},
	"tls.ech_payload_lengths":                      {kind: "numbers"},
	"tls.single_use_tickets":                       {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"tls.ticket_age_quantum_ms":                    {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"tls.defer_key_update":                         {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"tls.validate_encrypted_extensions":            {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"tls.preserve_sni_trailing_dot":                {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"tls.alpn_mismatch_alert":                      {kind: "number", min: 1, max: 255, choices: []string{}},
	"tls.certificate_decode_alert":                 {kind: "number", min: 1, max: 255, choices: []string{}},
	"tls.retry_local_alerts":                       {kind: "numbers", min: 0, max: 4294967295, choices: []string{}},
	"tls.handshake_retries":                        {kind: "number", min: 0, max: 8, choices: []string{}},
	"tls.false_start":                              {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"tls.full_size_records":                        {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"h1.merged_head_body_bytes":                    {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"h1.response_header_bytes":                     {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"h1.max_connections":                           {kind: "number", min: 1, max: 2147483647, choices: []string{}},
	"h1.max_idle_connections":                      {kind: "number", min: 1, max: 2147483647, choices: []string{}},
	"h1.missing_status":                            {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"h1.preserve_framing_fields":                   {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"h2.encoder_table_bytes":                       {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"h2.header_frame_payload":                      {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"h2.data_frame_payload":                        {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"h2.window_update_delay_ms":                    {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"h2.strict_max_streams":                        {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"h2.enforce_advertised_frame_limit":            {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"h2.allow_huffman_expansion":                   {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"h2.zero_window_stream_error":                  {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"h2.connection_window_overflow_error":          {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"h2.tolerated_response_fields":                 {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"h2.reset_data_before_headers":                 {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"h2.reject_unsolicited_ping_ack":               {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"h2.hpack_unindexed_prefixes":                  {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"h2.hpack_indexed_exceptions":                  {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"h2.hpack_first_static_name":                   {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"h2.hpack_index_oversized":                     {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"quic.enabled":                                 {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"quic.dedicated_socket":                        {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"quic.source_cid_bytes":                        {kind: "number", min: 0, max: 20, choices: []string{}},
	"quic.initial_dcid_bytes":                      {kind: "number", min: 0, max: 20, choices: []string{}},
	"quic.versions":                                {kind: "numbers", min: 0, max: 4294967295, choices: []string{}},
	"quic.version_information":                     {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"quic.grease_version":                          {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"quic.accept_zero_available_version":           {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"quic.version_parse_error":                     {kind: "number", min: 1, max: 1073741824, choices: []string{}},
	"quic.version_mismatch_error":                  {kind: "number", min: 1, max: 1073741824, choices: []string{}},
	"quic.ignore_vn_wrong_cids":                    {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"quic.ignore_vn_after_retry":                   {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"quic.max_udp_payload":                         {kind: "number", min: 1200, max: 1472, choices: []string{}},
	"quic.max_datagram_frame":                      {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"quic.max_ack_delay_ms":                        {kind: "number", min: 1, max: 16383, choices: []string{}},
	"quic.ack_timer_ms":                            {kind: "number", min: 1, max: 16383, choices: []string{}},
	"quic.active_cid_limit":                        {kind: "number", min: 2, max: 8, choices: []string{}},
	"quic.grease_parameter_id_bits":                {kind: "number", min: 8, max: 62, choices: []string{}},
	"quic.shuffle_parameters":                      {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"quic.stream_receive_window":                   {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"quic.connection_receive_window":               {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"quic.incoming_bidi_streams":                   {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"quic.incoming_uni_streams":                    {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"quic.idle_timeout_ms":                         {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"quic.initial_packet_bytes":                    {kind: "number", min: 1200, max: 1452, choices: []string{}},
	"quic.datagrams":                               {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"quic.tls_cipher_suites":                       {kind: "numbers", min: 0, max: 4294967295, choices: []string{}},
	"quic.tls_signature_algorithms":                {kind: "numbers", min: 0, max: 4294967295, choices: []string{}},
	"quic.tls_versions":                            {kind: "numbers", min: 0, max: 4294967295, choices: []string{}},
	"quic.alpn":                                    {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"quic.preserve_extensions":                     {kind: "numbers", min: 0, max: 4294967295, choices: []string{}},
	"quic.remove_grease_groups":                    {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"quic.shuffle_extensions":                      {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"h3.settings":                                  {kind: "settings", min: 0, max: 4294967295, choices: []string{}},
	"h3.priority_frame_type":                       {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"h3.pseudo_header_order":                       {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"h3.grease_settings":                           {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"h3.grease_frames":                             {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"headers.browser_context":                      {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"headers.cookie_slot":                          {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"headers.withhold_untrusted":                   {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"headers.untrusted_drop_codings":               {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"headers.priority_fetch":                       {kind: "text", min: 0, max: 4294967295, choices: []string{}},
	"headers.accept_fetch":                         {kind: "text", min: 0, max: 4294967295, choices: []string{}},
	"headers.h1_generated_priority":                {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"headers.renderer_order":                       {kind: "text", min: 0, max: 4294967295, choices: []string{"utf16-rapidhash-quadratic-v1", "sorted", "insertion"}},
	"headers.renderer_initial_buckets":             {kind: "number", min: 1, max: 2147483647, choices: []string{}},
	"headers.renderer_load_denominator":            {kind: "number", min: 1, max: 2147483647, choices: []string{}},
	"headers.renderer_extra_fields":                {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"headers.script_leading":                       {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"headers.script_metadata":                      {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"headers.script_trailing":                      {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"headers.authorization_leading":                {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"headers.default_referrer_policy":              {kind: "text", min: 0, max: 4294967295, choices: []string{}},
	"headers.h1_prefix":                            {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"headers.alps_after":                           {kind: "text", min: 0, max: 4294967295, choices: []string{}},
	"proxy.forward_http":                           {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"proxy.profile_tls":                            {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"proxy.connect_header_order":                   {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"proxy.connection_value":                       {kind: "text", min: 0, max: 4294967295, choices: []string{}},
	"proxy.connect_pseudo_order":                   {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"proxy.connect_priority_weight":                {kind: "number", min: 0, max: 255, choices: []string{}},
	"proxy.connect_priority_exclusive":             {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"proxy.idle_timeout_ms":                        {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"proxy.tls_cache_entries":                      {kind: "number", min: 1, max: 2147483647, choices: []string{}},
	"headers.script_priority_weight":               {kind: "number", min: 0, max: 255, choices: []string{}},
	"headers.script_priority_exclusive":            {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"http.redirects_navigation":                    {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"http.redirects_fetch":                         {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"http.max_auth_restarts":                       {kind: "number", min: 1, max: 2147483647, choices: []string{}},
	"http.auth_cache_entries":                      {kind: "number", min: 1, max: 2147483647, choices: []string{}},
	"http.auth_cache_paths":                        {kind: "number", min: 1, max: 2147483647, choices: []string{}},
	"http.auth_scheme_order":                       {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"http.preflight_default_age_seconds":           {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"http.preflight_max_age_seconds":               {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"http.max_site_pools":                          {kind: "number", min: 1, max: 2147483647, choices: []string{}},
	"http.body_read_bytes":                         {kind: "number", min: 1, max: 2147483647, choices: []string{}},
	"http.zstd_window_bytes":                       {kind: "number", min: 1, max: 2147483647, choices: []string{}},
	"http.content_codings":                         {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"http.gzip_decoder":                            {kind: "text", min: 0, max: 4294967295, choices: []string{"prefix-first-member", "rfc1952"}},
	"cookie.raw_fields":                            {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"cookie.ip_domain_host_only":                   {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"cookie.reset_order_on_value_change":           {kind: "boolean", min: 0, max: 4294967295, choices: []string{}},
	"cookie.max_age_seconds":                       {kind: "number", min: 1, max: 2147483647, choices: []string{}},
	"cookie.max_pair_bytes":                        {kind: "number", min: 1, max: 2147483647, choices: []string{}},
	"cookie.max_attribute_bytes":                   {kind: "number", min: 1, max: 2147483647, choices: []string{}},
	"cookie.lax_unsafe_age_seconds":                {kind: "number", min: 0, max: 4294967295, choices: []string{}},
	"cache.entry_bytes":                            {kind: "number", min: 1, max: 2147483647, choices: []string{}},
	"cache.total_bytes":                            {kind: "number", min: 1, max: 2147483647, choices: []string{}},
	"cache.entries":                                {kind: "number", min: 1, max: 2147483647, choices: []string{}},
	"headers.client_hint_order":                    {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"headers.default_client_hints":                 {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"headers.renderer_hint_insertion_order":        {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"headers.renderer_default_hints":               {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"headers.preflight_order":                      {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"headers.navigation_order":                     {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"headers.form_order":                           {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"headers.restarted_order":                      {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"headers.redirected_order":                     {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
}

//go:embed legacy-chromium.json
var legacyJSON []byte
var legacy = func() Policy {
	var p Policy
	if err := json.Unmarshal(legacyJSON, &p); err != nil {
		panic(err)
	}
	if err := p.Validate(); err != nil {
		panic(err)
	}
	return p
}()

// Legacy is a materialized migration policy for schema 0-2 and deprecated APIs.
// New profile schemas carry their own complete policy and never infer this from a name.
func Legacy() Policy { return legacy.Clone() }

// Resolve supports old backend callers. A non-nil policy, including {}, is authoritative.
func Resolve(p Policy, old bool) Policy {
	if p != nil {
		return p
	}
	if old {
		return legacy
	}
	return nil
}
func (p Policy) Clone() Policy {
	if p == nil {
		return nil
	}
	out := make(Policy, len(p))
	for k, v := range p {
		out[k] = bytes.Clone(v)
	}
	return out
}
func (p Policy) Has(k string) bool           { _, ok := p[k]; return ok }
func (p Policy) Flag(k string) bool          { var v bool; _ = json.Unmarshal(p[k], &v); return v }
func (p Policy) Uint(k string) uint64        { var v uint64; _ = json.Unmarshal(p[k], &v); return v }
func (p Policy) Int(k string) int            { return int(p.Uint(k)) }
func (p Policy) Text(k string) string        { var v string; _ = json.Unmarshal(p[k], &v); return v }
func (p Policy) Strings(k string) []string   { var v []string; _ = json.Unmarshal(p[k], &v); return v }
func (p Policy) Numbers(k string) []uint64   { var v []uint64; _ = json.Unmarshal(p[k], &v); return v }
func (p Policy) Settings(k string) []Setting { var v []Setting; _ = json.Unmarshal(p[k], &v); return v }
func (p Policy) Validate() error {
	for k, raw := range p {
		s, ok := supported[k]
		if !ok {
			return fmt.Errorf("unsupported behavior field %q", k)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("behavior %s must not be null", k)
		}
		var err error
		switch s.kind {
		case "boolean":
			var v bool
			err = json.Unmarshal(raw, &v)
		case "number":
			var v uint64
			err = json.Unmarshal(raw, &v)
			if err == nil && (v < s.min || v > s.max) {
				err = fmt.Errorf("must be in [%d,%d]", s.min, s.max)
			}
		case "text", "qpack-reason", "qpack-reason-stream":
			var v string
			err = json.Unmarshal(raw, &v)
			if err == nil && s.max > 0 && uint64(len(v)) > s.max {
				err = fmt.Errorf("text exceeds %d bytes", s.max)
			}
			if err == nil && strings.ContainsAny(v, "\r\n\x00") {
				err = fmt.Errorf("control byte in behavior text")
			}
			if err == nil && strings.HasPrefix(s.kind, "qpack-reason") {
				remaining := strings.ReplaceAll(v, "{detail}", "")
				if s.kind == "qpack-reason-stream" {
					remaining = strings.ReplaceAll(remaining, "{stream_id}", "")
				}
				if strings.ContainsAny(remaining, "{}") {
					err = fmt.Errorf("unsupported diagnostic placeholder")
				}
			}
			if err == nil && len(s.choices) > 0 && !slices.Contains(s.choices, v) {
				err = fmt.Errorf("unsupported primitive %q", v)
			}
		case "texts":
			var v []string
			err = json.Unmarshal(raw, &v)
		case "numbers":
			var v []uint64
			err = json.Unmarshal(raw, &v)
			for _, n := range v {
				if n > 1<<32-1 {
					err = fmt.Errorf("integer exceeds uint32")
					break
				}
			}
		case "settings":
			var v []Setting
			d := json.NewDecoder(bytes.NewReader(raw))
			d.DisallowUnknownFields()
			err = d.Decode(&v)
			seen := map[uint64]bool{}
			for _, x := range v {
				if x.ID >= 1<<62 || x.Value >= 1<<62 || seen[x.ID] {
					err = fmt.Errorf("invalid/duplicate HTTP3 setting")
					break
				}
				seen[x.ID] = true
				if !slices.Contains([]uint64{1, 6, 7, 51}, x.ID) && !(x.ID >= 33 && (x.ID-33)%31 == 0) {
					err = fmt.Errorf("HTTP3 setting capability API is unavailable: %d", x.ID)
					break
				}
				if x.ID == 51 && x.Value > 1 {
					err = fmt.Errorf("invalid H3_DATAGRAM boolean")
					break
				}

				if (x.ID == 1 && x.Value > 1<<20) || (x.ID == 7 && x.Value > 1024) {
					err = fmt.Errorf("QPACK exceeds engine resource safety bound")
					break
				}
			}
		}
		if err != nil {
			return fmt.Errorf("behavior %s: %w", k, err)
		}
	}
	if p.Has("h3.qpack.stream_order") {
		v := p.Numbers("h3.qpack.stream_order")
		if len(v) != 2 || !((v[0] == 2 && v[1] == 3) || (v[0] == 3 && v[1] == 2)) {
			return fmt.Errorf("h3.qpack.stream_order must contain 2 and 3 once")
		}
	}
	if p.Flag("quic.enabled") {
		vs := p.Numbers("quic.versions")
		if len(vs) != 1 || vs[0] != 1 {
			return fmt.Errorf("cross-version profile negotiation API is unavailable; only QUIC v1 is supported")
		}
		if !p.Flag("quic.dedicated_socket") && p.Has("quic.source_cid_bytes") && p.Uint("quic.source_cid_bytes") == 0 {
			return fmt.Errorf("zero source CID requires a dedicated socket")
		}
		if len(p.Numbers("quic.tls_versions")) != 1 || p.Numbers("quic.tls_versions")[0] != 772 {
			return fmt.Errorf("QUIC requires TLS1.3")
		}
		if p.Uint("quic.ack_timer_ms") > p.Uint("quic.max_ack_delay_ms") {
			return fmt.Errorf("ACK timer exceeds advertised delay")
		}
	}
	if p.Has("headers.renderer_initial_buckets") {
		n := p.Uint("headers.renderer_initial_buckets")
		if n&(n-1) != 0 {
			return fmt.Errorf("renderer bucket count must be a power of two")
		}
	}
	if p.Has("cache.entry_bytes") && p.Has("cache.total_bytes") && p.Uint("cache.entry_bytes") > p.Uint("cache.total_bytes") {
		return fmt.Errorf("cache entry limit exceeds total")
	}
	for _, k := range []string{"tls.retry_local_alerts"} {
		for _, v := range p.Numbers(k) {
			if v > 255 {
				return fmt.Errorf("%s contains an invalid TLS alert", k)
			}
		}
	}
	for _, k := range []string{"quic.tls_cipher_suites", "quic.tls_signature_algorithms", "quic.preserve_extensions", "tls.ech_payload_lengths", "url.blocked_ports"} {
		for _, v := range p.Numbers(k) {
			if v > 65535 {
				return fmt.Errorf("%s contains an out-of-range identifier", k)
			}
		}
	}
	for _, id := range p.Numbers("quic.preserve_extensions") {
		if id == 17513 || id == 17613 {
			return fmt.Errorf("HTTP3 ALPS bootstrap API is unavailable")
		}
	}
	if p.Has("h3.grease_setting_n_min") && p.Uint("h3.grease_setting_n_min") > p.Uint("h3.grease_setting_n_max") {
		return fmt.Errorf("invalid GREASE setting range")
	}
	if p.Uint("h3.grease_setting_n_max") > ((1<<62-1)-33)/31 {
		return fmt.Errorf("GREASE setting identifier exceeds QUIC varint")
	}
	if p.Has("h3.grease_frame_n_bits") && (p.Uint("h3.grease_frame_n_bits") < 1 || p.Uint("h3.grease_frame_n_bits") > 56) {
		return fmt.Errorf("unsupported GREASE frame range")
	}
	if p.Has("h3.grease_payload_lengths") {
		lengths := p.Numbers("h3.grease_payload_lengths")
		if len(lengths) == 0 || len(lengths) > 256 {
			return fmt.Errorf("invalid GREASE payload length vector")
		}
		for _, n := range lengths {
			if n > 4096 {
				return fmt.Errorf("GREASE payload exceeds engine resource bound")
			}
		}
	}
	if p.Has("h3.control_order") {
		order := p.Strings("h3.control_order")
		if len(order) == 0 || order[0] != "settings" {
			return fmt.Errorf("HTTP3 control order must start with SETTINGS")
		}
		seen := map[string]bool{}
		for _, component := range order {
			if seen[component] || !slices.Contains([]string{"settings", "priority", "grease"}, component) {
				return fmt.Errorf("invalid/duplicate HTTP3 control component")
			}
			seen[component] = true
		}
		if p.Flag("h3.grease_frames") && !seen["grease"] {
			return fmt.Errorf("GREASE frame enabled but absent from control order")
		}
		if p.Text("h3.priority_updates") == "initial" && p.Uint("h3.priority_frame_type") > 0 && !seen["priority"] {
			return fmt.Errorf("initial priority missing from control order")
		}
		if p.Text("h3.priority_updates") != "initial" && seen["priority"] {
			return fmt.Errorf("initial priority requires initial mode")
		}
	}
	if p.Flag("headers.browser_context") {
		for _, key := range []string{"headers.navigation_order", "headers.form_order", "headers.redirected_order", "headers.restarted_order"} {
			v := p.Strings(key)
			if !slices.Contains(v, "accept") {
				return fmt.Errorf("%s must contain the ALPS anchor", key)
			}
		}
		if !p.Has("headers.renderer_initial_buckets") || p.Uint("headers.renderer_load_denominator") < 2 {
			return fmt.Errorf("incomplete renderer map configuration")
		}
	}
	for _, k := range []string{"tls.alpn_mismatch_alert", "tls.certificate_decode_alert", "tls.unsolicited_extension_alert", "tls.duplicate_extension_alert", "tls.malformed_extension_alert"} {
		if p.Has(k) && p.Uint(k) == 0 {
			return fmt.Errorf("TLS alert must be nonzero: %s", k)
		}
	}
	if p.Has("h1.missing_status") && (p.Uint("h1.missing_status") < 100 || p.Uint("h1.missing_status") > 999) {
		return fmt.Errorf("fallback status must be three digits")
	}
	if p.Has("headers.renderer_initial_buckets") && p.Uint("headers.renderer_initial_buckets") > 1<<20 {
		return fmt.Errorf("renderer map exceeds engine memory bound")
	}
	if p.Flag("quic.enabled") && !p.Flag("quic.dedicated_socket") {
		return fmt.Errorf("shared profile QUIC socket API is unavailable")
	}
	for _, k := range []string{"quic.stream_receive_window", "quic.connection_receive_window", "quic.initial_packet_bytes", "quic.max_udp_payload", "quic.active_cid_limit", "quic.ack_timer_ms", "quic.max_ack_delay_ms", "quic.incoming_uni_streams"} {
		if p.Flag("quic.enabled") && !p.Has(k) {
			return fmt.Errorf("enabled QUIC policy requires %s", k)
		}
	}
	for _, id := range p.Numbers("quic.tls_cipher_suites") {
		if id < 4865 || id > 4867 {
			return fmt.Errorf("unsupported QUIC cipher API: %d", id)
		}
	}
	if p.Flag("headers.browser_context") {
		anchor := p.Text("headers.alps_after")
		if anchor == "" {
			return fmt.Errorf("ALPS header anchor is missing")
		}
		for _, key := range []string{"headers.navigation_order", "headers.form_order", "headers.redirected_order", "headers.restarted_order"} {
			if !slices.Contains(p.Strings(key), anchor) {
				return fmt.Errorf("%s is missing ALPS anchor %s", key, anchor)
			}
		}
	}
	if p.Has("h2.window_update_denominator") && p.Uint("h2.window_update_denominator") < 1 {
		return fmt.Errorf("WINDOW_UPDATE denominator must be positive")
	}
	for _, coding := range p.Strings("http.content_codings") {
		if !slices.Contains([]string{"gzip", "x-gzip", "deflate", "br", "zstd"}, coding) {
			return fmt.Errorf("content coding API is unavailable: %s", coding)
		}
	}

	if p.Flag("tls.validate_encrypted_extensions") {
		for _, k := range []string{"tls.unsolicited_extension_alert", "tls.duplicate_extension_alert", "tls.malformed_extension_alert"} {
			if !p.Has(k) {
				return fmt.Errorf("extension validation requires %s", k)
			}
		}
	}
	if p.Flag("quic.enabled") {
		names := p.Strings("h3.pseudo_header_order")
		want := []string{":method", ":authority", ":scheme", ":path"}
		if len(names) != len(want) {
			return fmt.Errorf("incomplete H3 pseudo-header order")
		}
		for _, n := range want {
			count := 0
			for _, v := range names {
				if v == n {
					count++
				}
			}
			if count != 1 {
				return fmt.Errorf("H3 pseudo-header order must contain %s once", n)
			}
		}
		for _, s := range p.Settings("h3.settings") {
			if s.ID == 51 && s.Value == 1 && !p.Flag("quic.datagrams") {
				return fmt.Errorf("H3 datagrams require QUIC datagram support")
			}
		}
	}
	for _, k := range []string{"headers.priority_fetch", "headers.accept_fetch", "h3.priority_value", "proxy.connection_value"} {
		if strings.ContainsAny(p.Text(k), "\r\n\x00") {
			return fmt.Errorf("invalid HTTP field value: %s", k)
		}
	}

	for _, id := range p.Numbers("h2.alps_settings") {
		if !slices.Contains([]uint64{1, 3, 4, 8, 9}, id) {
			return fmt.Errorf("ALPS setting application API is unavailable: %d", id)
		}
	}
	for _, alg := range p.Strings("http.digest_algorithms") {
		if !slices.Contains([]string{"MD5", "MD5-sess", "SHA-256", "SHA-256-sess"}, alg) {
			return fmt.Errorf("Digest algorithm API is unavailable: %s", alg)
		}
	}
	if strings.ContainsAny(p.Text("headers.accept_preflight"), "\r\n\x00") {
		return fmt.Errorf("invalid preflight Accept value")
	}

	if len(p.Strings("http.digest_algorithms")) > 0 && !p.Has("http.digest_cnonce_bytes") {
		return fmt.Errorf("Digest algorithms require an explicit nonce length")
	}
	if p.Flag("quic.enabled") {
		if len(p.Numbers("quic.tls_cipher_suites")) == 0 || len(p.Numbers("quic.tls_signature_algorithms")) == 0 || !slices.Contains(p.Strings("quic.alpn"), "h3") {
			return fmt.Errorf("incomplete QUIC TLS vectors")
		}
		if p.Flag("h3.grease_settings") && (!p.Has("h3.grease_setting_n_min") || !p.Has("h3.grease_setting_n_max")) {
			return fmt.Errorf("GREASE settings require an explicit range")
		}
		if p.Flag("h3.grease_frames") && !p.Has("h3.grease_frame_n_bits") {
			return fmt.Errorf("GREASE frames require an explicit range")
		}
	}

	return nil
}

//go:embed legacy-generic.json
var genericJSON []byte
var generic = func() Policy {
	var p Policy
	if err := json.Unmarshal(genericJSON, &p); err != nil {
		panic(err)
	}
	return p
}()

func Generic() Policy { return generic.Clone() }

// UnmarshalJSON rejects duplicate policy keys and canonicalizes whitespace so
// cloning and saving preserve semantic identity across indentation changes.
func (p *Policy) UnmarshalJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	tok, err := d.Token()
	if err != nil {
		return err
	}
	if tok != json.Delim('{') {
		return fmt.Errorf("behavior must be an object")
	}
	out := Policy{}
	for d.More() {
		tok, err = d.Token()
		if err != nil {
			return err
		}
		key := tok.(string)
		if _, ok := out[key]; ok {
			return fmt.Errorf("duplicate behavior field %q", key)
		}
		var raw json.RawMessage
		if err = d.Decode(&raw); err != nil {
			return err
		}
		var b bytes.Buffer
		if err = json.Compact(&b, raw); err != nil {
			return err
		}
		out[key] = bytes.Clone(b.Bytes())
	}
	if _, err = d.Token(); err != nil {
		return err
	}
	*p = out
	return nil
}

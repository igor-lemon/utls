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

// unreadBody are the ways an answer a request goes on from without reading
// it is let go of: as the engine always did ("read"), at once ("close"), read
// in the background within http.drain_bytes and http.drain_ms ("drain"), read
// to its end first ("read-all"), or once the first of its bytes come, within
// http.first_bytes_ms ("first-bytes").
var unreadBody = []string{"read", "close", "drain", "read-all", "first-bytes"}

// unreadBodies are the keys that say how, each of a kind of answer and a
// protocol.
var unreadBodies = []string{"h1.dropped_body", "h2.dropped_body", "h1.auth_body", "h2.auth_body",
	"h1.restart_body", "h2.restart_body", "h1.preflight_body", "h2.preflight_body"}

// h2RetryErrors are the HTTP/2 failures that say a request was not processed,
// which h2.retry_errors may name to send it again for: a stream refused
// (RST_STREAM REFUSED_STREAM), a stream above the last a GOAWAY with NO_ERROR
// or with another code says the server took, a connection given up for its
// PING.
var h2RetryErrors = []string{"refused-stream", "goaway-no-error", "goaway-error", "ping-failed"}

// givenOrders are the orders of a page's requests in which @given stands for
// the fields a request was given that Chrome has no slot of its own for,
// where Chrome driven over DevTools writes the extra headers it is given.
var givenOrders = []string{"headers.navigation_order", "headers.form_order", "headers.redirected_order", "headers.restarted_order"}

var supported = map[string]spec{
	"http.zero_content_length_methods":             {kind: "methods"},
	"http.content_length_empty_body":               {kind: "boolean"},
	"h1.zero_length_identity":                      {kind: "boolean"},
	"h1.zero_length_identity_excluded_methods":     {kind: "methods"},
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
	"headers.reload_cache_control":                 {kind: "text", max: 1<<32 - 1},
	"headers.storage_access":                       {kind: "text", max: 1<<32 - 1},
	"headers.cookie_after":                         {kind: "text", max: 1<<32 - 1},
	"headers.redirected_hints_after":               {kind: "text", max: 1<<32 - 1},
	"headers.h1_connection_default":                {kind: "text", max: 1<<32 - 1},
	"http.idle_connection_timeout_ms":              {kind: "number", max: 1<<32 - 1},
	"h1.idle_connection_timeout_ms":                {kind: "number", max: 1<<32 - 1},
	"h1.idle_reap":                                 {kind: "text", choices: []string{"timer", "on-request"}},
	"h2.idle_connection_timeout_ms":                {kind: "number", max: 1<<32 - 1},
	"h2.close_on_goaway":                           {kind: "boolean"},
	"h2.priority_dependency":                       {kind: "text", choices: []string{"root", "nearest-weight"}},
	"h2.preface_ping_idle_ms":                      {kind: "number", max: 1<<32 - 1},
	"h2.preface_ping_first_id":                     {kind: "number", max: 1<<64 - 1},
	"h2.preface_ping_hung_ms":                      {kind: "number", max: 1<<32 - 1},
	"h2.preface_ping_failed_goaway_code":           {kind: "number", max: 1<<32 - 1},
	"h2.preface_ping_failed_goaway_debug":          {kind: "text", max: 1024},
	"h2.retries":                                   {kind: "number", max: 16},
	"h2.retry_errors":                              {kind: "texts"},
	"h2.retry_delay_ms":                            {kind: "number", max: 60000},
	"http.connection_error_retries":                {kind: "number", max: 1000},
	"http.connection_error_methods":                {kind: "text", choices: []string{"any", "idempotent"}},
	"h1.request_timeout_resend":                    {kind: "boolean"},
	"h1.dropped_body":                              {kind: "text", choices: unreadBody},
	"h2.dropped_body":                              {kind: "text", choices: unreadBody},
	"h1.auth_body":                                 {kind: "text", choices: unreadBody},
	"h2.auth_body":                                 {kind: "text", choices: unreadBody},
	"h1.restart_body":                              {kind: "text", choices: unreadBody},
	"h2.restart_body":                              {kind: "text", choices: unreadBody},
	"h1.preflight_body":                            {kind: "text", choices: unreadBody},
	"h2.preflight_body":                            {kind: "text", choices: unreadBody},
	"http.drain_bytes":                             {kind: "number", max: 1 << 30},
	"http.drain_ms":                                {kind: "number", max: 1<<32 - 1},
	"http.first_bytes_ms":                          {kind: "number", max: 1<<32 - 1},
	"h1.unread_grace_us":                           {kind: "number", max: 10_000_000},
	"h2.unread_grace_us":                           {kind: "number", max: 10_000_000},
	"tls.close_notify":                             {kind: "boolean"},
	"tcp.keepalive":                                {kind: "boolean"},
	"tcp.keepalive_idle_seconds":                   {kind: "number", max: 32767},
	"tcp.keepalive_interval_seconds":               {kind: "number", max: 32767},
	"tcp.keepalive_count":                          {kind: "number", max: 127},
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
	"tls.ech":                                      {kind: "boolean"},
	"tls.ech_inner_own":                            {kind: "numbers"},
	"tls.ech_inner_omitted":                        {kind: "numbers"},
	"tls.ech_inner_min_version":                    {kind: "number", min: 0x0301, max: 0x0304},
	"tls.ech_padding_block":                        {kind: "number", max: 255},
	"tls.ech_kems":                                 {kind: "numbers"},
	"tls.ech_kdfs":                                 {kind: "numbers"},
	"tls.ech_aeads":                                {kind: "numbers"},
	"tls.ech_chacha_without_aes":                   {kind: "boolean"},
	"tls.ech_outer_psk":                            {kind: "text", choices: []string{"none"}},
	"tls.ech_retries":                              {kind: "number", max: 8},
	"tls.ech_retry_without":                        {kind: "boolean"},
	"dns.https_records":                            {kind: "boolean"},
	"dns.https_wait_percent":                       {kind: "number", max: 100},
	"dns.https_wait_min_ms":                        {kind: "number", max: 60000},
	"dns.https_wait_max_ms":                        {kind: "number", max: 60000},
	"dns.https_upgrade":                            {kind: "boolean"},
	"dns.resolver":                                 {kind: "text", choices: []string{"system", "built-in"}},
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
	"headers.without_context":                      {kind: "text", min: 0, max: 4294967295, choices: []string{"as-given", "typed-navigation"}},
	"headers.given_order":                          {kind: "text", min: 0, max: 4294967295, choices: []string{"bytes", "as-given"}},
	"headers.given_redirect_drops":                 {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"headers.sent_priority":                        {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"headers.renderer_origin_dests":                {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
	"h2.urgency_weights":                           {kind: "numbers", min: 0, max: 4294967295, choices: []string{}},
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
	"headers.form_reload_order":                    {kind: "texts", min: 0, max: 4294967295, choices: []string{}},
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
		case "methods":
			var methods []string
			err = json.Unmarshal(raw, &methods)
			seen := map[string]bool{}
			for _, method := range methods {
				if method == "" || len(method) > 256 || seen[method] {
					err = fmt.Errorf("empty, oversized or duplicate method")
					break
				}
				seen[method] = true
				for _, c := range method {
					if c <= 32 || c >= 127 || strings.ContainsRune("()<>@,;:\"/[]?={}", c) {
						err = fmt.Errorf("invalid method token")
						break
					}
				}
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
		if p.Has("headers.form_reload_order") && !slices.Contains(p.Strings("headers.form_reload_order"), anchor) {
			return fmt.Errorf("headers.form_reload_order is missing ALPS anchor %s", anchor)
		}
	}
	// A page reloaded as Ctrl+R reloads it asks for itself afresh, says the
	// person asked (Sec-Fetch-User) and posts a form again in an order of its
	// own: the three are said together.
	if p.Has("headers.reload_cache_control") != p.Has("headers.form_reload_order") ||
		p.Has("headers.reload_cache_control") && !p.Has("headers.navigation_fetch_user") {
		return fmt.Errorf("headers.reload_cache_control, headers.form_reload_order and headers.navigation_fetch_user " +
			"are said together")
	}
	for _, k := range []string{"tcp.keepalive_idle_seconds", "tcp.keepalive_interval_seconds", "tcp.keepalive_count"} {
		if p.Has(k) && !p.Has("tcp.keepalive") {
			return fmt.Errorf("%s requires tcp.keepalive", k)
		}
		if p.Has(k) && !p.Flag("tcp.keepalive") && p.Uint(k) != 0 {
			return fmt.Errorf("%s is set while tcp.keepalive is false", k)
		}
	}
	if p.Has("h1.idle_reap") && !p.Has("h1.idle_connection_timeout_ms") {
		return fmt.Errorf("h1.idle_reap requires h1.idle_connection_timeout_ms")
	}
	// A connection's own PING (Chrome's SpdySession::MaybeSendPrefacePing and
	// CheckPingStatus): what it says and how a connection is given up are
	// said only with when it is sent.
	for _, k := range []string{"h2.preface_ping_first_id", "h2.preface_ping_hung_ms"} {
		if p.Has(k) && !p.Has("h2.preface_ping_idle_ms") {
			return fmt.Errorf("%s requires h2.preface_ping_idle_ms", k)
		}
	}
	if p.Uint("h2.preface_ping_idle_ms") != 0 && !p.Has("h2.preface_ping_first_id") {
		return fmt.Errorf("h2.preface_ping_idle_ms requires h2.preface_ping_first_id")
	}
	if p.Has("h2.preface_ping_failed_goaway_code") && !p.Has("h2.preface_ping_hung_ms") {
		return fmt.Errorf("h2.preface_ping_failed_goaway_code requires h2.preface_ping_hung_ms")
	}
	if p.Has("h2.preface_ping_failed_goaway_debug") && !p.Has("h2.preface_ping_failed_goaway_code") {
		return fmt.Errorf("h2.preface_ping_failed_goaway_debug requires h2.preface_ping_failed_goaway_code")
	}
	// A request sent again (Chrome's HttpNetworkTransaction::HandleIOError):
	// for the failures named, which say it was not processed, as many times
	// as h2.retries says, and after a lost connection as many times as
	// http.connection_error_retries says, by the methods it names; neither
	// says anything without h2.retries.
	if p.Has("h2.retries") != p.Has("h2.retry_errors") {
		return fmt.Errorf("h2.retries and h2.retry_errors go together")
	}
	if p.Has("h2.retry_delay_ms") && !p.Has("h2.retries") {
		return fmt.Errorf("h2.retry_delay_ms requires h2.retries")
	}
	seen := map[string]bool{}
	for _, e := range p.Strings("h2.retry_errors") {
		if !slices.Contains(h2RetryErrors, e) || seen[e] {
			return fmt.Errorf("h2.retry_errors: unknown or repeated failure %q", e)
		}
		seen[e] = true
	}
	if seen["ping-failed"] && !p.Has("h2.preface_ping_hung_ms") {
		return fmt.Errorf("h2.retry_errors names ping-failed while no PING is given up (h2.preface_ping_hung_ms)")
	}
	if p.Has("http.connection_error_retries") != p.Has("http.connection_error_methods") {
		return fmt.Errorf("http.connection_error_retries and http.connection_error_methods go together")
	}
	if p.Has("http.connection_error_retries") && !p.Has("h2.retries") {
		return fmt.Errorf("http.connection_error_retries requires h2.retries")
	}
	// The fields a request is given that Chrome has no slot of its own for
	// go where @given stands: where one order of a page's request names it,
	// every one does, once. How they are ordered there and what a redirect
	// takes of them are said only with it, and a request without a browser
	// context is a typed navigation only where they have a place.
	marked := 0
	for _, key := range givenOrders {
		switch n := len(slices.DeleteFunc(slices.Clone(p.Strings(key)), func(s string) bool { return s != "@given" })); {
		case n > 1:
			return fmt.Errorf("%s names @given more than once", key)
		case n == 1:
			marked++
		}
	}
	if marked != 0 && marked != len(givenOrders) {
		return fmt.Errorf("@given is in some of %s and not in all", strings.Join(givenOrders, ", "))
	}
	for _, k := range []string{"headers.given_order", "headers.given_redirect_drops"} {
		if p.Has(k) && marked == 0 {
			return fmt.Errorf("%s requires @given in %s", k, strings.Join(givenOrders, ", "))
		}
	}
	if p.Text("headers.without_context") == "typed-navigation" {
		if !p.Flag("headers.browser_context") {
			return fmt.Errorf("headers.without_context typed-navigation requires headers.browser_context")
		}
		if marked == 0 {
			return fmt.Errorf("headers.without_context typed-navigation requires @given in %s", strings.Join(givenOrders, ", "))
		}
	}
	for _, name := range p.Strings("headers.given_redirect_drops") {
		if name == "" || name != strings.ToLower(name) || strings.ContainsAny(name, " \t:@\r\n\x00") {
			return fmt.Errorf("headers.given_redirect_drops: %q is not a field name in lower case", name)
		}
	}
	// The Priority a browser's request has over HTTP/2 by what it is for
	// (Sec-Fetch-Dest), when it came without one, as over HTTP/1.1 it does,
	// and the weight of its HEADERS frame by its urgency (RFC 9218), from 0.
	if len(p.Numbers("h2.urgency_weights")) != 0 && len(p.Numbers("h2.urgency_weights")) != 8 {
		return fmt.Errorf("h2.urgency_weights says a weight for each urgency, 0 to 7")
	}
	for _, w := range p.Numbers("h2.urgency_weights") {
		if w > 255 {
			return fmt.Errorf("h2.urgency_weights: %d is no weight on the wire", w)
		}
	}
	if p.Has("headers.sent_priority") && len(p.Numbers("h2.urgency_weights")) == 0 {
		return fmt.Errorf("headers.sent_priority requires h2.urgency_weights")
	}
	dests := map[string]bool{}
	for _, entry := range p.Strings("headers.sent_priority") {
		dest, _, ok := strings.Cut(entry, "=")
		if !ok || dest == "" || dests[dest] || dest != strings.ToLower(dest) || strings.ContainsAny(entry, "\r\n\x00") ||
			strings.ContainsAny(dest, " \t,;") {
			return fmt.Errorf("headers.sent_priority: %q is not a destination=Priority said once", entry)
		}
		dests[dest] = true
	}
	// An answer drained in the background (Chrome's HttpResponseBodyDrainer)
	// is drained within both limits, and one awaited until its first bytes
	// within its own; neither says anything without such an answer, nor
	// does the grace of a protocol none of whose answers is let go of.
	for _, limits := range [][]string{{"drain", "http.drain_bytes", "http.drain_ms"}, {"first-bytes", "http.first_bytes_ms"}} {
		mode := limits[0]
		used := slices.ContainsFunc(unreadBodies, func(k string) bool { return p.Text(k) == mode })
		for _, k := range limits[1:] {
			if used && !p.Has(k) {
				return fmt.Errorf("an answer let go of by %s requires %s", mode, k)
			}
			if !used && p.Has(k) {
				return fmt.Errorf("%s is set while no answer is let go of by %s", k, mode)
			}
		}
	}
	for _, proto := range []string{"h1.", "h2."} {
		letGo := slices.ContainsFunc(unreadBodies, func(k string) bool {
			return strings.HasPrefix(k, proto) && slices.Contains([]string{"close", "drain", "first-bytes"}, p.Text(k))
		})
		if p.Has(proto+"unread_grace_us") && !letGo {
			return fmt.Errorf("%sunread_grace_us is set while no answer over it is let go of", proto)
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

	if err := validateECH(p); err != nil {
		return err
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

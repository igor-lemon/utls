package tls

import (
	"bytes"
	"testing"
)

func TestExplicitGREASEPayloadSurvivesApplyPreset(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		for _, second := range [][]byte{nil, {}, {1, 2, 3}} {
			spec := sigAlgGREASESpec()
			first := &UtlsGREASEExtension{Body: []byte{9}, BodySet: explicit}
			last := &UtlsGREASEExtension{Body: bytes.Clone(second), BodySet: explicit}
			spec.Extensions = append(spec.Extensions, first, last)
			c := UClient(nil, &Config{ServerName: "a13.test"}, HelloCustom, false, false, false)
			if err := c.ApplyPreset(&spec); err != nil {
				t.Fatal(err)
			}
			want := second
			if !explicit {
				want = []byte{0}
			}
			if !bytes.Equal(first.Body, []byte{9}) || !bytes.Equal(last.Body, want) {
				t.Fatalf("explicit=%v: first=%x second=%x want=%x", explicit, first.Body, last.Body, want)
			}
			if !isGREASEUint16(first.Value) || !isGREASEUint16(last.Value) || first.Value == last.Value {
				t.Fatal("GREASE ID rules changed")
			}
			wire := make([]byte, last.Len())
			if _, err := last.Read(wire); err == nil {
				t.Fatal("extension reader lost EOF contract")
			}
			if !bytes.Equal(wire[4:], want) {
				t.Fatal("wire payload changed")
			}
		}
	}
}

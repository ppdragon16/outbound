package protocol

import "testing"

func TestParseMetadataPortBounds(t *testing.T) {
	cases := []struct {
		target  string
		wantErr bool
		want    uint16
	}{
		{"1.2.3.4:443", false, 443},
		{"[::1]:8080", false, 8080},
		{"example.com:80", false, 80},
		// Previously wrapped: Atoi + uint16 conversion mapped -1 to 65535
		// and 65536 to 0.
		{"1.2.3.4:-1", true, 0},
		{"1.2.3.4:65536", true, 0},
		{"1.2.3.4:99999", true, 0},
	}
	for _, c := range cases {
		mdata, err := ParseMetadata(c.target)
		if c.wantErr {
			if err == nil {
				t.Fatalf("ParseMetadata(%q) = %+v, want error", c.target, mdata)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseMetadata(%q): %v", c.target, err)
		}
		if mdata.Port != c.want {
			t.Fatalf("ParseMetadata(%q) port = %d, want %d", c.target, mdata.Port, c.want)
		}
	}
}

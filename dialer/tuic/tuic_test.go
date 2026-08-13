package tuic

import "testing"

func TestTuicURLRoundTripWithCwnd(t *testing.T) {
	cases := []struct {
		name     string
		link     string
		wantCwnd int
	}{
		{
			name:     "brutal with cwnd",
			link:     "tuic://uuid:pass@example.com:443?congestion_control=brutal&cwnd=80000000",
			wantCwnd: 80000000,
		},
		{
			name:     "no cwnd defaults to zero",
			link:     "tuic://uuid:pass@example.com:443?congestion_control=bbr",
			wantCwnd: 0,
		},
		{
			name:     "malformed cwnd degrades to zero",
			link:     "tuic://uuid:pass@example.com:443?congestion_control=brutal&cwnd=abc",
			wantCwnd: 0,
		},
		{
			name:     "negative cwnd degrades to zero",
			link:     "tuic://uuid:pass@example.com:443?congestion_control=brutal&cwnd=-5",
			wantCwnd: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseTuicURL(tc.link)
			if err != nil {
				t.Fatalf("ParseTuicURL: %v", err)
			}
			if parsed.Cwnd != tc.wantCwnd {
				t.Fatalf("Cwnd = %d, want %d", parsed.Cwnd, tc.wantCwnd)
			}

			// Export/parse round trip must preserve the cwnd value.
			reparsed, err := ParseTuicURL(parsed.ExportToURL())
			if err != nil {
				t.Fatalf("re-ParseTuicURL: %v", err)
			}
			if reparsed.Cwnd != tc.wantCwnd {
				t.Fatalf("round-trip Cwnd = %d, want %d", reparsed.Cwnd, tc.wantCwnd)
			}
			if reparsed.CongestionControl != parsed.CongestionControl {
				t.Fatalf("round-trip CongestionControl = %q, want %q",
					reparsed.CongestionControl, parsed.CongestionControl)
			}
		})
	}
}

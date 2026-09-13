package anytls

import (
	"testing"
)

// TestParseAnytlsURLSessionAsConn pins the mode default: the session-as-conn
// fast path is on unless an explicit `mode=stream` opts back out.
func TestParseAnytlsURLSessionAsConn(t *testing.T) {
	cases := []struct {
		name string
		link string
		want bool
	}{
		{
			name: "no mode parameter defaults to conn path",
			link: "anytls://testpass@example.com:8443/?sni=example.com&insecure=1",
			want: true,
		},
		{
			name: "explicit mode=conn",
			link: "anytls://testpass@example.com:8443/?mode=conn&sni=example.com",
			want: true,
		},
		{
			name: "explicit mode=stream",
			link: "anytls://testpass@example.com:8443/?mode=stream&sni=example.com",
			want: false,
		},
		{
			name: "unknown mode value behaves like the default (conn)",
			link: "anytls://testpass@example.com:8443/?mode=typo&sni=example.com",
			want: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := parseAnytlsURL(c.link)
			if err != nil {
				t.Fatal(err)
			}
			if s.SessionAsConn != c.want {
				t.Fatalf("SessionAsConn = %v, want %v", s.SessionAsConn, c.want)
			}
		})
	}
}

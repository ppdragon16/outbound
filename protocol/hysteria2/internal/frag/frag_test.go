package frag

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

func TestFragUDPMessage(t *testing.T) {
	type args struct {
		m       *protocol.UDPMessage
		maxSize int
	}
	tests := []struct {
		name string
		args args
		want []protocol.UDPMessage
	}{
		{
			"no frag",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("hello"),
				},
				100,
			},
			[]protocol.UDPMessage{
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("hello"),
				},
			},
		},
		{
			"2 frags",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("hello"),
				},
				21,
			},
			[]protocol.UDPMessage{
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 2,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("hel"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    1,
					FragCount: 2,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("lo"),
				},
			},
		},
		{
			"4 frags",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("abcdefgh"),
				},
				20,
			},
			[]protocol.UDPMessage{
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 4,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("ab"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    1,
					FragCount: 4,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("cd"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    2,
					FragCount: 4,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("ef"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    3,
					FragCount: 4,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("gh"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FragUDPMessage(tt.args.m, tt.args.maxSize); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FragUDPMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefragger(t *testing.T) {
	type args struct {
		m *protocol.UDPMessage
	}
	tests := []struct {
		name     string
		args     args
		wantOk   bool
		wantData string
	}{
		{
			"no frag",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    0,
					FragCount: 1,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("hello"),
				},
			},
			true,
			"hello",
		},
		{
			"frag 0 - 1/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    0,
					FragCount: 2,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("hello "),
				},
			},
			false,
			"",
		},
		{
			"frag 0 - 2/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    1,
					FragCount: 2,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("moto"),
				},
			},
			true,
			"hello moto",
		},
		{
			"frag 1 - 1/3",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    0,
					FragCount: 3,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("deco"),
				},
			},
			false,
			"",
		},
		{
			"frag 1 - 2/3",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    1,
					FragCount: 3,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("*"),
				},
			},
			false,
			"",
		},
		{
			"frag 1 - 3/3",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    2,
					FragCount: 3,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("27"),
				},
			},
			true,
			"deco*27",
		},
		{
			"frag 2 - 1/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    1,
					FragCount: 2,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("shinsekai"),
				},
			},
			false,
			"",
		},
		{
			"frag 3 - 2/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  244,
					FragID:    1,
					FragCount: 2,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("what???"),
				},
			},
			false,
			"",
		},
		{
			"frag 2 - 2/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    1,
					FragCount: 2,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte(" annaijo"),
				},
			},
			false,
			"",
		},
		{
			"invalid id",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    88,
					FragCount: 2,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("shinsekai"),
				},
			},
			false,
			"",
		},
		{
			"frag 2 - 1/2 re",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    0,
					FragCount: 2,
					AddrPort:  netip.MustParseAddrPort("1.2.3.4:1"),
					Data:      []byte("shinsekai"),
				},
			},
			true,
			"shinsekai annaijo",
		},
	}

	d := &Defragger{}
	buf := make([]byte, 1024)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clear(buf)
			n, ok := d.Feed(tt.args.m, buf)
			if ok != tt.wantOk {
				t.Errorf("Feed() ok = %v, want %v", ok, tt.wantOk)
			}
			if ok && string(buf[:n]) != tt.wantData {
				t.Errorf("Feed() data = %q, want %q", string(buf[:n]), tt.wantData)
			}
		})
	}
}

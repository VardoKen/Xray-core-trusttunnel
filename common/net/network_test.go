package net_test

import (
	"testing"

	. "github.com/xtls/xray-core/common/net"
)

func TestNetworkSystemString(t *testing.T) {
	testCases := []struct {
		network Network
		want    string
	}{
		{network: Network_TCP, want: "tcp"},
		{network: Network_UDP, want: "udp"},
		{network: Network_UNIX, want: "unix"},
		{network: Network_ICMP, want: "icmp"},
		{network: Network_Unknown, want: "unknown"},
	}

	for _, testCase := range testCases {
		if got := testCase.network.SystemString(); got != testCase.want {
			t.Fatalf("network %v SystemString() = %q, want %q", testCase.network, got, testCase.want)
		}
	}
}

func TestNetworkEnumString(t *testing.T) {
	if got := Network_ICMP.String(); got != "ICMP" {
		t.Fatalf("Network_ICMP.String() = %q, want %q", got, "ICMP")
	}
}

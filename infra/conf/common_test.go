package conf

import (
	"encoding/json"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
)

func TestNetworkBuildSupportsICMP(t *testing.T) {
	if got := Network("icmp").Build(); got != xnet.Network_ICMP {
		t.Fatalf("Network(\"icmp\").Build() = %v, want %v", got, xnet.Network_ICMP)
	}
}

func TestNetworkListBuildSupportsICMP(t *testing.T) {
	var list NetworkList
	if err := json.Unmarshal([]byte(`"tcp,icmp"`), &list); err != nil {
		t.Fatalf("failed to unmarshal network list: %v", err)
	}

	got := list.Build()
	if len(got) != 2 {
		t.Fatalf("len(Build()) = %d, want %d", len(got), 2)
	}
	if got[0] != xnet.Network_TCP || got[1] != xnet.Network_ICMP {
		t.Fatalf("Build() = %v, want [%v %v]", got, xnet.Network_TCP, xnet.Network_ICMP)
	}
}

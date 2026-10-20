package localnets

import (
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestHomeNet(t *testing.T) {
	var n yaml.Node
	_ = yaml.Unmarshal([]byte(`
vars:
  address-groups:
    HOME_NET: "[$LAN,10.0.0.0/8,!10.9.0.0/16,2001:db8:10::/48]"
    LAN: "[192.168.1.0/24,$GUEST]"
    GUEST: "192.168.9.0/24"
    EXTERNAL_NET: "!$HOME_NET"
`), &n)
	got := HomeNet(&n)
	want := []string{"192.168.1.0/24", "192.168.9.0/24", "10.0.0.0/8", "2001:db8:10::/48"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
	if HomeNet(nil) != nil {
		t.Fatal("nil config")
	}
}

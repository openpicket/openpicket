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

// TestHomeNetNested: suricontroller wraps the user's value to add the
// interface addresses; negated groups drop all they contain.
func TestHomeNetNested(t *testing.T) {
	for value, want := range map[string][]string{
		"[[192.168.0.0/16,!192.168.1.5],125.131.127.16,2001:db8::10]": {"192.168.0.0/16", "125.131.127.16", "2001:db8::10"},
		"[[[10.0.0.0/8]],![172.16.0.0/12,172.17.0.0/16],1.2.3.4]":     {"10.0.0.0/8", "1.2.3.4"},
		"[ 10.0.0.0/8 , !10.1.0.0/16 ]":                               {"10.0.0.0/8"},
		"any":                                                         nil,
	} {
		var n yaml.Node
		_ = yaml.Unmarshal([]byte("vars:\n  address-groups:\n    HOME_NET: \""+value+"\"\n"), &n)
		if got := HomeNet(&n); !slices.Equal(got, want) {
			t.Errorf("%s: got %v, want %v", value, got, want)
		}
	}
}

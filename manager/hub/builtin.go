package hub

import (
	builtin "github.com/openpicket/openpicket/hub"
	"github.com/openpicket/openpicket/pkg/hubitem"
)

// BuiltinBundle renders the built-in items in their default state,
// without a database (tests and offline setups pushing it by hand).
func BuiltinBundle(revision int64) (*hubitem.Bundle, error) {
	items, err := builtin.Builtin()
	if err != nil {
		return nil, err
	}
	b := &hubitem.Bundle{Revision: revision}
	for _, it := range items {
		p, err := hubitem.ItemPath(it.Type, it.Stage, it.Name)
		if err != nil {
			return nil, err
		}
		b.Items = append(b.Items, hubitem.File{Path: p, Content: it.Content})
		if it.Type == hubitem.Scenarios && DefaultState(it.Type, hubitem.SourceBuiltin) == hubitem.Simulation {
			b.Simulation = append(b.Simulation, it.Name)
		}
	}
	return b, b.Check()
}

package enforcer

import (
	"net/netip"
	"slices"
	"time"
)

// Piece is one element of an interval set.
type Piece struct {
	Prefix   netip.Prefix
	Deadline time.Time
	// From is the index (in the input) of the decision whose deadline the
	// piece has.
	From int
}

type node struct {
	p        netip.Prefix
	deadline time.Time
	from     int
	children []*node
	// maxDeadline over the subtree.
	maxDeadline time.Time
}

// Decompose turns possibly nested ranges of one set (same family) into
// disjoint prefixes, as interval sets require, without losing a block:
// every address keeps the latest deadline of the ranges covering it. A
// range inside a longer-lived one disappears into it; a range outliving
// the one around it splits the outer range around itself, so when the
// outer range expires the inner one is still in the kernel.
//
// Sorting by address then prefix length puts every range right after the
// ranges containing it, so a stack builds the nesting in O(n log n).
func Decompose(ranges []Entry) []Piece {
	store := make([]node, 0, len(ranges))
	for i, en := range ranges {
		p, err := netip.ParsePrefix(en.Value)
		if err != nil {
			continue
		}
		store = append(store, node{p: p.Masked(), deadline: en.Deadline, from: i})
	}
	nodes := make([]*node, len(store))
	for i := range store {
		nodes[i] = &store[i]
	}
	slices.SortFunc(nodes, func(a, b *node) int {
		if c := a.p.Addr().Compare(b.p.Addr()); c != 0 {
			return c
		}
		return a.p.Bits() - b.p.Bits()
	})
	var roots, stack []*node
	for _, n := range nodes {
		for len(stack) > 0 && !contains(stack[len(stack)-1].p, n.p) {
			stack = stack[:len(stack)-1]
		}
		if len(stack) > 0 {
			top := stack[len(stack)-1]
			if top.p == n.p {
				// The same range twice: keep the later deadline.
				if n.deadline.After(top.deadline) {
					top.deadline, top.from = n.deadline, n.from
				}
				continue
			}
			top.children = append(top.children, n)
		} else {
			roots = append(roots, n)
		}
		stack = append(stack, n)
	}
	out := make([]Piece, 0, len(roots))
	for _, r := range roots {
		subtreeMax(r)
		out = emit(out, r, time.Time{}, -1)
	}
	return out
}

func contains(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

func subtreeMax(n *node) time.Time {
	n.maxDeadline = n.deadline
	for _, c := range n.children {
		if m := subtreeMax(c); m.After(n.maxDeadline) {
			n.maxDeadline = m
		}
	}
	return n.maxDeadline
}

// emit adds the pieces of n, covered by ancestors up to inherited.
func emit(out []Piece, n *node, inherited time.Time, inheritedFrom int) []Piece {
	eff, from := n.deadline, n.from
	if inherited.After(eff) {
		eff, from = inherited, inheritedFrom
	}
	var outliving []*node
	for _, c := range n.children {
		if c.maxDeadline.After(eff) {
			outliving = append(outliving, c)
		}
	}
	if len(outliving) == 0 {
		// The common case: nothing inside outlives this range.
		return append(out, Piece{Prefix: n.p, Deadline: eff, From: from})
	}
	holes := make([]netip.Prefix, len(outliving))
	for i, c := range outliving {
		holes[i] = c.p
	}
	for _, p := range complement(n.p, holes) {
		out = append(out, Piece{Prefix: p, Deadline: eff, From: from})
	}
	for _, c := range outliving {
		out = emit(out, c, eff, from)
	}
	return out
}

// complement returns the prefixes of p not inside any of holes (disjoint
// prefixes within p), by halving p around them: at most
// len(holes) × (bits difference) prefixes.
func complement(p netip.Prefix, holes []netip.Prefix) []netip.Prefix {
	return appendComplement(nil, p, holes)
}

func appendComplement(out []netip.Prefix, p netip.Prefix, holes []netip.Prefix) []netip.Prefix {
	n := 0
	for _, h := range holes {
		if h == p {
			return out
		}
		if contains(p, h) {
			n++
		}
	}
	if n == 0 {
		return append(out, p)
	}
	in := holes
	if n < len(holes) {
		in = make([]netip.Prefix, 0, n)
		for _, h := range holes {
			if contains(p, h) {
				in = append(in, h)
			}
		}
	}
	lo, hi := halves(p)
	return appendComplement(appendComplement(out, lo, in), hi, in)
}

// halves splits p into its two sub-prefixes.
func halves(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits() + 1
	lo := netip.PrefixFrom(p.Addr(), bits)
	b := p.Addr().AsSlice()
	idx := (bits - 1) / 8
	b[idx] |= 0x80 >> ((bits - 1) % 8)
	hiAddr, _ := netip.AddrFromSlice(b)
	return lo, netip.PrefixFrom(hiAddr, bits)
}

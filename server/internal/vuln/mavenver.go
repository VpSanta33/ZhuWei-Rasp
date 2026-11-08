package vuln

import (
	"math/big"
	"strings"
)

// CompareMaven orders two Maven versions the way Maven's ComparableVersion does, which is what OSV's
// "Maven" ecosystem ranges are defined against:
//
//   - "." and "-" separate items; a switch between digits and letters also starts a new item ("1a1" = "1-a-1").
//   - "-" (and a digit/letter switch) opens a sub-list, so "1-1" sorts before "1.1".
//   - Null items (0, "", ga, final, release) are dropped at the end of each list: 1 == 1.0 == 1.0.0 == 1-ga.
//   - Qualifier order: alpha < beta < milestone < rc (= cr) < snapshot < "" (release) < sp < others (lexical).
//   - Numbers beat qualifiers and lists: 1.0.1 > 1.0-sp > 1.0 > 1.0-rc1.
//
// It returns -1, 0 or 1.
func CompareMaven(a, b string) int {
	c := parseMaven(a).compare(parseMaven(b))
	switch {
	case c < 0:
		return -1
	case c > 0:
		return 1
	}
	return 0
}

type mItem interface {
	compare(other mItem) int // other == nil means "end of list"
	isNull() bool
}

type intItem struct{ v *big.Int }
type strItem struct{ v string }
type listItem []mItem

var qualifierOrder = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}
var qualifierAliases = map[string]string{"ga": "", "final": "", "release": "", "cr": "rc"}

func qualifierRank(q string) string {
	for i, k := range qualifierOrder {
		if k == q {
			return string(rune('0' + i))
		}
	}
	return string(rune('0'+len(qualifierOrder))) + "-" + q // unknown qualifiers sort after known ones
}

func newStr(s string, followedByDigit bool) strItem {
	if followedByDigit && len(s) == 1 { // "a1", "b2", "m3"
		switch s {
		case "a":
			s = "alpha"
		case "b":
			s = "beta"
		case "m":
			s = "milestone"
		}
	}
	if a, ok := qualifierAliases[s]; ok {
		s = a
	}
	return strItem{s}
}

func (i intItem) isNull() bool { return i.v.Sign() == 0 }
func (i intItem) compare(o mItem) int {
	switch x := o.(type) {
	case nil:
		return i.v.Sign()
	case intItem:
		return i.v.Cmp(x.v)
	}
	return 1 // a number is newer than a qualifier or a sub-list
}

func (s strItem) isNull() bool { return s.v == "" }
func (s strItem) compare(o mItem) int {
	switch x := o.(type) {
	case nil:
		return strings.Compare(qualifierRank(s.v), qualifierRank(""))
	case strItem:
		return strings.Compare(qualifierRank(s.v), qualifierRank(x.v))
	}
	return -1
}

func (l listItem) isNull() bool { return len(l) == 0 }
func (l listItem) compare(o mItem) int {
	switch x := o.(type) {
	case nil:
		if len(l) == 0 {
			return 0
		}
		return l[0].compare(nil)
	case intItem:
		return -1
	case strItem:
		return 1
	case listItem:
		for i := 0; i < len(l) || i < len(x); i++ {
			var left, right mItem
			if i < len(l) {
				left = l[i]
			}
			if i < len(x) {
				right = x[i]
			}
			var c int
			switch {
			case left == nil && right == nil:
				continue
			case left == nil:
				c = -right.compare(nil)
			default:
				c = left.compare(right)
			}
			if c != 0 {
				return c
			}
		}
	}
	return 0
}

// normalize mirrors ComparableVersion.ListItem.normalize: walking backwards, null items are removed and
// non-null sub-lists are skipped over; the walk stops at the first non-null plain item.
func (l listItem) normalize() listItem {
	for i := len(l) - 1; i >= 0; i-- {
		if l[i].isNull() {
			l = append(l[:i], l[i+1:]...)
		} else if _, isList := l[i].(listItem); !isList {
			break
		}
	}
	return l
}

func parseMaven(version string) listItem {
	v := strings.ToLower(strings.TrimSpace(version))
	// lists[0] is the root; every "-" or digit/letter switch opens a sub-list nested in the previous one.
	lists := []listItem{{}}
	push := func(it mItem) { lists[len(lists)-1] = append(lists[len(lists)-1], it) }
	start, isDigit := 0, false
	emit := func(end int, followedByDigit bool) {
		if end <= start {
			push(intItem{big.NewInt(0)}) // empty item, e.g. "1..2" or "1-"
			return
		}
		tok := v[start:end]
		if isDigit {
			n, ok := new(big.Int).SetString(tok, 10)
			if !ok {
				n = big.NewInt(0)
			}
			push(intItem{n})
		} else {
			push(newStr(tok, followedByDigit))
		}
	}
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == '.':
			emit(i, false)
			start, isDigit = i+1, false
		case c == '-':
			emit(i, false)
			start, isDigit = i+1, false
			lists = append(lists, listItem{})
		case c >= '0' && c <= '9':
			if !isDigit && i > start { // letter -> digit
				emit(i, true)
				start = i
				lists = append(lists, listItem{})
			}
			isDigit = true
		default:
			if isDigit && i > start { // digit -> letter
				emit(i, false)
				start = i
				lists = append(lists, listItem{})
			}
			isDigit = false
		}
	}
	if len(v) > start {
		emit(len(v), false)
	}
	for len(lists) > 1 { // fold innermost first, normalising each list as Maven pops its stack
		child := lists[len(lists)-1].normalize()
		lists = lists[:len(lists)-1]
		lists[len(lists)-1] = append(lists[len(lists)-1], child)
	}
	return lists[0].normalize()
}

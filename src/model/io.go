package model

import (
	"fmt"
	"os"
	"strings"
)

// Header of fixtures/expected.tsv and results/cases.tsv.
const Header = "id\tversion\tendpoint\tlabel\tuser\tverify_idp\tresolve_idp\tconfused\tgate\tdiff_lines"

// Tokens: @empty = "" (an empty IdP id, diff:94-112), @none = no state.
func token(s string) string {
	if s == "@empty" {
		return ""
	}
	return s
}

func show(s string) string {
	if s == "" {
		return "@empty"
	}
	return s
}

func b(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// Row renders an outcome as one TSV line.
func (o Outcome) Row() string {
	return strings.Join([]string{o.ID, o.Version, o.Endpoint, o.Label, o.User, show(o.VerifyIDP), show(o.ResolveIDP), b(o.Confused), o.Gate, o.DiffLines}, "\t")
}

// Fixture is a case plus its hand labels.
type Fixture struct {
	Case
	HandPre, HandPost string
}

// LoadCases reads fixtures/cases.tsv (12 fields).
func LoadCases(file string) ([]Fixture, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var out []Fixture
	for n, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 12 {
			return nil, fmt.Errorf("%s:%d: want 12 fields, got %d", file, n+1, len(f))
		}
		if f[9] != "0" && f[9] != "1" {
			return nil, fmt.Errorf("%s:%d: shared_key must be 0 or 1", file, n+1)
		}
		out = append(out, Fixture{
			Case: Case{ID: f[0], Kind: f[1], Endpoint: f[2], PathIDP: token(f[3]), StateIDP: token(f[4]),
				Signer: f[5], SP: f[6], InResponseTo: f[7], NameID: f[8], SharedKey: f[9] == "1"},
			HandPre: f[10], HandPost: f[11]})
	}
	return out, nil
}

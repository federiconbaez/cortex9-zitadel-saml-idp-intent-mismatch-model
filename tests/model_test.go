// Tests for the ZITADEL SAML intent callback model. "diff:N" is a line of the
// saved fix diff CVE-2026-109372_zitadel_450c0560bc83.diff (see SOURCES.md).
package tests

import (
	"os"
	"strings"
	"testing"

	"github.com/federiconbaez/cortex9-zitadel-saml-idp-intent-mismatch-model/src/model"
)

func fixtures(t *testing.T) []model.Fixture {
	t.Helper()
	fs, err := model.LoadCases("../fixtures/cases.tsv")
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func byID(t *testing.T, id string) model.Case {
	t.Helper()
	for _, f := range fixtures(t) {
		if f.ID == id {
			return f.Case
		}
	}
	t.Fatalf("fixture %s missing", id)
	return model.Case{}
}

func TestFixtureCounts(t *testing.T) {
	n := map[string]int{}
	seen := map[string]bool{}
	for _, f := range fixtures(t) {
		n[f.Kind]++
		if seen[f.ID] {
			t.Errorf("duplicate id %s", f.ID)
		}
		seen[f.ID] = true
	}
	if n["pos"] < 7 || n["diff"] < 5 || n["neg"] < 7 || n["adv"] < 11 {
		t.Fatalf("fixture counts: %v", n)
	}
}

// The model must agree row by row with scripts/derive_expected.py.
func TestFixturesMatchIndependentDerivation(t *testing.T) {
	data, err := os.ReadFile("../fixtures/expected.tsv")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	got := []string{model.Header}
	for _, f := range fixtures(t) {
		got = append(got, model.Run(f.Case, model.Pre).Row(), model.Run(f.Case, model.Post).Row())
	}
	if len(got) != len(want) {
		t.Fatalf("rows: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d:\n got %s\nwant %s", i, got[i], want[i])
		}
	}
}

func TestHandLabels(t *testing.T) {
	for _, f := range fixtures(t) {
		if got := model.Run(f.Case, model.Pre).Label; got != f.HandPre {
			t.Errorf("%s pre: %s, hand %s", f.ID, got, f.HandPre)
		}
		if got := model.Run(f.Case, model.Post).Label; got != f.HandPost {
			t.Errorf("%s post: %s, hand %s", f.ID, got, f.HandPost)
		}
	}
}

// diff:73-112: the four rows of Test_checkSAMLIntentIDP.
func TestDiffUnitTable(t *testing.T) {
	rows := []struct {
		req, intent string
		ok          bool
	}{
		{"idp-a", "idp-a", true},  // "match", diff:73-82
		{"idp-a", "idp-b", false}, // "mismatch", diff:83-92
		{"", "", true},            // "both empty match", diff:93-102
		{"idp-a", "", false},      // "one empty mismatch", diff:103-112
	}
	for _, r := range rows {
		if got := model.CheckSAMLIntentIDP(r.req, r.intent); got != r.ok {
			t.Errorf("CheckSAMLIntentIDP(%q,%q)=%v want %v", r.req, r.intent, got, r.ok)
		}
	}
}

// Advisory + integration test diff:137-193: URL names A, RelayState names B.
func TestIntegrationScenario(t *testing.T) {
	c := byID(t, "p02_integration_shared_key")
	pre, post := model.Run(c, model.Pre), model.Run(c, model.Post)
	if pre.Label != model.ConfusedSession || pre.User != "user-victim" || pre.VerifyIDP != "idp-a" || pre.ResolveIDP != "idp-b" {
		t.Errorf("pre: %+v", pre)
	}
	if post.Label != model.RejectIDPMismatch || post.Gate != "fail" || post.DiffLines != "12-15;42-47" {
		t.Errorf("post: %+v", post)
	}
}

func TestPositivesConfusedPreRejectedPost(t *testing.T) {
	for _, f := range fixtures(t) {
		if f.Kind != "pos" {
			continue
		}
		pre, post := model.Run(f.Case, model.Pre), model.Run(f.Case, model.Post)
		if !pre.Confused || post.Label != model.RejectIDPMismatch || post.Confused {
			t.Errorf("%s: pre %+v post %+v", f.ID, pre, post)
		}
	}
}

func TestNegativesUnchanged(t *testing.T) {
	for _, f := range fixtures(t) {
		if f.Kind != "neg" {
			continue
		}
		pre, post := model.Run(f.Case, model.Pre), model.Run(f.Case, model.Post)
		if pre.Label != post.Label || pre.User != post.User || pre.Confused || post.Confused {
			t.Errorf("%s: pre %+v post %+v", f.ID, pre, post)
		}
	}
}

func TestSweepInvariants(t *testing.T) {
	cases := model.Sweep()
	if len(cases) != 5400 {
		t.Fatalf("sweep size %d", len(cases))
	}
	preConfused, mismatches := 0, 0
	for _, c := range cases {
		pre, post := model.Run(c, model.Pre), model.Run(c, model.Post)
		if post.Confused || strings.HasPrefix(post.Label, "CONFUSED") {
			t.Fatalf("post confused: %+v", c)
		}
		if pre.Confused {
			preConfused++
			if c.PathIDP == c.StateIDP {
				t.Fatalf("pre confused with equal IdPs: %+v", c)
			}
			if post.Label != model.RejectIDPMismatch {
				t.Fatalf("pre confused but post %s: %+v", post.Label, c)
			}
		}
		if c.PathIDP == c.StateIDP && pre != post {
			// Only the gate column may differ when both IdPs match.
			p := post
			p.Version, p.Gate = pre.Version, pre.Gate
			if p != pre {
				t.Fatalf("fix changed a consistent request: pre %+v post %+v", pre, post)
			}
		}
		if post.Label == model.RejectIDPMismatch {
			mismatches++
			if c.PathIDP == c.StateIDP || c.StateIDP == model.None {
				t.Fatalf("bad mismatch: %+v", c)
			}
		}
		if post.Label == model.Session && pre.Label != model.Session {
			t.Fatalf("fix created a session: %+v", c)
		}
	}
	// Hand count: ACS 3 paths x 3 other states x 3 name ids x 4 (signer, key) = 108;
	// SLO the same x 2 InResponseTo values = 216; total 324. Mismatches: ACS
	// 9 (path, state) pairs x 108 = 972; SLO 16 pairs x 108 = 1728; total 2700.
	if preConfused != 324 || mismatches != 2700 {
		t.Errorf("preConfused=%d mismatches=%d", preConfused, mismatches)
	}
}

func TestGateOrdering(t *testing.T) {
	// ACS: provider is looked up before the gate (samlProvider is used at diff:17,
	// gate at diff:12): an unknown path IdP is REJECT_PROVIDER in both versions.
	if o := model.Run(byID(t, "a01_case_variant_acs"), model.Post); o.Label != model.RejectProvider || o.Gate != "-" {
		t.Errorf("acs: %+v", o)
	}
	// SLO: the gate (diff:27) comes before getProvider (diff:32).
	if o := model.Run(byID(t, "a02_case_variant_slo"), model.Post); o.Label != model.RejectIDPMismatch {
		t.Errorf("slo: %+v", o)
	}
}

func TestAdversarialInputs(t *testing.T) {
	base := byID(t, "n01_victim_legit")
	for _, v := range []string{"", "PRE", "post "} {
		if o := model.Run(base, v); o.Label != model.BadInput {
			t.Errorf("version %q: %s", v, o.Label)
		}
	}
	bad := base
	bad.Endpoint = "logout"
	if o := model.Run(bad, model.Post); o.Label != model.BadInput {
		t.Errorf("endpoint: %s", o.Label)
	}
	bad = base
	bad.Signer = "idp-z"
	if o := model.Run(bad, model.Post); o.Label != model.BadInput {
		t.Errorf("signer: %s", o.Label)
	}
	// Byte-exact comparison: case, whitespace, a Cyrillic "а" and NUL all differ.
	for _, s := range []string{"IDP-B", "idp-b ", " idp-b", "idp-\u0431", "idp-b\x00", "idp-\u0430"} {
		if model.CheckSAMLIntentIDP("idp-b", s) {
			t.Errorf("gate accepted %q", s)
		}
	}
	// The fix does not help when IdPs share a signing key and the response is
	// built for the right SP (a06): outside the scope of the fix.
	c := byID(t, "a06_shared_key_forged_for_b")
	if o := model.Run(c, model.Post); o.Label != model.Session || o.User != "user-victim" {
		t.Errorf("a06: %+v", o)
	}
}

func TestResultsMatchCommitted(t *testing.T) {
	data, err := os.ReadFile("../results/sweep.csv")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != model.SweepCSV() {
		t.Fatal("results/sweep.csv differs from the model")
	}
	exp, err := os.ReadFile("../fixtures/expected.tsv")
	if err != nil {
		t.Fatal(err)
	}
	res, err := os.ReadFile("../results/cases.tsv")
	if err != nil {
		t.Fatal(err)
	}
	if string(exp) != string(res) {
		t.Fatal("results/cases.tsv differs from fixtures/expected.tsv")
	}
}

// PRACTICE.md levels.
func TestPracticeLevels(t *testing.T) {
	c := func(ep, path, state, signer, sp, irt, nid string, shared bool) model.Case {
		return model.Case{Endpoint: ep, PathIDP: path, StateIDP: state, Signer: signer, SP: sp, InResponseTo: irt, NameID: nid, SharedKey: shared}
	}
	// 1: legit login.
	if o := model.Run(c("acs", "idp-b", "idp-b", "idp-b", "idp-b", "intent", "victim-external-id", false), model.Pre); o.Label != model.Session || o.User != "user-victim" {
		t.Errorf("level 1: %+v", o)
	}
	// 2: confusion pre.
	if o := model.Run(c("acs", "idp-a", "idp-b", "idp-a", "idp-a", "intent", "victim-external-id", false), model.Pre); o.Label != model.ConfusedSession {
		t.Errorf("level 2: %+v", o)
	}
	// 3: without the InResponseTo copy.
	if o := model.Run(c("acs", "idp-a", "idp-b", "idp-a", "idp-a", "other", "victim-external-id", false), model.Pre); o.Label != model.RejectRequestID {
		t.Errorf("level 3: %+v", o)
	}
	// 4: the fix.
	if o := model.Run(c("acs", "idp-a", "idp-b", "idp-a", "idp-a", "intent", "victim-external-id", false), model.Post); o.Label != model.RejectIDPMismatch {
		t.Errorf("level 4: %+v", o)
	}
	// 5: SLO.
	if o := model.Run(c("slo", "idp-a", "idp-b", "idp-a", "idp-a", "intent", "-", false), model.Pre); o.Label != model.ConfusedLogout {
		t.Errorf("level 5: %+v", o)
	}
	// 6: both empty.
	if !model.CheckSAMLIntentIDP("", "") {
		t.Error("level 6")
	}
	// 7: shared key, out of scope.
	if o := model.Run(c("acs", "idp-b", "idp-b", "idp-a", "idp-b", "intent", "victim-external-id", true), model.Post); o.Label != model.Session {
		t.Errorf("level 7: %+v", o)
	}
}

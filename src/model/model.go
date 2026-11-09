// Package model is an offline, symbolic model of the ZITADEL SAML intent
// callbacks (ACS and SLO) before and after commit 450c0560bc83
// (CVE-2026-109372). "diff:N" is line N of the saved fix diff
// CVE-2026-109372_zitadel_450c0560bc83.diff. A trailing "*" in a diff
// reference means the step is reconstructed from the diff comments, the
// integration test or the advisory, not from code shown in the diff.
//
// No XML, no signatures, no network: an IdP's signing key is the string
// "k:<idp>" (or "k:instance" when the case shares one key, as in the
// integration test, diff:146-148).
package model

// Versions.
const (
	Pre  = "pre"
	Post = "post"
)

// Endpoints.
const (
	ACS = "acs"
	SLO = "slo"
)

// Labels.
const (
	RejectState       = "REJECT_STATE"
	RejectProvider    = "REJECT_PROVIDER"
	RejectIDPMismatch = "REJECT_IDP_MISMATCH"
	RejectSignature   = "REJECT_SIGNATURE"
	RejectAudience    = "REJECT_AUDIENCE"
	RejectRequestID   = "REJECT_REQUEST_ID"
	Session           = "SESSION"
	NoUser            = "NO_USER"
	ConfusedSession   = "CONFUSED_SESSION"
	ConfusedNoUser    = "CONFUSED_NO_USER"
	Logout            = "LOGOUT"
	ConfusedLogout    = "CONFUSED_LOGOUT"
	BadInput          = "BAD_INPUT"
)

// None is the fixture token for "the RelayState resolves to no intent or
// logout state".
const None = "@none"

// IDPs are the SAML providers configured on the modelled instance.
var IDPs = []string{"idp-a", "idp-b", "idp-c"}

// Links are the user links (idp, external user id) -> local user. The
// victim link mirrors diff:143-151.
var Links = map[[2]string]string{
	{"idp-b", "victim-external-id"}: "user-victim",
	{"idp-a", "attacker-ext"}:       "user-attacker",
	{"idp-c", "carol-ext"}:          "user-carol",
}

// Case is one callback. PathIDP is data.IDPID from the URL; StateIDP is the
// IdP of the intent (ACS) or logout state (SLO) found through the
// RelayState, or None. Signer is the IdP whose key signed the response, SP
// the IdP whose SP the response targets (Destination/Audience), InResponseTo
// "intent" (copied from the state's request, diff:214-216) or "other".
type Case struct {
	ID, Kind, Endpoint, PathIDP, StateIDP, Signer, SP, InResponseTo, NameID string
	SharedKey                                                               bool
}

// Outcome of one callback.
type Outcome struct {
	ID, Version, Endpoint, Label, User, VerifyIDP, ResolveIDP, Gate, DiffLines string
	Confused                                                                   bool
}

func known(idp string) bool {
	for _, x := range IDPs {
		if x == idp {
			return true
		}
	}
	return false
}

func key(idp string, shared bool) string {
	if shared {
		return "k:instance"
	}
	return "k:" + idp
}

// CheckSAMLIntentIDP is diff:42-47: byte-exact string comparison.
func CheckSAMLIntentIDP(requestIDPID, intentIDPID string) bool {
	return requestIDPID == intentIDPID
}

func validCase(c Case) bool {
	if c.Endpoint != ACS && c.Endpoint != SLO {
		return false
	}
	if c.InResponseTo != "intent" && c.InResponseTo != "other" {
		return false
	}
	return known(c.Signer) && known(c.SP)
}

// Run evaluates one case for one version.
func Run(c Case, version string) Outcome {
	o := Outcome{ID: c.ID, Version: version, Endpoint: c.Endpoint, User: "-", VerifyIDP: "-", ResolveIDP: "-", Gate: "-"}
	if (version != Pre && version != Post) || !validCase(c) {
		o.Label, o.DiffLines = BadInput, "-"
		return o
	}
	if c.Endpoint == ACS {
		return acs(c, version, o)
	}
	return slo(c, version, o)
}

func gate(c Case, version string, o *Outcome) bool {
	if version != Post {
		return true
	}
	if CheckSAMLIntentIDP(c.PathIDP, c.StateIDP) {
		o.Gate = "pass"
		return true
	}
	o.Gate = "fail"
	return false
}

// acs: intent and provider are obtained before diff:9 (both are used at
// diff:12 and diff:17; their order is reconstructed: intent first). The
// post-fix gate sits at diff:12-15, before saml2.NewSession (diff:17), which
// verifies signature and Destination/Audience with the path IdP's provider
// and InResponseTo against intent.RequestID (diff:17, 183-185, 214-216).
// The user is then resolved under the intent's IdP (diff:9-11; the call to
// checkExternalUser, diff:49, is outside the hunks).
func acs(c Case, version string, o Outcome) Outcome {
	if c.StateIDP == None {
		o.Label, o.DiffLines = RejectState, "5-7*"
		return o
	}
	if !known(c.PathIDP) {
		o.Label, o.DiffLines = RejectProvider, "5-7*"
		return o
	}
	if !gate(c, version, &o) {
		o.Label, o.DiffLines = RejectIDPMismatch, "12-15;42-47"
		return o
	}
	o.VerifyIDP = c.PathIDP
	if key(c.Signer, c.SharedKey) != key(c.PathIDP, c.SharedKey) {
		o.Label, o.DiffLines = RejectSignature, "9;17*"
		return o
	}
	if c.SP != c.PathIDP {
		o.Label, o.DiffLines = RejectAudience, "17*;146-148"
		return o
	}
	if c.InResponseTo != "intent" {
		o.Label, o.DiffLines = RejectRequestID, "17;183-185"
		return o
	}
	o.ResolveIDP = c.StateIDP
	o.Confused = o.VerifyIDP != o.ResolveIDP
	o.DiffLines = "9-11;17;49*"
	user, ok := Links[[2]string{c.StateIDP, c.NameID}]
	switch {
	case ok && o.Confused:
		o.Label, o.User = ConfusedSession, user
	case ok:
		o.Label, o.User = Session, user
	case o.Confused:
		o.Label = ConfusedNoUser
	default:
		o.Label = NoUser
	}
	return o
}

// slo: the logout state is read before diff:23. Pre has only the comment
// removed at diff:24; post adds the gate at diff:27-30, before
// getProvider(data.IDPID) at diff:32. Signature/destination checks of the
// logout response after diff:32 are reconstructed. InResponseTo is not
// modelled for SLO.
func slo(c Case, version string, o Outcome) Outcome {
	if c.StateIDP == None {
		o.Label, o.DiffLines = RejectState, "20-22*"
		return o
	}
	if !gate(c, version, &o) {
		o.Label, o.DiffLines = RejectIDPMismatch, "27-30;42-47"
		return o
	}
	if !known(c.PathIDP) {
		o.Label, o.DiffLines = RejectProvider, "32"
		return o
	}
	o.VerifyIDP = c.PathIDP
	if key(c.Signer, c.SharedKey) != key(c.PathIDP, c.SharedKey) {
		o.Label, o.DiffLines = RejectSignature, "32*"
		return o
	}
	if c.SP != c.PathIDP {
		o.Label, o.DiffLines = RejectAudience, "32*"
		return o
	}
	o.ResolveIDP = c.StateIDP
	o.Confused = o.VerifyIDP != o.ResolveIDP
	o.DiffLines = "24-26;32*"
	if o.Confused {
		o.Label = ConfusedLogout
	} else {
		o.Label = Logout
	}
	return o
}

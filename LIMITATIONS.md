# Limitations

- **A model is not a finding.** This repo re-states public behaviour from
  CVE-2026-109372, its advisories and the fix commit. Nothing here is a new
  vulnerability, and nothing was reproduced against a running ZITADEL.
- **Symbolic SAML.** No XML, no XML-DSig, no certificates, no clocks.
  "Signature valid" means "signer key string equals the URL IdP's key
  string". Destination, Recipient and Audience are folded into one `sp`
  field. Assertion lifetime, replay caches and encryption are not modelled.
- **Reconstructed steps** (marked `*`): the order of intent lookup vs.
  provider lookup in ACS (only "both before diff:9" is known), the checks
  inside `saml2.NewSession` (diff:17), the checks of the logout response
  after diff:32, and which IdP ID `checkExternalUser` (diff:49) receives
  (taken from the advisory: "resolves the user from the login intent").
- **SLO impact** is not described in the advisory beyond "the same check is
  applied"; `CONFUSED_LOGOUT` only says the logout state of one IdP was
  consumed through another IdP's path. InResponseTo is not modelled for SLO.
- **Error responses**: the model returns labels, not HTTP status codes,
  except that the diff shows `http.StatusBadRequest` for the gate
  (diff:13, 28).
- **Out of scope**: Login V1 (the advisory says it is not affected), OIDC
  and other non-SAML providers, organisation-admin permissions and public
  org registration (the advisory's precondition), instances, the 3.x line
  (no 3.x fix per the repo advisory).
- **Versions.** Only before/after 450c0560bc83 is modelled. The affected
  ranges come from the advisories, not tests.
- **Sweep** is a fixed grid of 5,400 cases, not a proof.

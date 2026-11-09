# cortex9-zitadel-saml-idp-intent-mismatch-model

Offline model of **CVE-2026-109372** (GHSA-65fv-6pff-4q47, repo advisory
GHSA-x4c7-fpcx-w9q6): SAML identity-provider confusion in ZITADEL's
identity-provider **intent** callbacks. The ACS handler verified the SAML
response with the provider named in the URL (`/idps/<id>/saml/acs`) but
resolved the user under the IdP of the login intent found through the
RelayState, without comparing the two. Fixed in 4.19.2 by commit
[450c0560bc83](https://github.com/zitadel/zitadel/commit/450c0560bc832760e58ac9b1dee21bec1ae1d4e7)
(`pre` = before, `post` = after), which adds `checkSAMLIntentIDP` to ACS
and SLO.

Educational, deterministic, Go standard library only (plus a Python 3
stdlib cross-check). No ZITADEL code is imported or run, no XML is parsed,
nothing is signed and no socket is opened. Keys and IdPs are symbolic
strings.

Spanish: [README.es.md](README.es.md). Exercises: [PRACTICE.md](PRACTICE.md).

## What is modelled

`diff:N` is line N of the saved fix diff (see [SOURCES.md](SOURCES.md)). A
`*` in the `diff_lines` column means the step is reconstructed (from diff
comments, the integration test or the advisory), not code shown in the diff.

| Step | ACS | SLO |
|---|---|---|
| State from RelayState (intent / logout state) | before diff:9 (`5-7*`) | before diff:23 (`20-22*`) |
| Provider from URL (`data.IDPID`) | before diff:9 (`5-7*`; used at diff:17) | `getProvider`, diff:32 |
| **Gate (post only)** `checkSAMLIntentIDP(data.IDPID, state.IDPID)`, byte-exact `!=` (diff:42-47) | diff:12-15, *after* the provider lookup | diff:27-30, *before* `getProvider` |
| Signature with the URL IdP's key, Destination/Audience = URL IdP's SP | `saml2.NewSession`, diff:17* (test comments diff:146-148) | after diff:32* |
| `InResponseTo == intent.RequestID` | diff:17 (`intent.RequestID`), diff:183-185, 214-216 | not modelled |
| User resolved under the **state's** IdP | diff:9-11; `checkExternalUser` diff:49* | — |

Fixed instance: `idp-a` (attacker), `idp-b` (victim, linked to
`victim-external-id` as in diff:143-151), `idp-c` (`carol-ext`). A response
whose signature was verified with IdP X but whose user is resolved under
IdP Y ≠ X is labelled `CONFUSED_SESSION` / `CONFUSED_NO_USER` /
`CONFUSED_LOGOUT`.

## Differential evidence (`results/cases.tsv`)

| Case | pre | post |
|---|---|---|
| `p01` URL `idp-a`, intent `idp-b`, signed by A for A's SP, InResponseTo copied | `CONFUSED_SESSION` as `user-victim` | `REJECT_IDP_MISMATCH` (diff:12-15) |
| `p02` same with one shared key (integration test, diff:146-148) | `CONFUSED_SESSION` | `REJECT_IDP_MISMATCH` |
| `p05` SLO, URL A, logout state B | `CONFUSED_LOGOUT` | `REJECT_IDP_MISMATCH` (diff:27-30) |
| `d01`-`d04` unit-test table (diff:73-112) | — | match/both-empty pass the gate, mismatch/one-empty fail |
| `a03` confusion without copying InResponseTo | `REJECT_REQUEST_ID` | `REJECT_IDP_MISMATCH` |
| `a02` SLO URL `IDP-B`, state `idp-b` | `REJECT_PROVIDER` | `REJECT_IDP_MISMATCH` (gate before diff:32) |
| `a06` shared key, response built for B's SP | `SESSION` | `SESSION` (outside the fix) |
| `n01`-`n07` legitimate / plainly invalid callbacks | unchanged | unchanged |

Sweep (`results/sweep.csv`, 5,400 cases): `post` never yields a confused
outcome; `pre` is confused in 324 cases, all with URL IdP ≠ state IdP; for
every case with equal IdPs the fix changes nothing; `post` rejects 2,700
cases with `REJECT_IDP_MISMATCH`. The counts are derived by hand in
`tests/model_test.go`.

**Model edges, not findings:** both empty IdP IDs pass the gate (as the
upstream unit test requires, diff:93-102); the model then rejects at
provider lookup. If two IdPs share a signing key (`a06`), a response built
for the right SP passes before and after the fix; that is key reuse, not
what this fix addresses.

## Run

```sh
sh scripts/build.sh test                                    # any skip = failure
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
python3 scripts/derive_expected.py sweep | diff - results/sweep.csv
sh scripts/build.sh results /tmp/r && diff -r results /tmp/r
go run ./src/cmd/samlmodel case pre acs idp-a idp-b idp-a idp-a intent victim-external-id
```

`fixtures/cases.tsv` holds hand labels; `scripts/derive_expected.py`
re-implements the checks in Python without reading the Go model; the tests
compare all three.

See [LIMITATIONS.md](LIMITATIONS.md) and [SOURCES.md](SOURCES.md).
License: Apache-2.0.

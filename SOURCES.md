# Sources

Local copies under `security-research-45/sources/cve2026/` (not in this
repo), fetched read-only; the NVD response carries the timestamp
2026-11-09T11:33:55 (UTC). Each SHA-256 below was checked against
`sources/cve2026/SHA256SUMS` before use. `diff:N` in this repo is line N of
the saved diff.

| Source | URL | Commit | Used for | SHA-256 of copy |
|---|---|---|---|---|
| Fix diff `diffs/CVE-2026-109372_zitadel_450c0560bc83.diff` (3 files, +183/-1) | https://github.com/zitadel/zitadel/commit/450c0560bc832760e58ac9b1dee21bec1ae1d4e7 | 450c0560bc832760e58ac9b1dee21bec1ae1d4e7 ("fix(idp): reject SAML assertions from a different IdP than the intent", author date 2026-09-28T06:10:31+02:00; cherry-pick of b834f7b1b2303a6442edda565759047d61257502) | ACS gate diff:9-15, SLO gate diff:24-30, `checkSAMLIntentIDP` diff:38-47, unit-test table diff:60-124, integration test diff:137-193 and helper diff:202-234 | 90df153e9a59f8c4bbedd7c1f99968ce4dd6b6c0653efd1eab8e955cfc3b88ba |
| GHSA record `ghsa_rec/CVE-2026-109372.json` (GHSA-65fv-6pff-4q47, unreviewed) | https://github.com/advisories/GHSA-65fv-6pff-4q47 | does not reference a commit | description, CWE-287, CVSS | 369556c8036ebcf3fd4c2da82820870771868db349b53f60ba6fd1dae680b4a2 |
| Repo advisory `ghsa_rec/CVE-2026-109372.repo-advisory.json` (GHSA-x4c7-fpcx-w9q6) | https://github.com/zitadel/zitadel/security/advisories/GHSA-x4c7-fpcx-w9q6 | does not reference a commit | mechanism (URL IdP verifies, intent IdP resolves), preconditions, Login V1 not affected, SLO gets the same check, 4.0.0-4.19.1 → 4.19.2, 3.0.0-3.4.15 without a 3.x fix | 8c408945f0e177218d0e8d5370ea2e8f1f686ea8d6ba99d73c2f569fd86663e4 |
| NVD record `nvd/CVE-2026-109372.json` (Deferred, published 2026-10-12) | https://nvd.nist.gov/vuln/detail/CVE-2026-109372 | does not reference a commit | description, references | aedd9bcff1895c9341f31bf708278bd63843f6bf03bb501064a3f179df5dd0fe |
| cve.org record `cveorg/CVE-2026-109372.json` (PUBLISHED) | https://www.cve.org/CVERecord?id=CVE-2026-109372 | — | affected `3.0.0` lessThan `4.19.2`, CWE-287 | d0c417a1bb544bbcb819f052c5447548e20115ddc7ea13e1b4aa1df8494fa447 |

**Commit ↔ CVE link.** None of the advisory records names the fix commit.
The link rests on: the commit message and code match the repo advisory's
"Patches" text (ACS and SLO check); the GitHub compare
`v4.19.1...v4.19.2` lists 450c0560bc83 among its 13 commits; and the saved
diff was re-downloaded from the commit URL on 2026-11-09 and is
byte-identical (same SHA-256). That compare result is a live lookup, not a
saved file.

Instructions addressed to a tool or agent: none found in these sources
(searched the diff, both advisories, NVD and cve.org records, including
invisible Unicode characters).

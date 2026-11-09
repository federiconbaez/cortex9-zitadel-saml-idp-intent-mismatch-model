#!/usr/bin/env python3
"""Independent derivation of fixtures/expected.tsv and results/sweep.csv.

Written from the saved diff CVE-2026-109372_zitadel_450c0560bc83.diff and
the advisory text, NOT from src/: it does not read the Go model. Each step
is written as a list of checks evaluated in the order the diff shows, so a
reordering in either implementation shows up as a mismatch.

  derive_expected.py            -> fixtures/expected.tsv on stdout
  derive_expected.py sweep      -> results/sweep.csv on stdout
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
CONFIGURED = ("idp-a", "idp-b", "idp-c")
LINKS = {("idp-b", "victim-external-id"): "user-victim",
         ("idp-a", "attacker-ext"): "user-attacker",
         ("idp-c", "carol-ext"): "user-carol"}
NONE = "@none"
HEADER = "id\tversion\tendpoint\tlabel\tuser\tverify_idp\tresolve_idp\tconfused\tgate\tdiff_lines"


def signing_key(idp, shared):
    return "k:instance" if shared else "k:" + idp


def derive(version, endpoint, path, state, signer, sp, irt, name_id, shared):
    """Return [label, user, verify_idp, resolve_idp, confused, gate, lines]."""
    if version not in ("pre", "post") or endpoint not in ("acs", "slo") \
            or irt not in ("intent", "other") or signer not in CONFIGURED or sp not in CONFIGURED:
        return ["BAD_INPUT", "-", "-", "-", 0, "-", "-"]
    gate = "-"
    # Steps as (condition_for_reject, label, lines). The gate (diff:42-47) is
    # a plain != on the two strings.
    if endpoint == "acs":
        steps = [("state", "REJECT_STATE", "5-7*"),
                 ("provider", "REJECT_PROVIDER", "5-7*"),
                 ("gate", "REJECT_IDP_MISMATCH", "12-15;42-47"),
                 ("sig", "REJECT_SIGNATURE", "9;17*"),
                 ("aud", "REJECT_AUDIENCE", "17*;146-148"),
                 ("irt", "REJECT_REQUEST_ID", "17;183-185")]
        ok_lines = "9-11;17;49*"
    else:
        steps = [("state", "REJECT_STATE", "20-22*"),
                 ("gate", "REJECT_IDP_MISMATCH", "27-30;42-47"),
                 ("provider", "REJECT_PROVIDER", "32"),
                 ("sig", "REJECT_SIGNATURE", "32*"),
                 ("aud", "REJECT_AUDIENCE", "32*")]
        ok_lines = "24-26;32*"
    verify = "-"
    for name, label, lines in steps:
        if name == "state" and state == NONE:
            return [label, "-", verify, "-", 0, gate, lines]
        if name == "provider" and path not in CONFIGURED:
            return [label, "-", verify, "-", 0, gate, lines]
        if name == "gate" and version == "post":
            if path != state:
                return [label, "-", verify, "-", 0, "fail", lines]
            gate = "pass"
        if name == "sig":
            verify = path
            if signing_key(signer, shared) != signing_key(path, shared):
                return [label, "-", verify, "-", 0, gate, lines]
        if name == "aud" and sp != path:
            return [label, "-", verify, "-", 0, gate, lines]
        if name == "irt" and irt != "intent":
            return [label, "-", verify, "-", 0, gate, lines]
    confused = int(verify != state)
    if endpoint == "slo":
        return ["CONFUSED_LOGOUT" if confused else "LOGOUT", "-", verify, state, confused, gate, ok_lines]
    user = LINKS.get((state, name_id))
    if user is None:
        return ["CONFUSED_NO_USER" if confused else "NO_USER", "-", verify, state, confused, gate, ok_lines]
    return ["CONFUSED_SESSION" if confused else "SESSION", user, verify, state, confused, gate, ok_lines]


def show(s):
    return "@empty" if s == "" else s


def tok(s):
    return "" if s == "@empty" else s


def fixtures(path):
    out = [HEADER]
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        f = line.split("\t")
        if len(f) != 12:
            sys.exit("bad fixture line: %r" % line)
        cid, _kind, ep, path_, state, signer, sp, irt, nid, shared, hp, hq = f
        for version, hand in (("pre", hp), ("post", hq)):
            r = derive(version, ep, tok(path_), tok(state), signer, sp, irt, nid, shared == "1")
            if r[0] != hand:
                sys.exit("%s/%s: derived %s != hand label %s" % (cid, version, r[0], hand))
            out.append("\t".join([cid, version, ep, r[0], r[1], show(r[2]), show(r[3]), str(r[4]), r[5], r[6]]))
    return "\n".join(out) + "\n"


def sweep():
    out = ["id,endpoint,path_idp,state_idp,signer,sp,in_response_to,name_id,shared_key,"
           "pre_label,pre_user,pre_confused,post_label,post_user,post_confused"]
    n = 0
    for ep in ("acs", "slo"):
        for path_ in ("idp-a", "idp-b", "idp-c", "", "IDP-A"):
            for state in ("idp-a", "idp-b", "idp-c", "", NONE):
                for signer in CONFIGURED:
                    for sp in CONFIGURED:
                        for irt in ("intent", "other"):
                            for nid in ("victim-external-id", "attacker-ext", "carol-ext"):
                                for shared in (False, True):
                                    n += 1
                                    a = derive("pre", ep, path_, state, signer, sp, irt, nid, shared)
                                    b = derive("post", ep, path_, state, signer, sp, irt, nid, shared)
                                    out.append(",".join(["s%04d" % n, ep, show(path_), show(state), signer, sp, irt, nid,
                                                         str(int(shared)), a[0], a[1], str(a[4]), b[0], b[1], str(b[4])]))
    return "\n".join(out) + "\n"


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "sweep":
        sys.stdout.write(sweep())
    else:
        sys.stdout.write(fixtures(sys.argv[1] if len(sys.argv) > 1 else HERE / "fixtures" / "cases.tsv"))


if __name__ == "__main__":
    main()

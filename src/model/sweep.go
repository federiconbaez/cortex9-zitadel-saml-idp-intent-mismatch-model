package model

import (
	"fmt"
	"strings"
)

// Sweep domains (fixed order; results/sweep.csv depends on it).
var (
	SweepEndpoints = []string{ACS, SLO}
	SweepPaths     = []string{"idp-a", "idp-b", "idp-c", "", "IDP-A"}
	SweepStates    = []string{"idp-a", "idp-b", "idp-c", "", None}
	SweepSigners   = []string{"idp-a", "idp-b", "idp-c"}
	SweepSPs       = []string{"idp-a", "idp-b", "idp-c"}
	SweepIRT       = []string{"intent", "other"}
	SweepNameIDs   = []string{"victim-external-id", "attacker-ext", "carol-ext"}
	SweepShared    = []bool{false, true}
)

// Sweep enumerates the full grid: 2*5*5*3*3*2*3*2 = 5400 cases.
func Sweep() []Case {
	var out []Case
	n := 0
	for _, e := range SweepEndpoints {
		for _, p := range SweepPaths {
			for _, s := range SweepStates {
				for _, sg := range SweepSigners {
					for _, sp := range SweepSPs {
						for _, irt := range SweepIRT {
							for _, nid := range SweepNameIDs {
								for _, sh := range SweepShared {
									n++
									out = append(out, Case{ID: fmt.Sprintf("s%04d", n), Kind: "sweep", Endpoint: e, PathIDP: p, StateIDP: s,
										Signer: sg, SP: sp, InResponseTo: irt, NameID: nid, SharedKey: sh})
								}
							}
						}
					}
				}
			}
		}
	}
	return out
}

// SweepCSV renders one line per sweep case with the pre and post outcome.
func SweepCSV() string {
	var sb strings.Builder
	sb.WriteString("id,endpoint,path_idp,state_idp,signer,sp,in_response_to,name_id,shared_key,pre_label,pre_user,pre_confused,post_label,post_user,post_confused\n")
	for _, c := range Sweep() {
		pre, post := Run(c, Pre), Run(c, Post)
		sb.WriteString(strings.Join([]string{c.ID, c.Endpoint, show(c.PathIDP), show(c.StateIDP), c.Signer, c.SP, c.InResponseTo, c.NameID, b(c.SharedKey),
			pre.Label, pre.User, b(pre.Confused), post.Label, post.User, b(post.Confused)}, ",") + "\n")
	}
	return sb.String()
}

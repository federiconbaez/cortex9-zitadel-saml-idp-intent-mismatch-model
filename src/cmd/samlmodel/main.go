// Command samlmodel evaluates fixtures and the fixed sweep with the ZITADEL
// SAML intent callback model.
//
//	samlmodel results <cases.tsv> <outdir>   write cases.tsv and sweep.csv
//	samlmodel case pre|post acs|slo <path_idp> <state_idp> <signer> <sp> <intent|other> <name_id> [shared]
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/federiconbaez/cortex9-zitadel-saml-idp-intent-mismatch-model/src/model"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "samlmodel:", err)
		os.Exit(2)
	}
}

func tok(s string) string {
	if s == "@empty" {
		return ""
	}
	return s
}

func run(args []string) error {
	if (len(args) == 9 || len(args) == 10) && args[0] == "case" {
		c := model.Case{ID: "cli", Endpoint: args[2], PathIDP: tok(args[3]), StateIDP: tok(args[4]), Signer: args[5], SP: args[6],
			InResponseTo: args[7], NameID: args[8], SharedKey: len(args) == 10 && args[9] == "shared"}
		fmt.Println(model.Header)
		fmt.Println(model.Run(c, args[1]).Row())
		return nil
	}
	if len(args) != 3 || args[0] != "results" {
		return fmt.Errorf("usage: samlmodel results <cases.tsv> <outdir> | case pre|post acs|slo <path> <state> <signer> <sp> <intent|other> <name_id> [shared]")
	}
	cases, err := model.LoadCases(args[1])
	if err != nil {
		return err
	}
	if err := os.MkdirAll(args[2], 0o755); err != nil {
		return err
	}
	var sb strings.Builder
	sb.WriteString(model.Header + "\n")
	for _, c := range cases {
		for _, v := range []string{model.Pre, model.Post} {
			sb.WriteString(model.Run(c.Case, v).Row() + "\n")
		}
	}
	if err := os.WriteFile(filepath.Join(args[2], "cases.tsv"), []byte(sb.String()), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(args[2], "sweep.csv"), []byte(model.SweepCSV()), 0o644)
}

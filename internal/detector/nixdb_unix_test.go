//go:build linux || darwin

package detector

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

const (
	nixSWEnv  = "/nix/store/ffffffffffffffffffffffffffffffff-system-path"
	nixBigEnv = "/nix/store/gggggggggggggggggggggggggggggggg-big-env"
)

// newNixDB writes a store database with the Nix schema subset the reader
// queries. The test is its only writer.
func newNixDB(t *testing.T, refs map[string][]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "db.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	must := func(_ sql.Result, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(tx.Exec(`CREATE TABLE ValidPaths (id INTEGER PRIMARY KEY, path TEXT UNIQUE NOT NULL)`))
	must(tx.Exec(`CREATE TABLE Refs (referrer INTEGER NOT NULL, reference INTEGER NOT NULL, PRIMARY KEY (referrer, reference))`))
	id := func(p string) int64 {
		must(tx.Exec(`INSERT OR IGNORE INTO ValidPaths (path) VALUES (?)`, p))
		var n int64
		if err := tx.QueryRow(`SELECT id FROM ValidPaths WHERE path = ?`, p).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for root, rs := range refs {
		r := id(root)
		for _, p := range rs {
			must(tx.Exec(`INSERT INTO Refs VALUES (?, ?)`, r, id(p)))
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNixDirectRefs(t *testing.T) {
	hm := hmRefs(t)[nixHMPath]
	sw := []string{nixSWEnv, nixHello, "/nix/store/99999999999999999999999999999999-env-manifest.nix", nixZlib}
	big := make([]string, maxNixRefs+1)
	for i := range big {
		big[i] = fmt.Sprintf("/nix/store/%032d-p-%d", i, i)
	}
	dbPath := newNixDB(t, map[string][]string{nixHMPath: hm, nixSWEnv: sw, nixBigEnv: big})
	before, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	files := executor.NewMock()
	files.SetSymlink(nixDBPath, dbPath)

	got, err := nixDirectRefs(context.Background(), files, []string{nixHMPath, nixSWEnv, nixBigEnv, nixEnvLead})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[nixEnvLead]; ok {
		t.Error("an unregistered root has references")
	}
	pkgs, status, _ := nixMembers(nixHMPath, got[nixHMPath])
	var names []string
	for _, p := range pkgs {
		names = append(names, p.Name+" "+p.Version)
	}
	if want := "which 2.23,hello 2.12.1,shared-mime-info 2.4,hm-session-vars.sh unknown,man-db 2.13.0"; strings.Join(names, ",") != want || status != model.SystemPackageStatusComplete {
		t.Errorf("home-path members %q %s, want %q complete", names, status, want)
	}
	if pkgs, _, _ := nixMembers(nixSWEnv, got[nixSWEnv]); len(pkgs) != 2 {
		t.Errorf("system path members %d, want 2 (itself and its env manifest excluded)", len(pkgs))
	}
	if len(got[nixBigEnv]) != maxNixRefs+1 {
		t.Errorf("big env refs %d, want the %d-row cut", len(got[nixBigEnv]), maxNixRefs+1)
	}
	if pkgs, status, errText := nixMembers(nixBigEnv, got[nixBigEnv]); len(pkgs) != maxNixRefs || status != model.SystemPackageStatusPartial || errText != nixRefLimit {
		t.Errorf("big env %d %s %q, want %d partial %q", len(pkgs), status, errText, maxNixRefs, nixRefLimit)
	}
	if after, _ := os.ReadFile(dbPath); !bytes.Equal(before, after) {
		t.Error("the read-only reader changed the database")
	}

	t.Run("missing database", func(t *testing.T) {
		files := executor.NewMock()
		files.SetSymlink(nixDBPath, filepath.Join(t.TempDir(), "absent.sqlite"))
		if _, err := nixDirectRefs(context.Background(), files, []string{nixHMPath}); !errors.Is(err, errNixDBOpen) {
			t.Errorf("err = %v, want %v", err, errNixDBOpen)
		}
	})
}

//go:build linux || darwin

package detector

import (
	"context"
	"database/sql"
	"errors"
	"net/url"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// Errors are fixed text: the engine's messages can quote what it read.
var (
	errNixDBOpen  = errors.New("nix: store database unavailable")
	errNixDBQuery = errors.New("nix: store database query failed")
)

// nixDirectRefs reads the direct references of each root from the Nix store
// database, read-only and in one transaction so every root sees one state.
// A root missing from the result is not registered in the store. At most
// maxNixRefs+1 references are returned per root so the caller can tell a cut.
func nixDirectRefs(ctx context.Context, files executor.Executor, roots []string) (map[string][]string, error) {
	// Open the path the guarded resolution returned, never a second string.
	resolved, err := files.EvalSymlinks(nixDBPath)
	if err != nil {
		return nil, errNixDBOpen
	}
	dsn := url.URL{Scheme: "file", Path: resolved,
		RawQuery: "mode=ro&_pragma=busy_timeout(2000)&_pragma=query_only(1)&_pragma=trusted_schema(0)"}
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return nil, errNixDBOpen
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)

	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, errNixDBOpen
	}
	defer func() { _ = tx.Rollback() }()

	const query = `SELECT r.path FROM ValidPaths v JOIN Refs x ON x.referrer = v.id
		JOIN ValidPaths r ON r.id = x.reference WHERE v.path = ? ORDER BY r.path LIMIT ?`
	var exists int
	out := make(map[string][]string, len(roots))
	for _, root := range roots {
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM ValidPaths WHERE path = ?`, root).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
			continue
		} else if err != nil {
			return nil, errNixDBQuery
		}
		rows, err := tx.QueryContext(ctx, query, root, maxNixRefs+1)
		if err != nil {
			return nil, errNixDBQuery
		}
		refs := []string{}
		for rows.Next() {
			var p string
			if err := rows.Scan(&p); err != nil {
				_ = rows.Close()
				return nil, errNixDBQuery
			}
			refs = append(refs, p)
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return nil, errNixDBQuery
		}
		out[root] = refs
	}
	return out, nil
}

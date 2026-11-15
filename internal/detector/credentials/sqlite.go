package credentials

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
	"modernc.org/sqlite/vfs"

	"github.com/step-security/dev-machine-guard/internal/safepath"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// dbRow is one row a database query returned: a key naming what the row holds
// and the value holding it. Only the rows of fixed queries are ever kept.
type dbRow struct {
	Key   string
	Value string
}

// dbSpec is the one query a source runs against one kind of database. The
// table and columns are checked against the schema before it runs, so a
// database of another layout is reported rather than half read.
type dbSpec struct {
	table string
	key   string
	value string
	query string
	args  []any
	// optional reads a database without the table as holding no rows.
	optional bool
}

// Database read bounds. The query reads only the pages its lookup touches, so
// a large editor database stays within the byte budget; a value longer than
// the length limit fails the query rather than arriving in memory.
const (
	dbReadBudget  = 8 << 20 // 8 MiB across the database and its write-ahead log
	dbValueLimit  = 1 << 20 // 1 MiB
	dbRowLimit    = maxAICount
	sqliteMagic   = "SQLite format 3\x00"
	walSuffix     = "-wal"
	journalSuffix = "-journal"
	dbMainName    = "db"
)

var openCodeCredentials = dbSpec{
	table: "credential", key: "integration_id", value: "value",
	query: `SELECT integration_id, CAST(value AS TEXT) FROM credential LIMIT 10001`,
}

// openCodeMCPCredentials is the same read for the MCP sign-in status, where a
// database from before OpenCode kept credentials holds none to report.
var openCodeMCPCredentials = dbSpec{
	table: openCodeCredentials.table, key: openCodeCredentials.key, value: openCodeCredentials.value,
	query: openCodeCredentials.query, optional: true,
}

// openCodeVersion2 asks for the migration OpenCode 2 records in every database
// it opens. It imports the 1.x provider sign-ins and none of the MCP ones, so
// from then on OpenCode keeps MCP sign-ins only in the database. A database
// that 1.x still tracks with Drizzle's journal has no migration table.
var openCodeVersion2 = dbSpec{
	table: "migration", key: "id", value: "time_completed", optional: true,
	query: `SELECT id, CAST(time_completed AS TEXT) FROM migration WHERE id = ? LIMIT 1`,
	args:  []any{"20260805200742_import_legacy_credentials"},
}

// editorItems queries the editor key-value table. Keys are matched exactly or
// by a half-open range, which the table's key index answers without a scan.
func editorItems(query string, args ...any) dbSpec {
	return dbSpec{table: "ItemTable", key: "key", value: "value", query: query, args: args}
}

// dbSpecs maps each source that reads a database to its query.
var dbSpecs = map[string]dbSpec{
	sourceOpenCode:    openCodeCredentials,
	sourceOpenCodeMCP: openCodeCredentials,
	sourceCursor: editorItems(
		`SELECT key, CAST(value AS TEXT) FROM ItemTable WHERE key IN (?, ?, ?, ?, ?, ?, ?, ?) LIMIT 10001`,
		"cursorAuth/openAIKey", "cursorAuth/claudeKey", "cursorAuth/googleKey",
		"secret://cursorAuth/openAIKey", "secret://cursorAuth/claudeKey", "secret://cursorAuth/googleKey",
		"cursorAuth/accessToken", "cursorAuth/refreshToken",
	),
	sourceCursorMCP: editorItems(
		`SELECT key, CAST(value AS TEXT) FROM ItemTable WHERE key >= ? AND key < ? LIMIT 10001`,
		"mcpOAuth.secret.", "mcpOAuth.secret/",
	),
	sourceVSCodeMCP: editorItems(
		`SELECT key, CAST(value AS TEXT) FROM ItemTable WHERE key = ? LIMIT 10001`,
		"mcpInputs",
	),
}

// EditorItem is one row of a fixed key-value query.
type EditorItem struct{ Key, Value string }

// ReadEditorItems runs one fixed query against an editor ItemTable through the
// guarded read-only reader. On macOS the editors keep the database below the
// protected Library, so the guard admits that database and the two log names
// beside it, and nothing else there.
func ReadEditorItems(ctx context.Context, skipper *tcc.Skipper, home, dbPath, query string, args ...any) ([]EditorItem, error) {
	library := filepath.Join(home, "Library")
	var admitted []libraryPath
	if rest, ok := trimPathPrefix(dbPath, library); ok && rest != "" && !strings.Contains(rest, "*") {
		for _, name := range []string{rest, rest + walSuffix, rest + journalSuffix} {
			admitted = append(admitted, libraryPath{base: library, rel: strings.Split(filepath.ToSlash(name), "/")})
		}
	}
	rows, _, _, capped, err := readDB(ctx, safepath.New(home, consentGuard(skipper, admitted...)), dbPath, editorItems(query, args...))
	if err != nil {
		return nil, err
	}
	if capped {
		return nil, errDBBudget
	}
	items := make([]EditorItem, len(rows))
	for i, row := range rows {
		items[i] = EditorItem(row)
	}
	return items, nil
}

// OpenCodeMCPCredential is all the sign-in status needs from one OpenCode MCP
// credential row. No token value leaves this package.
type OpenCodeMCPCredential struct {
	IntegrationID string // the server's integration, which OpenCode derives from its name and URL
	ServerURL     string // the URL the server signed in at, after OpenCode substituted the config
	HasAccess     bool
	HasRefresh    bool
	ExpiresAt     *float64 // milliseconds; nil when the server gave the token no lifetime
}

// OpenCodeMCPStore is what OpenCode's databases hold for MCP sign-ins.
type OpenCodeMCPStore struct {
	Credentials []OpenCodeMCPCredential
	// Version2 is set when OpenCode 2 has opened a database. It no longer
	// reads the 1.x mcp-auth.json.
	Version2 bool
}

// ReadOpenCodeMCPCredentials finds OpenCode's databases the way the
// opencode_mcp source does, from the XDG_DATA_HOME and OPENCODE_DB values the
// caller passes, and reads their MCP credential rows through the guarded
// reader. The caller supplies the environment so no login shell is probed.
func ReadOpenCodeMCPCredentials(ctx context.Context, skipper *tcc.Skipper, home, xdgDataHome, openCodeDB string) (OpenCodeMCPStore, error) {
	i := slices.IndexFunc(sources, func(s source) bool { return s.ID == sourceOpenCodeMCP })
	paths := newUserPaths("", home, runtime.GOOS).withXDGData(xdgDataHome)
	resolver := safepath.New(home, consentGuard(skipper))
	seen := map[string]bool{}
	var out OpenCodeMCPStore
	for _, c := range candidatesFor(sources[i], paths, map[string]string{"OPENCODE_DB": openCodeDB}, runtime.GOOS) {
		if !c.SQLite {
			continue
		}
		dbs, err := listedDatabases(resolver, c)
		if err != nil {
			return OpenCodeMCPStore{}, err
		}
		for _, db := range dbs {
			if seen[db] {
				continue
			}
			seen[db] = true
			rows, _, _, capped, err := readDB(ctx, resolver, db, openCodeMCPCredentials)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return OpenCodeMCPStore{}, err
			}
			if capped {
				return OpenCodeMCPStore{}, errDBBudget
			}
			marker, _, _, capped, err := readDB(ctx, resolver, db, openCodeVersion2)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return OpenCodeMCPStore{}, err
			}
			if capped {
				return OpenCodeMCPStore{}, errDBBudget
			}
			out.Version2 = out.Version2 || len(marker) > 0
			for _, row := range rows {
				var v map[string]any
				if json.Unmarshal([]byte(row.Value), &v) != nil || !openCodeMCPRow(row.Key, v) {
					continue
				}
				meta, _ := v["metadata"].(map[string]any)
				serverURL, _ := meta["serverUrl"].(string)
				access, _ := v["access"].(string)
				refresh, _ := v["refresh"].(string)
				// OpenCode writes 0 for a token the server gave no lifetime.
				var expiresAt *float64
				if ms, ok := v["expires"].(float64); ok && ms != 0 {
					expiresAt = &ms
				}
				out.Credentials = append(out.Credentials, OpenCodeMCPCredential{IntegrationID: row.Key, ServerURL: serverURL, HasAccess: access != "", HasRefresh: refresh != "", ExpiresAt: expiresAt})
			}
		}
	}
	return out, nil
}

// listedDatabases expands a "*" in a catalog database name against one listing
// of its directory. Only the catalog's own part can hold a pattern; a path from
// the environment is taken as written. A listing past the cap is as incomplete
// as a read past the budget, so it fails the same way.
func listedDatabases(resolver *safepath.Resolver, c candidate) ([]string, error) {
	path := c.path()
	if !strings.Contains(c.Rel, "*") {
		return []string{path}, nil
	}
	dir, pattern := filepath.Split(path)
	names, _, more, err := resolver.ReadDirNames(dir, maxKeyDirEntries)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if more {
		return nil, errDBBudget
	}
	slices.Sort(names)
	var out []string
	for _, name := range names {
		if matched, _ := filepath.Match(pattern, name); matched && listedName(name) {
			out = append(out, filepath.Join(dir, name))
		}
	}
	return out, nil
}

// readDB runs a source's fixed query against a database without ever handing
// SQLite a path. The database and its write-ahead log are opened through the
// guarded resolver and held; SQLite sees only a read-only file system with two
// fixed names backed by those handles, so it can neither reach another file nor
// write a journal or shared-memory file beside the developer's database. A
// rollback journal beside it means a write is in progress, and a database or
// log that changes during the read is discarded rather than reported.
func readDB(ctx context.Context, r *safepath.Resolver, path string, spec dbSpec) (rows []dbRow, resolved string, info os.FileInfo, capped bool, err error) {
	main, resolved, info, err := r.OpenReadOnly(path)
	if err != nil {
		return nil, "", nil, false, err
	}
	defer main.Close()
	if info.IsDir() {
		return nil, resolved, info, false, nil
	}
	if !sqliteHeader(main) {
		return nil, "", nil, false, errUnrecognizedFormat
	}
	if _, _, err := r.Stat(path + journalSuffix); !errors.Is(err, fs.ErrNotExist) {
		return nil, "", nil, false, errUnrecognizedFormat
	}
	wal, _, walInfo, err := r.OpenReadOnly(path + walSuffix)
	switch {
	case err == nil:
		defer wal.Close()
	case errors.Is(err, fs.ErrNotExist):
		wal = nil
	default:
		return nil, "", nil, false, err
	}

	budget := int64(dbReadBudget)
	files := heldFiles{dbMainName: {f: main, info: info, budget: &budget}}
	if wal != nil {
		files[dbMainName+walSuffix] = heldFile{f: wal, info: walInfo, budget: &budget}
	}
	rows, capped, err = queryHeld(ctx, files, wal != nil, spec)
	if budget <= 0 {
		capped, err = true, nil
	}
	if err != nil {
		return nil, "", nil, false, err
	}
	if drifted(r, path, main, info, wal, walInfo) {
		return nil, "", nil, false, errUnrecognizedFormat
	}
	return rows, resolved, info, capped, nil
}

// sqliteHeader reports whether a file starts with the database format's magic
// string, so nothing else is handed to the engine.
func sqliteHeader(f *os.File) bool {
	head := make([]byte, len(sqliteMagic))
	n, _ := f.ReadAt(head, 0)
	return n == len(head) && bytes.Equal(head, []byte(sqliteMagic))
}

// drifted reports whether the database or its log changed while it was read,
// whether either name now leads to another file, or whether a journal or a log
// appeared beside it.
func drifted(r *safepath.Resolver, path string, main *os.File, info os.FileInfo, wal *os.File, walInfo os.FileInfo) bool {
	if replaced(r, path, main, info) || (wal != nil && replaced(r, path+walSuffix, wal, walInfo)) {
		return true
	}
	if _, _, err := r.Stat(path + journalSuffix); !errors.Is(err, fs.ErrNotExist) {
		return true
	}
	if wal != nil {
		return false
	}
	_, _, err := r.Stat(path + walSuffix)
	return !errors.Is(err, fs.ErrNotExist)
}

// replaced reports whether a held file's size or modification time moved, or
// its name no longer resolves to it: a file renamed over the name leaves the
// held handle reading the old one unchanged.
func replaced(r *safepath.Resolver, path string, f *os.File, before os.FileInfo) bool {
	after, err := f.Stat()
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return true
	}
	_, named, err := r.Stat(path)
	return err != nil || !os.SameFile(before, named)
}

// queryHeld opens the held files through a private virtual file system and
// runs the query. Every error is reduced to a reason: the engine's messages can
// quote the data it choked on.
func queryHeld(ctx context.Context, files heldFiles, hasWAL bool, spec dbSpec) (rows []dbRow, capped bool, err error) {
	name, fsys, err := vfs.New(files)
	if err != nil {
		return nil, false, errUnrecognizedFormat
	}
	defer fsys.Close()

	// Without a log the database is read as immutable, so the engine takes no
	// locks. With one, exclusive locking lets the log be read without the
	// shared-memory file the virtual file system does not provide.
	dsn := "file:" + dbMainName + "?vfs=" + name + "&mode=ro&_pragma=trusted_schema(OFF)&_pragma=temp_store(MEMORY)"
	if hasWAL {
		dsn += "&_pragma=locking_mode(EXCLUSIVE)"
	} else {
		dsn += "&immutable=1"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, false, errUnrecognizedFormat
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, false, dbError(ctx)
	}
	defer conn.Close()
	if _, err := sqlite.Limit(conn, sqlite3.SQLITE_LIMIT_LENGTH, dbValueLimit); err != nil {
		return nil, false, errUnrecognizedFormat
	}
	if ok, missing := hasSchema(ctx, conn, spec); !ok {
		if missing && spec.optional {
			return nil, false, nil
		}
		return nil, false, errUnrecognizedFormat
	}

	result, err := conn.QueryContext(ctx, spec.query, spec.args...)
	if err != nil {
		return nil, false, dbError(ctx)
	}
	defer result.Close()
	for result.Next() {
		if len(rows) == dbRowLimit {
			return rows, true, nil
		}
		var key, value sql.NullString
		if err := result.Scan(&key, &value); err != nil {
			return nil, false, errUnrecognizedFormat
		}
		rows = append(rows, dbRow{Key: key.String, Value: value.String})
	}
	if err := result.Err(); err != nil {
		var e *sqlite.Error
		if errors.As(err, &e) && e.Code()&0xff == sqlite3.SQLITE_TOOBIG {
			return rows, true, nil
		}
		return nil, false, dbError(ctx)
	}
	return rows, false, nil
}

// hasSchema reports whether the database has the query's table as a real table
// with both of its columns, so a view or a renamed column cannot stand in.
// missing is set when nothing in the database has the table's name.
func hasSchema(ctx context.Context, conn *sql.Conn, spec dbSpec) (ok, missing bool) {
	var kind string
	err := conn.QueryRowContext(ctx, `SELECT type FROM pragma_table_list WHERE schema = 'main' AND name = ?`, spec.table).Scan(&kind)
	if err != nil || kind != "table" {
		return false, errors.Is(err, sql.ErrNoRows)
	}
	columns, err := conn.QueryContext(ctx, `SELECT name FROM pragma_table_xinfo(?)`, spec.table)
	if err != nil {
		return false, false
	}
	defer columns.Close()
	found := 0
	for columns.Next() {
		var column string
		if columns.Scan(&column) == nil && (column == spec.key || column == spec.value) {
			found++
		}
	}
	return columns.Err() == nil && found == 2, false
}

// dbError reduces a query failure to a reason: the run's deadline when that is
// what stopped it, and otherwise a database this build cannot read.
func dbError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errUnrecognizedFormat
}

// heldFiles is the file system SQLite is given: the fixed names of the held
// handles and nothing else.
type heldFiles map[string]heldFile

// heldFile is one held handle and the budget its reads draw from.
type heldFile struct {
	f      *os.File
	info   os.FileInfo
	budget *int64
}

// Open returns an independent view of a held handle, so the engine's seeks
// never move another reader. Any other name does not exist.
func (h heldFiles) Open(name string) (fs.File, error) {
	held, ok := h[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return &dbView{SectionReader: io.NewSectionReader(held.f, 0, held.info.Size()), held: held}, nil
}

// dbView is the engine's view of one held file.
type dbView struct {
	*io.SectionReader
	held heldFile
}

// errDBBudget stops a read past the shared byte budget.
var errDBBudget = errors.New("database read budget exhausted")

// Read draws from the shared budget, failing once it is spent so a query that
// would read the whole of a large database stops instead.
func (v *dbView) Read(p []byte) (int, error) {
	if int64(len(p)) > *v.held.budget {
		*v.held.budget = 0
		return 0, errDBBudget
	}
	n, err := v.SectionReader.Read(p)
	*v.held.budget -= int64(n)
	return n, err
}

// Stat reports the size the view was opened with.
func (v *dbView) Stat() (fs.FileInfo, error) { return v.held.info, nil }

// Close leaves the held handle open: readDB owns it and checks it for change
// after the query.
func (v *dbView) Close() error { return nil }

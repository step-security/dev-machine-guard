package devicepolicy

// Writer reads, upserts, and removes the `extensions.allowed` key in the
// user-scope VS Code settings.json. It is a thin primitive: it manages ONLY
// that one top-level key — every other key, comment, and formatting detail in
// the file is preserved (single-key JSONC merge), which is what makes editing
// a file the user also owns safe. Ownership and drift decisions (whether the
// agent may overwrite or remove) live in the reconciler, not here, so the
// writer stays pure and fake-testable.
//
// Values are compact JSON object strings — the backend's compiled
// extensions.allowed object, compacted. Read returns the on-disk value
// re-compacted, so equality against a recorded written value is canonical
// regardless of how the file is formatted on disk.
//
// The production implementation is settingsWriter (settings_writer.go); the
// reconciler is exercised against fakes.
type Writer interface {
	// Read returns the current extensions.allowed value (compacted) and
	// whether it is present. (present=false, err=nil) means the file is
	// missing or readable-but-without-the-key. An unparseable settings.json
	// is an error — the writer refuses to reason about a file it cannot
	// understand.
	Read() (value string, present bool, err error)

	// Write upserts extensions.allowed to value, then reads it back and
	// returns the read-back value. The reconciler compares it to value to
	// detect a silent non-apply (policy_not_applied). An error means the
	// write itself failed or the file is unsalvageable → write_failed.
	Write(value string) (readback string, err error)

	// Clear removes the extensions.allowed key, leaving the rest of the file
	// (and the file itself) intact. A missing file or absent key is a no-op.
	Clear() error

	// Location is a human-readable description of the target, for logs.
	Location() string
}

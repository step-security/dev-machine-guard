package rules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// Default cap values (all hard-bounded). See Caps.
const (
	defaultMaxFiles        = 50000            // total candidate files evaluated across all rules
	defaultMaxMatchPerRule = 200              // per-rule file-match cap
	defaultPerRunBudget    = 10 * time.Minute // overall scan deadline
)

// Caps bounds the cost of a scan. Zero/negative fields are replaced with the
// defaults by NewEngine.
type Caps struct {
	MaxFileSize       int64         // hard cap 8 MiB; a rule's max_file_size is clamped to this
	MaxFiles          int           // total candidate files evaluated across all rules
	MaxMatchesPerRule int           // per-rule file-match cap; overflow ⇒ truncated + incomplete
	PerRunBudget      time.Duration // overall scan deadline (also honors the passed ctx)
}

// DefaultCaps returns the production cap set.
func DefaultCaps() Caps {
	return Caps{
		MaxFileSize:       hardMaxFileSize,
		MaxFiles:          defaultMaxFiles,
		MaxMatchesPerRule: defaultMaxMatchPerRule,
		PerRunBudget:      defaultPerRunBudget,
	}
}

// Engine evaluates a RuleSet against a machine. It does no I/O of its own
// beyond the executor it is handed and the directory walk, which makes Scan
// fully drivable from a temp dir of fixtures with no backend or network.
type Engine struct {
	exec    executor.Executor
	skipper *tcc.Skipper
	caps    Caps
	log     *progress.Logger
}

// NewEngine builds an Engine, clamping caps to safe bounds.
func NewEngine(exec executor.Executor, skipper *tcc.Skipper, caps Caps, log *progress.Logger) *Engine {
	if caps.MaxFileSize <= 0 || caps.MaxFileSize > hardMaxFileSize {
		caps.MaxFileSize = hardMaxFileSize
	}
	if caps.MaxFiles <= 0 {
		caps.MaxFiles = defaultMaxFiles
	}
	if caps.MaxMatchesPerRule <= 0 {
		caps.MaxMatchesPerRule = defaultMaxMatchPerRule
	}
	if caps.PerRunBudget <= 0 {
		caps.PerRunBudget = defaultPerRunBudget
	}
	if log == nil {
		log = progress.NewNoop()
	}
	return &Engine{exec: exec, skipper: skipper, caps: caps, log: log}
}

// ruleState accumulates one rule's matches during a scan.
type ruleState struct {
	rule      *Rule
	matches   []model.RuleFileMatch
	seen      map[string]bool // dedupe candidate paths per rule
	truncated bool            // hit MaxMatchesPerRule
}

// scanState is the mutable bookkeeping shared across the absolute-resolution
// pass and the directory walk within one Scan.
type scanState struct {
	states       []*ruleState
	cache        *fileCache
	filesScanned int
	globalStop   bool // a global file/time budget cut the scan short ⇒ ScanComplete=false
}

// Scan evaluates rs against searchDirs and returns the result object. It
// never fails: unreadable/vanished files are skipped; hitting a global file or
// time budget sets ScanComplete=false (suppressing backend auto-resolution),
// and a rule hitting its per-rule cap is marked truncated/incomplete.
func (e *Engine) Scan(ctx context.Context, rs RuleSet, searchDirs []string) model.RuleScan {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, e.caps.PerRunBudget)
	defer cancel()

	st := &scanState{cache: newFileCache()}
	st.states = make([]*ruleState, len(rs.Rules))
	for i := range rs.Rules {
		st.states[i] = &ruleState{rule: &rs.Rules[i], seen: make(map[string]bool)}
	}

	// Absolute globs name exact paths — resolve them directly (no walk needed).
	e.resolveAbsolute(ctx, st)

	// Relative globs are matched against paths relative to each search root
	// during a single TCC-aware walk per root.
	if !st.globalStop {
		e.walkRoots(ctx, st, searchDirs)
	}

	if st.globalStop {
		e.log.Warn("malicious_file_scan: hit per-run budget/file cap — scan_complete=false; auto-resolution suppressed")
	}

	res := model.RuleScan{ScanComplete: !st.globalStop}
	matchedRules, matchedFiles, incompleteRules := 0, 0, 0
	for _, rstate := range st.states {
		complete := res.ScanComplete && !rstate.truncated
		if !complete {
			incompleteRules++
		}
		res.EvaluatedRules = append(res.EvaluatedRules, model.EvaluatedRule{
			RuleID:       rstate.rule.ID,
			RuleRevision: rstate.rule.Revision,
			Complete:     complete,
		})
		if len(rstate.matches) > 0 {
			matchedRules++
			matchedFiles += len(rstate.matches)
			res.Results = append(res.Results, model.RuleResult{
				RuleID:           rstate.rule.ID,
				RuleRevision:     rstate.rule.Revision,
				MatchesTruncated: rstate.truncated,
				Files:            rstate.matches,
			})
			e.log.Debug("malicious_file_scan: rule %q matched %d files (complete=%v truncated=%v)",
				rstate.rule.ID, len(rstate.matches), complete, rstate.truncated)
		}
	}

	e.log.Debug("malicious_file_scan: done scan_complete=%v rules_evaluated=%d rules_matched=%d files_matched=%d files_scanned=%d incomplete_rules=%d elapsed=%s",
		res.ScanComplete, len(res.EvaluatedRules), matchedRules, matchedFiles, st.filesScanned, incompleteRules, time.Since(start))

	return res
}

// evaluate reads and evaluates one candidate file for one rule, appending a
// RuleFileMatch unless the rule's per-rule cap is hit. It returns true only
// when a GLOBAL file budget was exhausted, signalling the caller to stop the
// whole scan (and mark ScanComplete=false).
func (e *Engine) evaluate(st *scanState, rstate *ruleState, path, matchedGlob string) (globalStop bool) {
	if rstate.seen[path] {
		return false
	}
	rstate.seen[path] = true

	if len(rstate.matches) >= e.caps.MaxMatchesPerRule {
		rstate.truncated = true
		return false
	}
	if st.filesScanned >= e.caps.MaxFiles {
		return true
	}
	st.filesScanned++

	info, err := e.exec.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}

	fm := model.RuleFileMatch{
		Path:        path,
		MatchedGlob: matchedGlob,
		FileAttrs:   fileAttrs(info),
	}

	// Size guard: a file larger than the (clamped) rule limit is reported but
	// not read — no hash, no condition evaluation.
	limit := e.caps.MaxFileSize
	if rstate.rule.MaxFileSize > 0 && rstate.rule.MaxFileSize < limit {
		limit = rstate.rule.MaxFileSize
	}
	if info.Size() > limit {
		fm.SizeExceeded = true
		rstate.matches = append(rstate.matches, fm)
		return false
	}

	data, hash, ok := st.cache.read(e.exec, path)
	if !ok {
		// Unreadable: still report existence + metadata, no content-derived fields.
		rstate.matches = append(rstate.matches, fm)
		return false
	}
	fm.FileSHA256 = hash
	// A rule with no groups is existence-only: any matched file is reported.
	// Otherwise the file is reported only if at least one group is satisfied
	// (all its mandatory conditions matched) — so a rule targeting a file that
	// legitimately exists won't flag it unless its required indicators are present.
	reported := len(rstate.rule.Groups) == 0
	for _, g := range rstate.rule.Groups {
		gr, satisfied := evalGroup(g, data, hash)
		fm.Groups = append(fm.Groups, gr)
		if satisfied {
			reported = true
		}
	}
	if !reported {
		return false // mandatory conditions unmet in every group — not a finding
	}
	rstate.matches = append(rstate.matches, fm)
	return false
}

// fileCache memoizes the bytes + whole-file SHA-256 of the single file
// currently being processed. Every rule whose globs match a given path is
// evaluated consecutively (within one WalkDir callback, or one resolveAbsolute
// path), so a file matched by several rules is still read and hashed only once.
// As soon as processing moves to a new path, the previous file's bytes are
// released — bounding peak memory to one file (<= MaxFileSize) instead of
// retaining every matched file's bytes for the whole scan.
type fileCache struct {
	path   string
	data   []byte
	hash   string
	ok     bool
	loaded bool // path/data/hash/ok are populated for the current path
}

func newFileCache() *fileCache { return &fileCache{} }

func (fc *fileCache) read(exec executor.Executor, path string) (data []byte, hash string, ok bool) {
	if fc.loaded && fc.path == path {
		return fc.data, fc.hash, fc.ok
	}
	b, err := exec.ReadFile(path)
	if err != nil {
		// Cache the failure for this path (a sibling rule matching the same file
		// must not re-attempt the read) while releasing any prior file's bytes.
		*fc = fileCache{path: path, loaded: true}
		return nil, "", false
	}
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	*fc = fileCache{path: path, data: b, hash: h, ok: true, loaded: true}
	return b, h, true
}

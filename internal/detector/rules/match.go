package rules

import (
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// evalCondition evaluates one condition against a file's bytes and precomputed
// whole-file SHA-256, returning only a boolean (Negate applied). No matched
// text is ever captured. An unknown kind (rejected by Prepare) yields false.
func evalCondition(c Condition, data []byte, fileHash string) bool {
	var matched bool
	switch c.Kind {
	case condKindRegex:
		matched = c.re != nil && c.re.Match(data)
	case condKindSHA256:
		matched = strings.EqualFold(fileHash, c.Pattern)
	}
	if c.Negate {
		return !matched
	}
	return matched
}

// evalGroup evaluates every condition in a group and reports each by id.
// FullMatch is true only when all conditions matched. The second return value,
// satisfied, is true when all MANDATORY conditions matched (a group with no
// mandatory conditions is always satisfied); it gates whether the file is
// reported at all.
func evalGroup(g ConditionGroup, data []byte, fileHash string) (model.GroupResult, bool) {
	res := model.GroupResult{GroupID: g.ID, FullMatch: true}
	satisfied := true
	for _, c := range g.Conditions {
		m := evalCondition(c, data, fileHash)
		if !m {
			res.FullMatch = false
			if c.Mandatory {
				satisfied = false
			}
		}
		res.Conditions = append(res.Conditions, model.ConditionResult{
			ID:      c.ID,
			Kind:    c.Kind,
			Matched: m,
		})
	}
	return res, satisfied
}

package updatestate

// validRunOwner reports whether s can name a run file's owner: a SID
// (S-1-5-21-…) or a uid, so letters, digits and '-' only.
func validRunOwner(s string) bool {
	if s == "" || len(s) > 184 {
		return false
	}
	for _, c := range s {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

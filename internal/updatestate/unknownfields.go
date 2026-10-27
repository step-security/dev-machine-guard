package updatestate

import (
	"encoding/json"
	"reflect"
	"strings"
)

// State objects keep JSON keys they don't know in Extra and write them back
// verbatim, so an older updater (the one that runs during every probation)
// never erases fields a newer one added (R-F1-2, frozen read contract).

func (s *State) UnmarshalJSON(b []byte) error {
	type plain State
	return decodeKeepingUnknown(b, (*plain)(s), &s.Extra)
}

func (s State) MarshalJSON() ([]byte, error) {
	type plain State
	return encodeKeepingUnknown(plain(s), s.Extra)
}

func (p *Probation) UnmarshalJSON(b []byte) error {
	type plain Probation
	return decodeKeepingUnknown(b, (*plain)(p), &p.Extra)
}

func (p Probation) MarshalJSON() ([]byte, error) {
	type plain Probation
	return encodeKeepingUnknown(plain(p), p.Extra)
}

func (q *Quarantine) UnmarshalJSON(b []byte) error {
	type plain Quarantine
	return decodeKeepingUnknown(b, (*plain)(q), &q.Extra)
}

func (q Quarantine) MarshalJSON() ([]byte, error) {
	type plain Quarantine
	return encodeKeepingUnknown(plain(q), q.Extra)
}

func (u *Updater) UnmarshalJSON(b []byte) error {
	type plain Updater
	return decodeKeepingUnknown(b, (*plain)(u), &u.Extra)
}

func (u Updater) MarshalJSON() ([]byte, error) {
	type plain Updater
	return encodeKeepingUnknown(plain(u), u.Extra)
}

func (o *OutboxEvent) UnmarshalJSON(b []byte) error {
	type plain OutboxEvent
	return decodeKeepingUnknown(b, (*plain)(o), &o.Extra)
}

func (o OutboxEvent) MarshalJSON() ([]byte, error) {
	type plain OutboxEvent
	return encodeKeepingUnknown(plain(o), o.Extra)
}

// decodeKeepingUnknown decodes b into dst (a struct pointer) and stores the
// keys no field claims in *extra. Matching is case-insensitive, as in
// encoding/json.
func decodeKeepingUnknown(b []byte, dst any, extra *map[string]json.RawMessage) error {
	if err := json.Unmarshal(b, dst); err != nil {
		return err
	}
	*extra = nil
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil || raw == nil {
		return nil
	}
	known := jsonFieldNames(reflect.TypeOf(dst).Elem())
	for k := range raw {
		for _, f := range known {
			if strings.EqualFold(k, f) {
				delete(raw, k)
				break
			}
		}
	}
	if len(raw) > 0 {
		*extra = raw
	}
	return nil
}

// encodeKeepingUnknown marshals v and adds the extra keys it doesn't emit.
func encodeKeepingUnknown(v any, extra map[string]json.RawMessage) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil || len(extra) == 0 {
		return b, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	for k, raw := range extra {
		if _, ok := m[k]; !ok {
			m[k] = raw
		}
	}
	return json.Marshal(m)
}

// jsonFieldNames lists the JSON keys of a struct type's fields.
func jsonFieldNames(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" || !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "" {
			name = f.Name
		}
		out = append(out, name)
	}
	return out
}

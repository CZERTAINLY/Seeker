package model

import (
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	cue "cuelang.org/go/cue"
	cueerrors "cuelang.org/go/cue/errors"
)

type CueErrorDetail struct {
	Path    string // service.repository.auth.token
	Code    string // missing_required | empty_required | unknown_field | type_mismatch | conflict | invalid_enum ...
	Message string // Human text
	Pos     CueErrorPosition
	Raw     string // original message
}

func (c CueErrorDetail) Attr(name string) slog.Attr {
	return slog.GroupAttrs(
		name,
		slog.String("code", c.Code),
		slog.String("path", c.Path),
		slog.String("message", c.Message),
		slog.String("file", c.Pos.Filename),
		slog.Int("line", c.Pos.Line),
		slog.Int("column", c.Pos.Column),
	)
}

type CueErrorPosition struct {
	Filename string
	Line     int
	Column   int
}

var (
	reIncomplete  = regexp.MustCompile(`(?i)incomplete value`)
	reNotAllowed  = regexp.MustCompile(`(?i)not allowed|unknown field`)
	reConflict    = regexp.MustCompile(`(?i)conflicting values|cannot unify|incompatible`)
	reExpectedGot = regexp.MustCompile(`(?i)expected .* got .*`)
	reEnum        = regexp.MustCompile(`(?i)must be one of|expected one of`)
)

func humanize(err error, root cue.Value) []CueErrorDetail {
	if err == nil {
		return nil
	}

	seen := make(map[CueErrorPosition]struct{})

	var out []CueErrorDetail
	for _, e := range cueerrors.Errors(err) {
		raw, _ := e.Msg()
		path := normalizePath(e.Path())
		code, msg := classify(raw, path, root)

		pos := position(e)
		if pos.Filename == "" {
			continue
		}
		if _, ok := seen[pos]; ok {
			continue
		}

		if path == "service.mode" {
			serviceMode := schema.LookupPath(cue.ParsePath("service.mode"))
			values, dflt := enumStrings(serviceMode)
			msg += fmt.Sprintf(": possible values (%s)", strings.Join(values, ","))
			if dflt != nil {
				msg += fmt.Sprintf(" (default %s)", *dflt)
			}
			msg += ": got " + valueToString(serviceMode)
		}

		out = append(out, CueErrorDetail{
			Path:    path,
			Code:    code,
			Message: msg,
			Pos:     position(e),
			Raw:     err.Error(),
		})
		seen[pos] = struct{}{}
	}
	return out
}

func valueToString(v cue.Value) string {
	s, err := valueToStringE(v)
	if err != nil {
		return "E: " + err.Error()
	}
	return s
}

func valueToStringE(v cue.Value) (string, error) {
	switch v.Kind() {
	case cue.StringKind:
		return v.String()
	case cue.IntKind:
		i, err := v.Int64()
		if err != nil {
			return "", err
		}
		return strconv.FormatInt(i, 10), nil
	case cue.FloatKind:
		f, err := v.Float64()
		if err != nil {
			return "", err
		}
		return strconv.FormatFloat(f, 'g', -1, 64), nil
	case cue.BoolKind:
		b, err := v.Bool()
		if err != nil {
			return "", err
		}
		return strconv.FormatBool(b), nil
	default:
		// Fallback: CUE syntax form
		b, err := v.MarshalJSON()
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
}

func enumStrings(v cue.Value) (values []string, def *string) {
	// Get default (if any)
	if d, ok := v.Default(); ok {
		if s, err := d.String(); err == nil {
			ss := s
			def = &ss
		}
	}
	// Detect disjunction
	if op, args := v.Expr(); op == cue.OrOp {
		seen := map[string]struct{}{}
		for _, a := range args {
			if a.Kind() != cue.StringKind {
				continue
			}
			if s, err := a.String(); err == nil {
				if _, ok := seen[s]; !ok {
					seen[s] = struct{}{}
					values = append(values, s)
				}
			}
		}
	} else if v.Kind() == cue.StringKind {
		// Single fixed value
		if s, err := v.String(); err == nil {
			values = append(values, s)
		}
	}
	return
}

func position(err cueerrors.Error) CueErrorPosition {
	for _, r := range cueerrors.Positions(err) {
		if r.Filename() == "" {
			continue
		}
		pos := CueErrorPosition{
			Filename: r.Filename(),
			Line:     r.Line(),
			Column:   r.Column(),
		}
		return pos
	}
	var zero CueErrorPosition
	return zero
}

func normalizePath(p []string) string {
	if len(p) == 0 {
		return ""
	}
	// Remove leading definition (#Config)
	if strings.HasPrefix(p[0], "#") {
		p = p[1:]
	}
	return strings.Join(p, ".")
}

func classify(raw, path string, root cue.Value) (code, msg string) {
	switch {
	case reNotAllowed.MatchString(raw):
		return "unknown_field", fmt.Sprintf("Field %s is not allowed", last(path))
	case reIncomplete.MatchString(raw):
		// Determine if conditional required + non-empty
		if looksNonEmptyConditional(path, root) {
			return "missing_required", fmt.Sprintf("Field %s is required and must be non-empty", last(path))
		}
		return "missing_required", fmt.Sprintf("Field %s is required", last(path))
	case reConflict.MatchString(raw):
		return "conflicting_values", fmt.Sprintf("Conflicting values for %s", last(path))
	case reEnum.MatchString(raw):
		return "invalid_enum", fmt.Sprintf("Field %s has invalid value", last(path))
	case reExpectedGot.MatchString(raw):
		return "type_mismatch", fmt.Sprintf("Field %s has wrong type/value", last(path))
	default:
		return "validation_error", raw
	}
}

func looksNonEmptyConditional(path string, root cue.Value) bool {
	if path == "" {
		return false
	}
	v := lookup(root, path)
	if !v.Exists() {
		return false
	}
	// Inspect definition text (rough heuristic; CUE API doesn’t expose full constraint list easily)
	// If you can obtain source, you could parse; here we just check if & !="" appears in error chain.
	//for i := 0; i < v.Len(); i++ {
	// skip; simple heuristic removed for brevity
	//}
	// Instead rely on raw path presence; refine if needed.
	return true
}

func lookup(root cue.Value, path string) cue.Value {
	if path == "" {
		return root
	}
	pp := cue.ParsePath(path)
	return root.LookupPath(pp)
}

func last(p string) string {
	if p == "" {
		return p
	}
	if i := strings.LastIndexByte(p, '.'); i >= 0 {
		return p[i+1:]
	}
	return p
}

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

type CueErrorCode string

const (
	CodeUnknownField      CueErrorCode = "unknown_field"
	CodeMissingRequired   CueErrorCode = "missing_required"
	CodeConflictingValues CueErrorCode = "conflicting_values"
	CodeInvalidEnum       CueErrorCode = "invalid_enum"
	CodeTypeMismatch      CueErrorCode = "type_mismatch"
	CodeValidationError   CueErrorCode = "validation_error"
)

type CueErrorDetail struct {
	Path    string
	Code    CueErrorCode
	Message string
	Pos     CueErrorPosition
	Raw     string // original message
}

func (c CueErrorDetail) Attr(name string) slog.Attr {
	return slog.GroupAttrs(
		name,
		slog.String("code", string(c.Code)),
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
	reIncomplete         = regexp.MustCompile(`(?i)incomplete value`)
	reNotAllowed         = regexp.MustCompile(`(?i)not allowed|unknown field`)
	reConflict           = regexp.MustCompile(`(?i)conflicting values|cannot unify|incompatible`)
	reExpectedGot        = regexp.MustCompile(`(?i)expected .* got .*`)
	reEnum               = regexp.MustCompile(`(?i)must be one of|expected one of`)
	reInvalidValueBounds = regexp.MustCompile(`(?i)invalid value %v \(out of bound %s`)
)

func humanize(err error, config cue.Value) []CueErrorDetail {
	if err == nil {
		return nil
	}

	seen := make(map[CueErrorPosition]struct{})

	var out []CueErrorDetail
	cuerrs := cueerrors.Errors(err)
	for _, e := range cuerrs {
		raw, args := e.Msg()
		path := normalizePath(e.Path())
		code, msg := classify(raw, args, path, config)

		pos := position(e)
		if pos.Filename == "" && len(cuerrs) > 1 {
			continue
		}
		if _, ok := seen[pos]; ok {
			continue
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

func lookup(schema cue.Value, path string) cue.Value {
	// Traverse a dotted path resolving optional/definition fields at every segment.
	if path == "" {
		return schema
	}

	parent, label := splitPath(path)

	// Resolve the parent chain first (ensures optional ancestors are reached via iteration).
	base := schema
	if parent != "" {
		base = lookup(schema, parent)
	}
	if !base.Exists() || base.Err() != nil {
		return base
	}

	// First try direct lookup (works if field is concrete / already materialized).
	if direct := base.LookupPath(cue.ParsePath(label)); direct.Exists() && direct.Err() == nil {
		return direct
	}

	// Fallback: iterate including optional and definition fields.
	it, _ := base.Fields(cue.Optional(true), cue.Definitions(true), cue.Hidden(true))
	for it.Next() {
		if it.Selector().Unquoted() == label {
			return it.Value()
		}
	}

	// Return (possibly non-existent) direct result for consistent bottom signaling.
	return base.LookupPath(cue.ParsePath(label))
}

func splitPath(p string) (parent, last string) {
	if p == "" {
		return "", ""
	}
	i := strings.LastIndexByte(p, '.')
	if i < 0 {
		return "", p
	}
	return p[:i], p[i+1:]
}

func valueToString(v cue.Value) string {
	if !v.Exists() {
		return "<non-existent>"
	}
	if v.Err() != nil {
		return "<invalid>"
	}
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

func enumerate(v cue.Value) (values []string, def *string) {
	// Get default (if any)
	if d, ok := v.Default(); ok {
		s := valueToString(d)
		def = &s
	}
	// Detect disjunction
	if op, args := v.Expr(); op == cue.OrOp {
		seen := map[string]struct{}{}
		for _, a := range args {
			s := valueToString(a)
			if _, ok := seen[s]; !ok {
				seen[s] = struct{}{}
				values = append(values, s)
			}
		}
	} else {
		s := valueToString(v)
		values = append(values, s)
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

func classify(raw string, args []any, path string, config cue.Value) (code CueErrorCode, msg string) {
	switch {
	case reNotAllowed.MatchString(raw):
		return CodeUnknownField, fmt.Sprintf("Field %s is not allowed", last(path))
	case reIncomplete.MatchString(raw):
		// Determine if conditional required + non-empty
		if looksNonEmptyConditional(path, config) {
			return CodeMissingRequired, fmt.Sprintf("Field %s is required and must be non-empty", last(path))
		}
		return CodeMissingRequired, fmt.Sprintf("Field %s is required", last(path))
	case reConflict.MatchString(raw):
		return furtherClassify(CodeConflictingValues, raw, args, path, config)
	case reEnum.MatchString(raw):
		return CodeInvalidEnum, fmt.Sprintf("Field %s has invalid value", last(path))
	case reExpectedGot.MatchString(raw):
		return CodeTypeMismatch, fmt.Sprintf("Field %s has wrong type/value", last(path))
	case reInvalidValueBounds.MatchString(raw):
		return furtherClassify(CodeValidationError, raw, args, path, config)
	default:
		return CodeValidationError, raw
	}
}

func furtherClassify(in CueErrorCode, raw string, args []any, path string, config cue.Value) (code CueErrorCode, msg string) {
	asStr := func(x any) string {
		return fmt.Sprintf("%s", x)
	}
	code = in
	msg = fmt.Sprintf(raw, args...)
	validMsg := false
	switch len(args) {
	case 2:
		s1, s2 := asStr(args[0]), asStr(args[1])
		switch {
		case s1 == `""` && s2 == `!=""`:
			msg = "value must not be empty"
			validMsg = true
		case s2 == `=~"^https?://.+"`:
			msg = "value must be a valid http(s) URL"
			validMsg = true
		}
	case 4:
		s3, s4 := asStr(args[2]), asStr(args[3])
		if strings.Contains(raw, "mismatched types") {
			msg = fmt.Sprintf("expected type %s: got %s", s4, s3)
			validMsg = true
		}
	}
	switch code {
	case CodeValidationError:
		msg = fmt.Sprintf("Field %s is invalid: %s", last(path), msg)
	case CodeConflictingValues:
		if !validMsg {
			msg = enumPossibilitiesOnConflict(path, config)
		}
		msg = fmt.Sprintf("Conflicting values for %s: %s", last(path), msg)
	}
	return
}

func enumPossibilitiesOnConflict(path string, config cue.Value) (msg string) {
	cueValue := lookup(schema, path)
	values, dflt := enumerate(cueValue)
	msg = fmt.Sprintf("possible values (%s)", strings.Join(values, ","))
	if dflt != nil {
		msg += fmt.Sprintf(" (default %s)", *dflt)
	}
	msg += ": got " + valueToString(config.LookupPath(cue.ParsePath(path)))
	return
}

func looksNonEmptyConditional(path string, root cue.Value) bool {
	if path == "" {
		return false
	}
	v := lookup(root, path)
	return v.Exists()
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

package service

import (
	"fmt"
	"strings"

	"github.com/robfig/cron/v3"
)

// ParseFlexible parses a cron expression that may have 5 or 6 time fields (seconds optional).
// Returns the compiled cron.Schedule, number of time fields used (5 or 6), or error.
// Supports macros (@every, @hourly, etc.).
func ParseFlexible(expr string) (int, error) {
	e := strings.TrimSpace(expr)
	if e == "" {
		return 0, fmt.Errorf("empty cron expression")
	}

	// Macros / @every handled by ParseStandard (it also supports plain 5-field specs).
	if strings.HasPrefix(e, "@") {
		_, err := cron.ParseStandard(e)
		if err != nil {
			return 0, err
		}
		// Macro: treat as 5-field style for reporting (doesn't really have fields).
		return 5, nil
	}

	fields := strings.Fields(e)
	if len(fields) < 5 || len(fields) > 6 {
		return 0, fmt.Errorf("invalid field count: got %d (want 5 or 6)", len(fields))
	}

	parser6 := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	parser5 := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

	// If exactly 6 fields, try 6-field parser first.
	if len(fields) == 6 {
		if _, err := parser6.Parse(e); err == nil {
			return 6, nil
		} else {
			return 0, err
		}
	}

	// len == 5
	if _, err := parser5.Parse(e); err == nil {
		return 5, nil
	} else {
		return 0, err
	}
}

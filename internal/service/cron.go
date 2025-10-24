package service

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

// ParseCron parses a cron expression that have 5 fields
// return error if it fails
func ParseCron(expr string) error {
	e := strings.TrimSpace(expr)
	if e == "" {
		return fmt.Errorf("empty cron expression")
	}

	// Macros / @every handled by ParseStandard (it also supports plain 5-field specs).
	if strings.HasPrefix(e, "@") {
		_, err := cron.ParseStandard(e)
		return err
	}

	parser5 := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

	// len == 5
	_, err := parser5.Parse(e)
	return err
}

var cueDurationRx = regexp.MustCompile(`^(\d+d)?(\d+h)?(\d+m)?(\d+s)?$`)

// ParseCueDuration parses strings matching ^(\d+d)?(\d+h)?(\d+m)?(\d+s)?$ into time.Duration.
// Supports ordered day/hour/minute/second segments. Empty string rejected.
func ParseCueDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, errors.New("empty duration")
	}
	m := cueDurationRx.FindStringSubmatch(s)
	if m == nil {
		return 0, errors.New("invalid duration format")
	}
	var total time.Duration
	for i, seg := range m[1:] { // groups 1..4
		if seg == "" {
			continue
		}
		// seg like "12d"
		numStr := seg[:len(seg)-1]
		val, err := strconv.ParseInt(numStr, 10, 64)
		if err != nil {
			return 0, errors.New("invalid number in " + seg)
		}
		var add time.Duration
		switch last := seg[len(seg)-1]; last {
		case 'd':
			add = time.Hour * 24 * time.Duration(val)
		case 'h':
			add = time.Hour * time.Duration(val)
		case 'm':
			add = time.Minute * time.Duration(val)
		case 's':
			add = time.Second * time.Duration(val)
		default:
			return 0, errors.New("unknown unit in " + seg)
		}
		// overflow check
		if (add > 0 && total > time.Duration(math.MaxInt64)-add) ||
			(add < 0 && total < time.Duration(math.MinInt64)-add) {
			return 0, errors.New("duration overflow")
		}
		total += add

		// Optional: enforce no skipped ordering violations (regex already does).
		_ = i
	}
	return total, nil
}

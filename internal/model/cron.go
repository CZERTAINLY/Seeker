package model

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
// returns error if it fails
func ParseCron(expr string) (time.Duration, error) {
	e := strings.TrimSpace(expr)
	if e == "" {
		return 0, fmt.Errorf("empty cron expression")
	}

	// Macros / @every handled by ParseStandard (it also supports plain 5-field specs).
	var schedule cron.Schedule
	var err error
	if strings.HasPrefix(e, "@") {
		schedule, err = cron.ParseStandard(e)
	} else {
		parser5 := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
		schedule, err = parser5.Parse(e)
	}
	if err != nil {
		return 0, err
	}
	next1 := schedule.Next(time.Now())
	next2 := schedule.Next(next1)
	interval := next2.Sub(next1)
	return interval, nil
}

var isoDurationRx = regexp.MustCompile(`^P((?P<day>\d+)D)?(T?(?:(?P<hour>[+-]?\d+)H)?(?:(?P<minute>[+-]?\d+)M)?(?:(?P<second>[+-]?\d+(?:[.,]\d+)?)S)?)?$`)

var ErrISOFormat error = errors.New("invalid ISO8601 duration")

func ParseISODuration(dur string) (time.Duration, error) {
	if dur == "" || dur == "P" || dur == "PT" || !isoDurationRx.MatchString(dur) {
		return 0, ErrISOFormat
	}
	match := isoDurationRx.FindStringSubmatch(dur)

	// without T components P2M is ambiguous according ISO
	hasT := strings.Contains(dur, "T")
	var hasHMS = false

	var ret time.Duration

	for i, name := range isoDurationRx.SubexpNames() {
		part := match[i]
		if i == 0 || name == "" || part == "" {
			continue
		}

		num, frac, err := parse(part)
		if err != nil {
			return 0, err
		}
		var d time.Duration
		switch name {
		case "day":
			d = 24 * time.Hour
		case "hour":
			hasHMS = true
			// But T without hour not
			hasT = true
			d = 1 * time.Hour
		case "minute":
			hasHMS = true
			if !hasT {
				return 0, ErrISOFormat
			}
			d = 1 * time.Minute
		case "second":
			hasHMS = true
			d = 1 * time.Second
		default:
			return 0, fmt.Errorf("unknown component %s", name)
		}
		ret += time.Duration(num) * d
		if num >= 0 {
			ret += time.Duration(frac * float64(d))
		} else {
			ret -= time.Duration(frac * float64(d))
		}
	}

	// eg P2DT - this is overly compliant, but well
	if hasT && !hasHMS {
		return 0, ErrISOFormat
	}

	return ret, nil
}

func parse(s string) (num int, frac float64, err error) {
	s = strings.Replace(s, ",", ".", 1)
	a, b, ok := strings.Cut(s, ".")
	if ok {
		if len(b) > 9 {
			return 0, 0.0, ErrISOFormat
		}
		var f int
		f, err = strconv.Atoi(b)
		if err != nil {
			err = fmt.Errorf("parsing fraction: %w", err)
			return
		}
		if f != 0 {
			frac = float64(f) / math.Pow10(len(b))
		}
	}
	num, err = strconv.Atoi(a)
	if err != nil {
		err = fmt.Errorf("parsing number: %w", err)
	}
	return
}

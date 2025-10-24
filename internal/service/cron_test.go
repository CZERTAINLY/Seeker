package service_test

import (
	"errors"
	"testing"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/service"

	"github.com/stretchr/testify/require"
)

func TestParseCron(t *testing.T) {
	t.Parallel()
	type then struct {
		err error
	}
	cases := []struct {
		scenario string
		given    string
		then     then
	}{
		{"valid_5_fields", "*/15 * * * *", then{nil}},
		{"macro_hourly", "@hourly", then{nil}},
		{"macro_every", "@every 5m", then{nil}},
		{"invalid_field_count_4", "* * * *", then{errors.New("expected exactly 5 fields, found 4: [* * * *]")}},
		{"invalid_field_count_7", "* * * * * * *", then{errors.New("expected exactly 5 fields, found 7: [* * * * * * *]")}},

		{"invalid_token_5_fields", "* * 32 * *", then{errors.New("end of range (32) above maximum (31): 32")}},
		{"empty", "", then{errors.New("empty cron expression")}},
	}

	for _, tc := range cases {
		t.Run(tc.scenario, func(t *testing.T) {
			err := service.ParseCron(tc.given)
			if tc.then.err != nil {
				require.Error(t, err)
				require.EqualError(t, err, tc.then.err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestParseCueDuration_Success(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"1d", 24 * time.Hour},
		{"2h", 2 * time.Hour},
		{"3m", 3 * time.Minute},
		{"4s", 4 * time.Second},
		{"1d2h3m4s", 24*time.Hour + 2*time.Hour + 3*time.Minute + 4*time.Second},
		{"5d10m", 5*24*time.Hour + 10*time.Minute},
		{"7h8s", 7*time.Hour + 8*time.Second},
		{"9m", 9 * time.Minute},
		{"10d", 10 * 24 * time.Hour},
		// Skipping groups allowed (regex permits omission)
		{"1d3m", 24*time.Hour + 3*time.Minute},
		{"1d4s", 24*time.Hour + 4*time.Second},
		{"2h5m", 2*time.Hour + 5*time.Minute},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := service.ParseCueDuration(tc.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("ParseCueDuration(%q) = %v want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseCueDuration_Error(t *testing.T) {
	t.Parallel()
	tests := []string{
		"",            // empty
		"abc",         // invalid chars
		"1x",          // bad unit
		"1d2h3",       // missing final unit char
		"1h1d",        // wrong order (day must come first if present)
		"1d2h3m4s5ms", // unsupported extra unit
		"1d-2h",       // minus sign not allowed
		"1d 2h",       // spaces not allowed
		"1d2m1h",      // wrong order: hour after minute
	}

	for _, in := range tests {
		t.Run(in, func(t *testing.T) {
			got, err := service.ParseCueDuration(in)
			if err == nil {
				t.Fatalf("expected error for %q, got duration %v", in, got)
			}
		})
	}
}

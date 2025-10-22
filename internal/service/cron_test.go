package service_test

import (
	"errors"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/service"

	"github.com/stretchr/testify/require"
)

func TestParseFlexible(t *testing.T) {
	type then struct {
		fields int
		err    error
	}
	cases := []struct {
		scenario string
		given    string
		then     then
	}{
		{"valid_5_fields", "*/15 * * * *", then{5, nil}},
		{"valid_6_fields", "0 */2 * * * *", then{6, nil}},
		{"macro_hourly", "@hourly", then{5, nil}},
		{"macro_every", "@every 5m", then{5, nil}},
		{"invalid_field_count_4", "* * * *", then{0, errors.New("invalid field count: got 4 (want 5 or 6)")}},
		{"invalid_field_count_7", "* * * * * * *", then{0, errors.New("invalid field count: got 7 (want 5 or 6)")}},
		{"invalid_token_6_fields", "70 * * * * *", then{0, errors.New("end of range (70) above maximum (59): 70")}},
		{"invalid_token_5_fields", "* * 32 * *", then{0, errors.New("end of range (32) above maximum (31): 32")}},
		{"empty", "", then{0, errors.New("empty cron expression")}},
	}

	for _, tc := range cases {
		t.Run(tc.scenario, func(t *testing.T) {
			fields, err := service.ParseFlexible(tc.given)
			if tc.then.err != nil {
				require.Error(t, err)
				require.EqualError(t, err, tc.then.err.Error())
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.then.fields, fields)
		})
	}
}

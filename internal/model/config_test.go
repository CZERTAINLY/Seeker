package model_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()
	yml := `
version: 0
service:
  mode: manual
  log: stderr
  repository:
    enabled: true
    url: https://example.com/repo
    auth:
      type: token
      token: ABC123
`
	cfg, err := model.LoadConfig(strings.NewReader(yml))
	if err != nil {
		for _, d := range model.CueErrDetails(err) {
			t.Logf("%s\n", d)
		}
	}
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, model.ServiceModeManual, cfg.Service.Mode)
	require.Equal(t, model.LogStderr, cfg.Service.Log)
	require.NotNil(t, cfg.Service.Repository)
	require.True(t, cfg.Service.Repository.Enabled)
	require.Equal(t, "https://example.com/repo", cfg.Service.Repository.URL)
	require.Equal(t, "token", cfg.Service.Repository.Auth.Type)
	require.Equal(t, "ABC123", cfg.Service.Repository.Auth.Token)
}

func TestLoadConfig_Fail(t *testing.T) {
	t.Parallel()

	var testCases = []struct {
		scenario string
		given    string
		then     string
	}{
		{
			scenario: "Missing required auth.token for token auth type",
			given: `
version: 0
service:
  mode: manual
  repository:
    enabled: true
    url: https://example.com/repo
    auth:
      type: token
`,
			then: `#Config.service.repository.auth.token: incomplete value !=""`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			t.Parallel()
			_, err := model.LoadConfig(strings.NewReader(tc.given))
			require.Error(t, err)
			for _, d := range model.CueErrDetails(err) {
				t.Logf("%s", d)
			}
			require.EqualError(t, err, tc.then)
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()
	cfg := model.DefaultConfig(t.Context())
	require.NotZero(t, cfg)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	err := enc.Encode(cfg)
	require.NoError(t, err)

	cfg2, err := model.LoadConfig(&buf)
	if err != nil {
		for _, d := range model.CueErrDetails(err) {
			t.Logf("%s", d)
		}
	}
	require.NoError(t, err)

	require.Equal(t, cfg, cfg2)
}

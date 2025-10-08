package model_test

import (
	"strings"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	yml := `
version: 0
service:
  mode: manual
  log: stderr
  repository:
    enabled: true
    url: https://example.com/repo
    auth:
      type: static_token
      token: ABC123
`
	cfg, err := model.LoadConfig(strings.NewReader(yml))
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, model.ServiceModeManual, cfg.Service.Mode)
	require.NotNil(t, cfg.Service.Log)
	require.Equal(t, model.LogStderr, *cfg.Service.Log)
	require.NotNil(t, cfg.Service.Repository)
	require.NotNil(t, cfg.Service.Repository.Enabled)
	require.True(t, *cfg.Service.Repository.Enabled)
	require.Equal(t, "https://example.com/repo", cfg.Service.Repository.URL)
	require.Equal(t, "static_token", cfg.Service.Repository.Auth.Type)
	require.Equal(t, "ABC123", cfg.Service.Repository.Auth.Token)
}

func TestLoadConfig_Fail(t *testing.T) {
	// Missing required auth.token for static_token
	yml := `
version: 0
service:
  mode: manual
  repository:
    enabled: true
    url: https://example.com/repo
    auth:
      type: static_token
`
	_, err := model.LoadConfig(strings.NewReader(yml))
	require.Error(t, err)
	require.EqualError(t, err, "#Config.service.repository.auth.token: incomplete value string")
}

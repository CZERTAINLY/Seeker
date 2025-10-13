package model_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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

func TestIsZero(t *testing.T) {
	t.Parallel()

	var f model.Filesystem
	var cc model.ContainersConfig
	var p model.Ports
	var s model.Service
	var c model.Config

	for _, z := range []interface{ IsZero() bool }{f, cc, p, s, c} {
		require.True(t, z.IsZero())
	}
}

func TestExpandEnv(t *testing.T) {
	// this must not be parallel
	const inp = `
version: 0
service:
  mode: manual
  dir: ${TEST_EE_SERVICE_DIR}
filesystem:
  paths:
    - $TEST_EE_FILESYSTEM_PATH_1
    - $TEST_EE_FILESYSTEM_PATH_2
    - $TEST_EE_FILESYSTEM_PATH_undefined
containers:
  config:
    - name: ${TEST_EE_CONTAINERS1_NAME}
      host: ${TEST_EE_CONTAINERS1_HOST}
      images: 
        - $TEST_EE_CONTAINERS1_IMAGE_1
ports:
  binary: ${TEST_EE_NMAP_BINARY}
`

	var names = []string{
		"TEST_EE_SERVICE_DIR",
		"TEST_EE_FILESYSTEM_PATH_1",
		"TEST_EE_FILESYSTEM_PATH_2",
		"TEST_EE_CONTAINERS1_NAME",
		"TEST_EE_CONTAINERS1_HOST",
		"TEST_EE_CONTAINERS1_IMAGE_1",
		"TEST_EE_NMAP_BINARY",
	}

	for _, name := range names {
		require.NoError(t, os.Setenv(name, strings.ToLower(name)))
	}

	t.Cleanup(func() {
		for _, name := range names {
			require.NoError(t, os.Unsetenv(name))
		}
	})

	cfg, err := model.LoadConfig(strings.NewReader(inp))
	require.NoError(t, err)

	require.Equal(t, "test_ee_service_dir", cfg.Service.Dir)
	require.Len(t, cfg.Filesystem.Paths, 3)
	require.Equal(t, "test_ee_filesystem_path_1", cfg.Filesystem.Paths[0])
	require.Equal(t, "test_ee_filesystem_path_2", cfg.Filesystem.Paths[1])
	require.Equal(t, "", cfg.Filesystem.Paths[2])

	require.Len(t, cfg.Containers.Config, 1)
	c0 := cfg.Containers.Config[0]
	require.Equal(t, "test_ee_containers1_name", c0.Name)
	require.Equal(t, "test_ee_containers1_host", c0.Host)
	require.Len(t, c0.Images, 1)
	require.Equal(t, "test_ee_containers1_image_1", c0.Images[0])

	require.Equal(t, "test_ee_nmap_binary", cfg.Ports.Binary)

}

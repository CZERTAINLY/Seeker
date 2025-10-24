package model_test

import (
	"bytes"
	"errors"
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
		then     []model.CueErrorDetail
	}{
		{
			scenario: "extra",
			given: `
version: 0
service:
  mode: manual
extra: true
`,
			then: []model.CueErrorDetail{
				{
					Path:    "extra",
					Code:    model.CodeUnknownField,
					Message: "Field extra is not allowed",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     5,
						Column:   1,
					},
					Raw: "#Config.extra: field not allowed",
				},
			},
		},
		{
			scenario: "Additional field",
			given: `
version: 0
service:
  mode: manual
  x: true
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.x",
					Code:    model.CodeUnknownField,
					Message: "Field x is not allowed",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     5,
						Column:   3,
					},
					Raw: "#Config.service.x: field not allowed",
				},
			},
		},
		{
			scenario: "service.mode missing",
			given: `
version: 0
service:
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for service: expected type struct: got null",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     3,
						Column:   9,
					},
					Raw: "#Config.service: conflicting values null and {verbose?:(bool|*false),log?:(*\"stderr\"|\"stdout\"|\"discard\"|string),dir?:string,repository?:#Repository} (mismatched types null and struct)",
				},
			},
		},
		{
			scenario: "version 1",
			given: `
version: 1
service:
  mode: manual
`,
			then: []model.CueErrorDetail{
				{
					Path:    "version",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for version: possible values (0): got 1",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     2,
						Column:   10,
					},
					Raw: "#Config.version: conflicting values 1 and 0",
				},
			},
		},
		{
			scenario: "service.dir wrong type",
			given: `
version: 0
service:
  mode: manual
  dir: 123
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.dir",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for dir: expected type string: got int",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     5,
						Column:   8,
					},
					Raw: `#Config.service.dir: conflicting values 123 and string (mismatched types int and string)`,
				},
			},
		},
		{
			scenario: "service.mode",
			given: `
version: 0
service:
  mode: automatic_gear
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.mode",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for mode: possible values (manual,timer) (default manual): got automatic_gear",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     4,
						Column:   9,
					},
					Raw: "#Config.service.mode: 2 errors in empty disjunction: (and 2 more errors)",
				},
			},
		},
		{
			scenario: "service.verbose",
			given: `
version: 0
service:
  mode: manual
  verbose: "yes"
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.verbose",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for verbose: expected type bool: got string",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     5,
						Column:   12,
					},
					Raw: `#Config.service.verbose: 2 errors in empty disjunction: (and 2 more errors)`,
				},
			},
		},
		{
			scenario: "service.verbose type",
			given: `
version: 0
service:
  mode: manual
  verbose: "true"
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.verbose",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for verbose: expected type bool: got string",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     5,
						Column:   12,
					},
					Raw: `#Config.service.verbose: 2 errors in empty disjunction: (and 2 more errors)`,
				},
			},
		},
		{
			scenario: "service.mode timer and missing every",
			given: `
version: 0
service:
  mode: timer
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.schedule",
					Code:    model.CodeMissingRequired,
					Message: "Field schedule is required",
					Pos: model.CueErrorPosition{
						Filename: "",
						Line:     0,
						Column:   0,
					},
					Raw: "#Config.service.schedule: incomplete value {cron:=~\"^(@(yearly|anually|monthly|weekly|daily|midnigth|hourly)|(?:\\\\S+\\\\s+){4}\\\\S+)|(@every.*)$\"} | {duration:=~\"^(\\\\d+d)?(\\\\d+h)?(\\\\d+m)?(\\\\d+s)?$\" & !=\"\"}",
				},
			},
		},
		{
			scenario: "service.mode timer and empty schedule",
			given: `
version: 0
service:
  mode: timer
  schedule:
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.schedule",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for schedule: expected type struct: got null",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     5,
						Column:   12,
					},
					Raw: "#Config.service.schedule: 2 errors in empty disjunction: (and 2 more errors)",
				},
			},
		},
		{
			scenario: "service.mode timer and empty schedule values",
			given: `
version: 0
service:
  mode: timer
  schedule:
    cron: ""
    duration: ""
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.schedule.cron",
					Code:    model.CodeValidationError,
					Message: "Field cron is invalid: invalid value \"\" (out of bound =~\"^(@(yearly|anually|monthly|weekly|daily|midnigth|hourly)|(?:\\\\S+\\\\s+){4}\\\\S+)|(@every.*)$\")",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     6,
						Column:   11,
					},
					Raw: "#Config.service.schedule: 2 errors in empty disjunction: (and 2 more errors)",
				},
				{
					Path:    "service.schedule.duration",
					Code:    model.CodeValidationError,
					Message: "Field duration is invalid: value must not be empty",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     7,
						Column:   15,
					},
					Raw: "#Config.service.schedule: 2 errors in empty disjunction: (and 2 more errors)",
				},
			},
		},
		// FIXME: fix the test
		/*
					{
						scenario: "service.mode timer and both schedule values",
						given: `
			version: 0
			service:
			  mode: timer
			  schedule:
			    cron: "@hourly"
			    duration: "1d2h3m4s"
			`,
						then: []model.CueErrorDetail{},
					},
		*/
		{
			scenario: "service.repository url is missing",
			given: `
version: 0
service:
  mode: manual
  repository:
    enabled: true
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.repository.url",
					Code:    model.CodeMissingRequired,
					Message: "Field url is required",
					Pos: model.CueErrorPosition{
						Filename: "",
						Line:     0,
						Column:   0,
					},
					Raw: `#Config.service.repository.url: incomplete value =~"^https?://.+"`,
				},
			},
		},
		{
			scenario: "service.repository.url not url",
			given: `
version: 0
service:
  mode: manual
  repository:
    enabled: true
    url: ""
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.repository.url",
					Code:    model.CodeValidationError,
					Message: "Field url is invalid: value must be a valid http(s) URL",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     7,
						Column:   10,
					},
					Raw: `#Config.service.repository.url: invalid value "" (out of bound =~"^https?://.+")`,
				},
			},
		},
		{
			scenario: "service.repository.url is ftp",
			given: `
version: 0
service:
  mode: manual
  repository:
    enabled: true
    url: "ftp://example.com"
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.repository.url",
					Code:    model.CodeValidationError,
					Message: "Field url is invalid: value must be a valid http(s) URL",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     7,
						Column:   10,
					},
					Raw: `#Config.service.repository.url: invalid value "ftp://example.com" (out of bound =~"^https?://.+")`,
				},
			},
		},
		{
			scenario: "service.repository.url is prefix only",
			given: `
version: 0
service:
  mode: manual
  repository:
    enabled: true
    url: "https://"
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.repository.url",
					Code:    model.CodeValidationError,
					Message: "Field url is invalid: value must be a valid http(s) URL",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     7,
						Column:   10,
					},
					Raw: `#Config.service.repository.url: invalid value "https://" (out of bound =~"^https?://.+")`,
				},
			},
		},
		{
			scenario: "service.repository.auth.type token missing",
			given: `
version: 0
service:
  mode: manual
  repository:
    enabled: true
    url: "https://example.com"
    auth:
      type: "token"
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.repository.auth.token",
					Code:    model.CodeMissingRequired,
					Message: "Field token is required",
					Pos: model.CueErrorPosition{
						Filename: "",
						Line:     0,
						Column:   0,
					},
					Raw: `#Config.service.repository.auth.token: incomplete value !=""`,
				},
			},
		},
		{
			scenario: "service.repository.auth.type token empty",
			given: `
version: 0
service:
  mode: manual
  repository:
    enabled: true
    url: "https://example.com"
    auth:
      type: "token"
      token: ""
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.repository.auth.token",
					Code:    model.CodeValidationError,
					Message: "Field token is invalid: value must not be empty",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     10,
						Column:   14,
					},
					Raw: `#Config.service.repository.auth.token: invalid value "" (out of bound !="")`,
				},
			},
		},
		{
			scenario: "service.repository.auth.type invalid",
			given: `
version: 0
service:
  mode: manual
  repository:
    enabled: true
    url: "https://example.com"
    auth:
      type: "invalid"
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.repository.auth.type",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for type: possible values (token): got invalid",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     9,
						Column:   13,
					},
					Raw: `#Config.service.repository.auth.type: conflicting values "token" and "invalid"`,
				},
			},
		},
		{
			scenario: "containers.config wrong yaml",
			// this is funny case - the config is recognized as
			// "config": {"-name" : "c1"}} by YAML parser
			given: `
version: 0
service:
  mode: manual
containers:
  enabled: true
  config:
    -name: c1
`,
			then: []model.CueErrorDetail{
				{
					Path:    "containers.config",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for config: expected type struct: got list",
					Pos: model.CueErrorPosition{
						Filename: "",
						Line:     0,
						Column:   0,
					},
					Raw: `#Config.containers.config: conflicting values [...#ContainerConfig] and {"-name":"c1"} (mismatched types list and struct)`,
				},
			},
		},
		{
			scenario: "containers.config no host",
			given: `
version: 0
service:
  mode: manual
containers:
  enabled: true
  config:
    -
      name: c1
`,
			then: []model.CueErrorDetail{
				{
					Path:    "containers.config.0.host",
					Code:    model.CodeMissingRequired,
					Message: "Field host is required",
					Pos: model.CueErrorPosition{
						Filename: "",
						Line:     0,
						Column:   0,
					},
					Raw: `#Config.containers.config.0.host: incomplete value string`,
				},
			},
		},
		{
			scenario: "ports.ports number",
			given: `
version: 0
service:
  mode: manual
ports:
  ports: 8080
`,
			then: []model.CueErrorDetail{
				{
					Path:    "ports.ports",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for ports: expected type string: got int",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     6,
						Column:   10,
					},
					Raw: `#Config.ports.ports: 2 errors in empty disjunction: (and 2 more errors)`,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			_, err := model.LoadConfig(strings.NewReader(tc.given))
			require.Error(t, err)
			var cuerr model.CueError
			ok := errors.As(err, &cuerr)
			require.Truef(t, ok, "%q is not model.CueError", err)
			for _, f := range cuerr.Details() {
				t.Logf("%#+v", f)
			}
			require.Equal(t, tc.then, cuerr.Details())
			require.NotEmpty(t, cuerr.Details()[0].Attr("test"))
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
		var cuerr model.CueError
		ok := errors.As(err, &cuerr)
		require.True(t, ok)
		for _, d := range cuerr.Details() {
			t.Logf("%+v", d)
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

package model

import (
	"io"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/encoding/yaml"

	_ "embed"
)

// Enum helpers (optional).
const (
	ContainerTypeDocker = "docker"
	ContainerTypePodman = "podman"

	AuthTypeNone        = "none"
	AuthTypeStaticToken = "static_token"

	ServiceModeManual = "manual"

	LogStderr  = "stderr"
	LogStdout  = "stdout"
	LogDiscard = "discard"
)

//go:embed config.cue
var cueSource []byte

var (
	cueCtx *cue.Context
	schema cue.Value
)

func init() {
	if len(cueSource) == 0 {
		panic("variable cueSource is empty")
	}
	cueCtx = cuecontext.New()
	compiled := cueCtx.CompileBytes(cueSource)
	if compiled.Err() != nil {
		panic(compiled.Err())
	}

	if err := compiled.Validate(); err != nil {
		panic(err)
	}

	schema = compiled.LookupPath(cue.ParsePath("#Config"))
	if schema.Err() != nil {
		panic(schema.Err())
	}
	if err := schema.Validate(); err != nil {
		panic(err)
	}

}

type Config struct {
	Version    int               `json:"version"` // fixed 0 for now
	Filesystem *Filesystem       `json:"filesystem,omitempty"`
	Containers []ContainerConfig `json:"containers,omitempty"`
	Ports      *Ports            `json:"ports,omitempty"`
	Service    Service           `json:"service"` // currently only manual mode
}

// Filesystem scanning settings.
type Filesystem struct {
	Enabled *bool    `json:"enabled,omitempty"`
	Paths   []string `json:"paths,omitempty"` // nil/empty => use CWD
}

// Container daemon configuration list element.
type ContainerConfig struct {
	Enabled *bool    `json:"enabled,omitempty"`
	Name    *string  `json:"name,omitempty"`
	Type    string   `json:"type"`             // "docker" | "podman"
	Socket  *string  `json:"socket,omitempty"` // e.g. /var/run/docker.sock
	Images  []string `json:"images,omitempty"` // explicit images (empty => discover)
}

// Local ports scanning module configuration.
type Ports struct {
	Enabled *bool   `json:"enabled,omitempty"`
	Binary  *string `json:"binary,omitempty"` // path or name (e.g. nmap)
	Ports   *string `json:"ports,omitempty"`  // "1-65535", "22,80,8000-8100", etc.
	IPv4    *bool   `json:"ipv4,omitempty"`
	IPv6    *bool   `json:"ipv6,omitempty"`
}

// Service (only manual supported now). Output fields are flattened.
type Service struct {
	Mode       string      `json:"mode"` // must be "manual"
	Verbose    *bool       `json:"verbose,omitempty"`
	Log        *string     `json:"log,omitempty"`        // "stderr"|"stdout"|"discard"|path
	Dir        *string     `json:"dir,omitempty"`        // output directory
	Repository *Repository `json:"repository,omitempty"` // remote publication
}

// Repository publication settings.
type Repository struct {
	Enabled *bool  `json:"enabled,omitempty"`
	URL     string `json:"url"`
	Auth    Auth   `json:"auth"` // discriminated union by Auth.Type
}

// Auth is a tagged union: Type "none" or "static_token".
type Auth struct {
	Type  string `json:"type"`            // "none" | "static_token"
	Token string `json:"token,omitempty"` // required when Type == "static_token"
}

// LoadConfig validates YAML from r against CUE schema and decodes to Config.
func LoadConfig(r io.Reader) (*Config, error) {
	yamlFile, err := yaml.Extract("config.yaml", r)
	if err != nil {
		return nil, err
	}
	yamlValue := cueCtx.BuildFile(yamlFile)

	unified := schema.Unify(yamlValue)
	if err := unified.Validate(
		cue.All(),          // all constraints
		cue.Concrete(true), // no incomplete values
	); err != nil {
		return nil, err
	}

	var out Config
	if err := unified.Decode(&out); err != nil {
		return nil, err
	}

	return &out, nil
}

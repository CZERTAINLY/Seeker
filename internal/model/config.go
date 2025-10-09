package model

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/encoding/yaml"
	"github.com/CZERTAINLY/Seeker/internal/log"
	"github.com/docker/docker/client"

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

type Config struct {
	Version    int               `json:"version"` // fixed 0 for now
	Filesystem *Filesystem       `json:"filesystem,omitempty"`
	Containers []ContainerConfig `json:"containers,omitempty"`
	Ports      *Ports            `json:"ports,omitempty"`
	Service    Service           `json:"service"`
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
	Socket  string   `json:"socket,omitempty"` // e.g. /var/run/docker.sock
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
	Mode       string      `json:"mode"` // must be "manual" or "timer"
	Verbose    *bool       `json:"verbose,omitempty"`
	Log        *string     `json:"log,omitempty"`        // "stderr"|"stdout"|"discard"|path
	Dir        *string     `json:"dir,omitempty"`        // output directory
	Repository *Repository `json:"repository,omitempty"` // remote publication
	Every      string      `json:"every,omitempty"`
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

// DefaultConfig returns a default configuration for seeker
// It tries to discover and ping docker/podman sockets, so those
// scans can be added to the list
func DefaultConfig(ctx context.Context) Config {
	var portsEnabled = true
	nmap, err := exec.LookPath("nmap")
	if err != nil {
		portsEnabled = false
		slog.WarnContext(ctx, "nmap binary not found")
	}

	var cfg = Config{
		Version: 0,
		Filesystem: &Filesystem{
			Enabled: ptr(true),
			Paths:   nil,
		},
		Ports: &Ports{
			Enabled: ptr(portsEnabled),
			Binary:  ptr(nmap),
			Ports:   ptr("1-65535"),
			IPv4:    ptr(true),
			IPv6:    ptr(true),
		},
		Service: Service{
			Mode:       ServiceModeManual,
			Verbose:    ptr(true),
			Log:        ptr("stderr"),
			Dir:        ptr("."),
			Repository: nil,
			Every:      "24h",
		},
	}

	slog.DebugContext(ctx, "probing docker/podman sockets")
	// detect docker socket
	for _, path := range []string{"${DOCKER_HOST}", "/run/docker.sock", "/var/run/docker.sock"} {
		ctx = log.ContextAttrs(ctx, slog.String("path", path))
		cc, err := containerConfig(ctx, ContainerTypeDocker, path)
		if err != nil {
			slog.DebugContext(ctx, "probe failed", "error", err)
			continue
		}
		cfg.Containers = append(cfg.Containers, cc)
	}
	// detect podman sockets
	for _, path := range []string{"${PODMAN_SOCKET}", "/run/podman/podman.sock", "/var/run/podman/podman.sock"} {
		ctx = log.ContextAttrs(ctx, slog.String("path", path))
		cc, err := containerConfig(ctx, ContainerTypePodman, path)
		if err != nil {
			slog.DebugContext(ctx, "probe failed", "error", err)
			continue
		}
		cfg.Containers = append(cfg.Containers, cc)
	}
	return cfg
}

// ptr returns a pointer to v. Useful for literals in composite literals.
// Remove when Go 1.26 (not yet released) with new(value) will be the minimum supported compiler
func ptr[T any](v T) *T {
	return &v
}

func containerConfig(ctx context.Context, typ string, sockPath string) (ContainerConfig, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := probeDockerLikeSocket(ctx, sockPath); err != nil {
		return ContainerConfig{}, err
	}
	return ContainerConfig{
		Enabled: ptr(true),
		Name:    ptr(typ + " " + sockPath),
		Type:    typ,
		Socket:  sockPath,
		Images:  []string{},
	}, nil
}

func probeDockerLikeSocket(ctx context.Context, sockPath string) error {
	sockPath = os.ExpandEnv(sockPath)

	// Build host URL
	var host string
	if !strings.Contains(sockPath, "://") {
		host = "unix://" + sockPath
	} else {
		host = sockPath
	}

	cli, err := client.NewClientWithOpts(
		client.WithHost(host),
		client.WithAPIVersionNegotiation(), // negotiate highest mutually supported
	)
	if err != nil {
		return fmt.Errorf("new client: %w", err)
	}
	defer func() { _ = cli.Close() }()

	if _, err = cli.Ping(ctx); err != nil {
		// Distinguish dial errors
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return fmt.Errorf("ping timeout: %w", err)
		}
		return fmt.Errorf("ping failed: %w", err)
	}

	return nil
}

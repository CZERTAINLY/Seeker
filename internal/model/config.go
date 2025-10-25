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
	"reflect"
	"strings"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/log"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/encoding/yaml"
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
	Version    int        `json:"version"` // fixed 0 for now
	Filesystem Filesystem `json:"filesystem"`
	Containers Containers `json:"containers"`
	Ports      Ports      `json:"ports"`
	Service    Service    `json:"service"`
}

// Filesystem scanning settings.
type Filesystem struct {
	Enabled bool     `json:"enabled"`
	Paths   []string `json:"paths,omitempty"` // nil/empty => use CWD
}

type Containers struct {
	Enabled bool `json:"enabled"`
	Config  ContainersConfig
}

type ContainersConfig []ContainerConfig

// Container daemon configuration list element.
type ContainerConfig struct {
	Name   string   `json:"name,omitempty"`
	Type   string   `json:"type"`             // "docker" | "podman"
	Host   string   `json:"host,omitempty"`   // e.g. /var/run/docker.sock or ${DOCKER_HOST}
	Images []string `json:"images,omitempty"` // explicit images (empty => discover)
}

// Local ports scanning module configuration.
type Ports struct {
	Enabled bool   `json:"enabled"`
	Binary  string `json:"binary,omitempty"` // path or name (e.g. nmap)
	Ports   string `json:"ports,omitempty"`  // "1-65535", "22,80,8000-8100", etc.
	IPv4    bool   `json:"ipv4"`
	IPv6    bool   `json:"ipv6"`
}

// Service configuration
type Service struct {
	Mode       string         `json:"mode"` // must be "manual" or "timer"
	Verbose    bool           `json:"verbose,omitempty"`
	Log        string         `json:"log,omitempty"`                                    // "stderr"|"stdout"|"discard"|path - defaults to stderr
	Dir        string         `json:"dir,omitempty"`                                    // output directory
	Repository *Repository    `json:"repository,omitempty" yaml:"repository,omitempty"` // remote publication
	Schedule   *TimerSchedule `json:"schedule,omitempty"`                               // only for mode timer
}

// TimerSchedule defines the duration for a timer mode
type TimerSchedule struct {
	Cron     string `json:"cron,omitempty"`
	Duration string `json:"duration,omitempty"`
}

// Repository publication settings.
type Repository struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
	Auth    Auth   `json:"auth"` // discriminated union by Auth.Type
}

// Auth is a tagged union: Type "none" or "static_token".
type Auth struct {
	Type  string `json:"type"`            // "none" | "static_token"
	Token string `json:"token,omitempty"` // required when Type == "static_token"
}

func (c Config) IsZero() bool {
	return c.Filesystem.IsZero() &&
		c.Containers.Config.IsZero() &&
		c.Ports.IsZero() &&
		c.Service.IsZero()
}

func (c Filesystem) IsZero() bool {
	return isZero(c)
}
func (c ContainersConfig) IsZero() bool {
	return len(c) == 0
}
func (c Ports) IsZero() bool {
	return isZero(c)
}
func (c Service) IsZero() bool {
	return isZero(c)
}

func (c *Config) ExpandEnv() {
	var kids = []interface{ ExpandEnv() }{
		&c.Filesystem,
		&c.Containers,
		&c.Ports,
		&c.Service,
	}
	for _, ee := range kids {
		ee.ExpandEnv()
	}
}

func (c *Filesystem) ExpandEnv() {
	c.Paths = expandStrings(c.Paths)
}

func (c *Containers) ExpandEnv() {
	for idx, cc := range c.Config {
		cc.Name = os.ExpandEnv(cc.Name)
		cc.Host = os.ExpandEnv(cc.Host)
		cc.Images = expandStrings(cc.Images)
		c.Config[idx] = cc
	}
}

func (c *Ports) ExpandEnv() {
	c.Binary = os.ExpandEnv(c.Binary)
}

func (c *Service) ExpandEnv() {
	c.Dir = os.ExpandEnv(c.Dir)
}

func expandStrings(slice []string) []string {
	ret := make([]string, len(slice))
	for idx, s := range slice {
		ret[idx] = os.ExpandEnv(s)
	}
	return ret
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
// NOT SAFE for multiple goroutines
// Return CueError in a case validation phase fails
func LoadConfig(r io.Reader) (Config, error) {
	var zero Config
	yamlFile, err := yaml.Extract("config.yaml", r)
	if err != nil {
		return zero, err
	}
	yamlValue := cueCtx.BuildFile(yamlFile)

	unified := schema.Unify(yamlValue)
	if err := unified.Validate(
		cue.All(),          // all constraints
		cue.Concrete(true), // no incomplete values
	); err != nil {
		return zero, CueError{cuerr: err, config: yamlValue}
	}

	var out Config
	if err := unified.Decode(&out); err != nil {
		return zero, err
	}

	out.ExpandEnv()
	return out, nil
}

// CueError provides more user friendly validation errors on top of
// those generated by cuelang itself
type CueError struct {
	cuerr  error
	config cue.Value // content of --config file
}

// Error implements error interface, returns the string content of underlying
// cue error
func (e CueError) Error() string {
	return e.cuerr.Error()
}

// Unwrap allows one to get the original error via errors.As
func (e CueError) Unwrap() error {
	return e.cuerr
}

// Details provide human-friendlier error messages
func (c CueError) Details() []CueErrorDetail {
	return humanize(c.cuerr, c.config)
}

// DefaultConfig returns a default configuration for seeker
// It tries to discover and ping docker/podman sockets, so those
// scans can be added to the list
// NOT SAFE for multiple goroutines
func DefaultConfig(ctx context.Context) Config {
	var portsEnabled = true
	nmap, err := exec.LookPath("nmap")
	if err != nil {
		portsEnabled = false
		slog.WarnContext(ctx, "nmap binary not found")
	}

	var cfg = Config{
		Version: 0,
		Filesystem: Filesystem{
			Enabled: true,
			Paths:   []string{},
		},
		Ports: Ports{
			Enabled: portsEnabled,
			Binary:  nmap,
			Ports:   "1-65535",
			IPv4:    true,
			IPv6:    true,
		},
		Service: Service{
			Mode:    ServiceModeManual,
			Verbose: true,
			Log:     "stderr",
			Dir:     ".",
		},
	}

	var containers ContainersConfig
	slog.DebugContext(ctx, "probing docker/podman sockets")
	// detect docker socket
	for _, path := range []string{"${DOCKER_HOST}", "/run/docker.sock", "/var/run/docker.sock"} {
		ctx = log.ContextAttrs(ctx, slog.String("path", path))
		cc, err := containerConfig(ctx, ContainerTypeDocker, path)
		if err != nil {
			slog.DebugContext(ctx, "probe failed", "error", err)
			continue
		}
		containers = append(containers, cc)
	}
	// detect podman sockets
	for _, path := range []string{"${PODMAN_SOCKET}", "/run/podman/podman.sock", "/var/run/podman/podman.sock"} {
		ctx = log.ContextAttrs(ctx, slog.String("path", path))
		cc, err := containerConfig(ctx, ContainerTypePodman, path)
		if err != nil {
			slog.DebugContext(ctx, "probe failed", "error", err)
			continue
		}
		containers = append(containers, cc)
	}

	if len(containers) > 0 {
		cfg.Containers.Enabled = true
		cfg.Containers.Config = containers
	}

	return cfg
}

func containerConfig(ctx context.Context, typ string, sockPath string) (ContainerConfig, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	sockPath = os.ExpandEnv(sockPath)
	if err := probeDockerLikeSocket(ctx, sockPath); err != nil {
		return ContainerConfig{}, err
	}
	return ContainerConfig{
		Name:   typ,
		Type:   typ,
		Host:   sockPath,
		Images: []string{},
	}, nil
}

func probeDockerLikeSocket(ctx context.Context, sockPath string) error {
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

func isZero[T any](v T) bool {
	return reflect.ValueOf(v).IsZero()
}

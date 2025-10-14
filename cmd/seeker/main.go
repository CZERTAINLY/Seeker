package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/CZERTAINLY/Seeker/internal/gitleaks"
	"github.com/CZERTAINLY/Seeker/internal/log"
	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/CZERTAINLY/Seeker/internal/scan"
	"github.com/CZERTAINLY/Seeker/internal/service"
	"github.com/CZERTAINLY/Seeker/internal/x509"
	"gopkg.in/yaml.v3"

	"github.com/spf13/cobra"
)

var (
	detectors []scan.Detector

	userConfigPath string // /default/config/path/seeker on given OS
	configPath     string // actual config file used (if loaded)
	config         model.Config

	flagConfigFilePath string // value of --config flag
	flagVerbose        bool   //valur if --verbose flag
)

var rootCmd = &cobra.Command{
	Use:          "seeker",
	Short:        "Tool detecting secrets and providing BOM",
	SilenceUsage: true,
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "run command reads the configuration and executes the scan",
	RunE:  doRun,
}

var scanCmd = &cobra.Command{
	Use:    "_scan",
	Short:  "internal command",
	RunE:   doScan,
	Hidden: true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "version provide version of a seeker",
	RunE:  doVersion,
}

func init() {
	// user configuration
	d, err := os.UserConfigDir()
	if err != nil {
		panic(err)
	}
	userConfigPath = filepath.Join(d, "seeker")

	// configure default detectors
	// secrets:
	leaks, err := gitleaks.NewDetector()
	if err != nil {
		panic(err)
	}

	// certificates:
	detectors = []scan.Detector{
		x509.Detector{},
		leaks,
	}
}

func main() {
	// root flags
	rootCmd.PersistentFlags().StringVar(&flagConfigFilePath, "config", "", "Config file to load - default is seeker.yaml in current directory or in "+userConfigPath)
	rootCmd.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "verbose logging")

	// never print messages and usage
	rootCmd.SilenceErrors = true
	rootCmd.SilenceUsage = true

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)

	if cmd, err := rootCmd.ExecuteC(); err != nil {
		slog.Error("seeker failed", "err", err)
		if strings.HasPrefix(err.Error(), "unknown command") {
			_ = rootCmd.Help() // ./cmd bflmp
		} else {
			_ = cmd.Help() // ./cmd run gfagf (extra arg)
		}
		os.Exit(1)
	}
}

func doVersion(cmd *cobra.Command, args []string) error {
	if err := initSeeker(cmd, args); err != nil {
		return err
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		fmt.Println("seeker: version info not available")
	}

	if configPath != "" {
		fmt.Printf("config: %s\n", configPath)
	}
	fmt.Printf("seeker: %s\n", info.Main.Version)
	fmt.Printf("go:     %s\n", info.GoVersion)
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			fmt.Printf("commit: %s\n", s.Value)
		case "vcs.time":
			fmt.Printf("date:   %s\n", s.Value)
		case "vcs.modified":
			fmt.Printf("dirty:  %s\n", s.Value)
		}
	}
	fmt.Println()

	return nil
}

func doScan(cmd *cobra.Command, args []string) error {
	if err := initSeeker(cmd, args); err != nil {
		return err
	}

	ctx := cmd.Context()
	attrs := slog.Group("seeker",
		slog.String("cmd", "_scan"),
		slog.Int("pid", os.Getpid()),
	)
	ctx = log.ContextAttrs(ctx, attrs)
	seeker, err := NewSeeker(ctx, detectors, config)
	if err != nil {
		return err
	}
	return seeker.Do(ctx, os.Stdout)
}

func doRun(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("unsupported arguments: %s", strings.Join(args, ", "))
	}
	if err := initSeeker(cmd, args); err != nil {
		return err
	}

	ctx := cmd.Context()
	if config.Service.Mode != model.ServiceModeManual {
		return fmt.Errorf("only manual mode is supported now")
	}

	attrs := slog.Group("seeker",
		slog.String("cmd", "run"),
		slog.Int("pid", os.Getpid()),
	)
	ctx = log.ContextAttrs(ctx, attrs)
	slog.DebugContext(ctx, "", "environ", os.Environ())
	slog.DebugContext(ctx, "", "config", config)

	supervisor, err := service.SupervisorFromConfig(ctx, config.Service, configPath)
	if err != nil {
		return err
	}

	return supervisor.Do(ctx)
}

func initSeeker(_ *cobra.Command, _ []string) error {
	if envConfig, ok := os.LookupEnv("SEEKERCONFIG"); ok {
		configPath = envConfig
	} else if flagConfigFilePath != "" {
		configPath = flagConfigFilePath
	} else {
		for _, d := range []string{userConfigPath, "."} {
			path := filepath.Join(d, "seeker.yaml")
			if exists(path) {
				configPath = path
				break
			}
		}
	}

	// store default configuration
	if configPath == "" {
		config = model.DefaultConfig(context.Background())
		configPath = filepath.Join(userConfigPath, "seeker.yaml")
		err := os.MkdirAll(filepath.Dir(configPath), 0755)
		if err != nil {
			return fmt.Errorf("creating directory %s: %w", filepath.Dir(configPath), err)
		}

		f, err := os.Create(configPath)
		if err != nil {
			return fmt.Errorf("creating file %s: %w", configPath, err)
		}
		defer func() {
			_ = f.Close()
		}()
		enc := yaml.NewEncoder(f)
		err = enc.Encode(config)
		if err != nil {
			return fmt.Errorf("storing configuration: %w", err)
		}
	} else {
		var err error
		f, err := os.Open(configPath)
		if err != nil {
			return fmt.Errorf("storing opening config file: %w", err)
		}
		defer func() {
			_ = f.Close()
		}()
		config, err = model.LoadConfig(f)
		if err != nil {
			var cuerr model.CueError
			ok := errors.As(err, &cuerr)
			if ok {
				for _, d := range cuerr.Details() {
					slog.Error("validation error", d.Attr("detail"))
				}
			}
			return fmt.Errorf("parsing config: %w", err)
		}
	}

	// --verbose has a precedence over config file
	if flagVerbose {
		config.Service.Verbose = true
	}

	// initialize logging
	slog.SetDefault(log.New(config.Service.Verbose))

	slog.Debug("seeker run", "configPath", configPath)
	slog.Debug("seeker run", "config", config)
	return nil
}

func exists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

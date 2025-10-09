package main

import (
	"context"
	"fmt"
	stdlog "log"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/CZERTAINLY/Seeker/internal/log"
	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/CZERTAINLY/Seeker/internal/service"
	"gopkg.in/yaml.v3"

	"github.com/spf13/cobra"
)

var (
	userConfigPath     string // /default/config/path/seeker on given OS
	flagConfigFilePath string // value of --config flag
	configPath         string // actual config file used (if loaded)
	config             model.Config

	flagVerbose bool
)

func init() {
	d, err := os.UserConfigDir()
	if err != nil {
		panic(err)
	}
	userConfigPath = filepath.Join(d, "seeker")
}

func main() {
	cobra.OnInitialize(onInitialize)

	// root flags
	rootCmd.PersistentFlags().StringVar(&flagConfigFilePath, "config", "", "Config file to load - default is seeker.yaml in current directory or in "+userConfigPath)
	rootCmd.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "verbose logging")

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		slog.Error("seeker failed", "err", err)
		os.Exit(1)
	}
}

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
	Run: func(cmd *cobra.Command, args []string) {
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
	},
}

func doScan(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	return service.Scan(ctx, config)
}

func doRun(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	return service.Run(ctx, configPath, config)
}

func onInitialize() {
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
		config := model.DefaultConfig(context.Background())
		configPath = filepath.Join(userConfigPath, "seeker.yaml")
		f, err := os.Create(configPath)
		if err != nil {
			stdlog.Fatal(err)
		}
		defer func() {
			_ = f.Close()
		}()
		enc := yaml.NewEncoder(f)
		err = enc.Encode(config)
		if err != nil {
			stdlog.Fatal(err)
		}
	}

	// initialize logging
	level := slog.LevelInfo
	if flagVerbose || (config.Service.Verbose != nil && *config.Service.Verbose) {
		level = slog.LevelDebug
	}
	base := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: false,
		Level:     level,
	})
	ctxHandler := log.New(base)
	slog.SetDefault(slog.New(ctxHandler))
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err != nil
}

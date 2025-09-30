package main

import (
	"fmt"
	"iter"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/CZERTAINLY/Seeker/internal/bom"
	"github.com/CZERTAINLY/Seeker/internal/gitleaks"
	"github.com/CZERTAINLY/Seeker/internal/log"
	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/CZERTAINLY/Seeker/internal/scan"
	"github.com/CZERTAINLY/Seeker/internal/walk"
	"github.com/CZERTAINLY/Seeker/internal/x509"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	flagConfigFilePath string // value of --config flag
	defaultConfigPath  string // /default/config/path/seeker on given OS
	configPathUsed     string // actual config file used (if loaded)

	flagVerbose bool
)

func init() {
	d, err := os.UserConfigDir()
	if err != nil {
		panic(err)
	}
	defaultConfigPath = filepath.Join(d, "seeker")
}

func main() {
	cobra.OnInitialize(onInitialize)

	// root flags
	rootCmd.PersistentFlags().StringVar(&flagConfigFilePath, "config", "", "Config file to load - default is seeker.yaml in current directory or in "+defaultConfigPath)
	rootCmd.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "verbose logging")
	// root sub-commands
	rootCmd.AddCommand(alphaCmd)
	rootCmd.AddCommand(versionCmd)

	// alpha commands
	alphaCmd.AddCommand(scanCmd)

	// seeker alpha scan
	// -path
	scanCmd.Flags().String("path", ".", "local path to inspect")
	_ = viper.BindPFlag("alpha.scan.path", scanCmd.Flags().Lookup("path"))
	// - docker
	scanCmd.Flags().String("docker", "", "docker image to inspect, must be pulled-in")
	_ = viper.BindPFlag("alpha.scan.docker", scanCmd.Flags().Lookup("docker"))

	if err := rootCmd.Execute(); err != nil {
		slog.Error("seeker failed", "err", err)
		os.Exit(1)
	}
}

func doScan(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	flagPath := viper.GetString("alpha.scan.path")
	flagDocker := viper.GetString("alpha.scan.docker")

	var source iter.Seq2[walk.Entry, error]

	if flagDocker == "" {
		root, err := os.OpenRoot(flagPath)
		if err != nil {
			return fmt.Errorf("can't open path %s: %w", flagPath, err)
		}
		ctx = log.ContextAttrs(ctx, slog.Group(
			"source",
			slog.String("type", "filesystem"),
			slog.String("path", "flagPath"),
		))
		source = walk.Root(ctx, root)
	} else {
		ociImage, err := stereoscope.GetImageFromSource(
			ctx,
			flagDocker,
			image.DockerDaemonSource,
			nil,
		)
		if err != nil {
			return fmt.Errorf("can't open docker image, please docker pull %s first: %w", flagDocker, err)
		}
		ctx = log.ContextAttrs(ctx, slog.Group(
			"source",
			slog.String("type", "docker"),
			slog.String("image", flagDocker),
		))
		source = walk.Image(ctx, ociImage)
	}

	b := bom.NewBuilder()

	leaks, err := gitleaks.NewDetector()
	if err != nil {
		return err
	}

	var detectors = []scan.Detector{
		x509.Detector{},
		leaks,
	}
	scanner := scan.New(4, detectors)
	cntAll := 0
	cntDetections := 0
	for results, err := range scanner.Do(ctx, source) {
		cntAll++
		if err != nil {
			continue
		}

		cntDetections++
		for _, detection := range results {
			b.AppendComponents(detection.Components...)
		}
	}

	slog.InfoContext(ctx, "scan finished",
		"processed-files", cntAll,
		"detections", cntDetections,
	)
	stats := scanner.Stats()
	slog.DebugContext(ctx, "processing-stats",
		slog.Group(
			"pool",
			slog.Int("new", stats.PoolNewCounter),
			slog.Int("put", stats.PoolPutCounter),
			slog.Int("put(err)", stats.PoolPutErrCounter),
		),
	)
	if cntDetections > 0 {
		return b.AsJSON(os.Stdout)
	}
	return model.ErrNoMatch
}

var rootCmd = &cobra.Command{
	Use:          "seeker",
	Short:        "Tool detecting secrets and providing BOM",
	SilenceUsage: true,
}

var alphaCmd = &cobra.Command{
	Use:     "alpha",
	Aliases: []string{"a"},
	Short:   "alpha command has unstable API, may change at any time",
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "scan scans the provided source and report detected things",
	RunE:  doScan,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "version provide version of a seeker",
	Run: func(cmd *cobra.Command, args []string) {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			fmt.Println("seeker: version info not available")
		}

		if configPathUsed != "" {
			fmt.Printf("config: %s\n", configPathUsed)
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

func onInitialize() {
	// use
	if flagConfigFilePath != "" {
		// 1.) passed --config path, so load the file
		viper.SetConfigFile(flagConfigFilePath)
	} else if envConfig, ok := os.LookupEnv("SEEKERCONFIG"); ok {
		// 2.) or use SEEKERCONFIG - no underscore to not confuse viper
		viper.SetConfigFile(envConfig)
	} else {
		// 3.) try to load seeker.yaml from current directory or default path for config files
		viper.AddConfigPath(".")
		viper.AddConfigPath(defaultConfigPath)
		viper.SetConfigName("seeker")
		viper.SetConfigType("yaml")
	}

	// env variables are SEEKER with underscores
	viper.SetEnvPrefix("SEEKER")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		configPathUsed = viper.ConfigFileUsed()
	}

	// initialize logging
	level := slog.LevelInfo
	if flagVerbose {
		level = slog.LevelDebug
	}
	base := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: false,
		Level:     level,
	})
	ctxHandler := log.New(base)
	slog.SetDefault(slog.New(ctxHandler))
}

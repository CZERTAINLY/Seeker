package main

import (
	"fmt"
	"iter"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/CZERTAINLY/Seeker/internal/bom"
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
)

func init() {
	d, err := os.UserConfigDir()
	if err != nil {
		panic(err)
	}
	defaultConfigPath = filepath.Join(d, "seeker")
}

func main() {
	cobra.OnInitialize(initializeConfig)

	// root flags
	rootCmd.PersistentFlags().StringVar(&flagConfigFilePath, "config", "", "Config file to load - default is seeker.yaml in current directory or in "+defaultConfigPath)
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
		log.Fatal(err)
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
		source = walk.Image(ctx, ociImage)
	}

	b := bom.NewBuilder()

	var detectors = []scan.Detector{
		x509.Detector{},
	}
	scanner := scan.New(4, detectors)
	for results, err := range scanner.Do(ctx, source) {
		if err != nil {
			continue
		}

		for _, detection := range results {
			b.AppendComponents(detection.Components...)
		}
	}
	return b.AsJSON(os.Stdout)
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

func initializeConfig() {
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
}

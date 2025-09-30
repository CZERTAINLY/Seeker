package main

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/bom"
	"github.com/CZERTAINLY/Seeker/internal/log"
	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/CZERTAINLY/Seeker/internal/nmap"
	"github.com/CZERTAINLY/Seeker/internal/parallel"
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
	alphaCmd.AddCommand(nmapCmd)

	// seeker alpha scan
	// -path
	scanCmd.Flags().String("path", ".", "local path to inspect")
	_ = viper.BindPFlag("alpha.scan.path", scanCmd.Flags().Lookup("path"))
	// - docker
	scanCmd.Flags().String("docker", "", "docker image to inspect, must be pulled-in")
	_ = viper.BindPFlag("alpha.scan.docker", scanCmd.Flags().Lookup("docker"))

	// seeker alpha nmap
	// --nmap
	nmapCmd.Flags().String("nmap", "", "nmap binary to use, defaults to autodetect")
	_ = viper.BindPFlag("alpha.nmap.nmap", nmapCmd.Flags().Lookup("nmap"))
	// --timeout
	nmapCmd.Flags().Duration("timeout", 0, "timeout for a port scan (defaults to infinite)")
	_ = viper.BindPFlag("alpha.nmap.timeout", nmapCmd.Flags().Lookup("timeout"))
	// --ssh
	nmapCmd.Flags().Bool("ssh", false, "perform ssh scan (defaults to tls/https)")
	_ = viper.BindPFlag("alpha.nmap.ssh", nmapCmd.Flags().Lookup("ssh"))
	// --host
	nmapCmd.Flags().String("target", "", "connect to host (defaults to localhost). For testing only.")
	_ = viper.BindPFlag("alpha.nmap.target", nmapCmd.Flags().Lookup("target"))

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

var nmapCmd = &cobra.Command{
	Use:     "nmap",
	Aliases: []string{"n"},
	Short:   "nmap scans local network using nmap",
	RunE:    doNmap,
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

	var detectors = []scan.Detector{
		x509.Detector{},
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

func doNmap(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	flagNmap := viper.GetString("alpha.nmap.nmap")
	flagTimeout := viper.GetDuration("alpha.nmap.timeout")
	flagSSH := viper.GetBool("alpha.nmap.ssh")
	flagTarget := viper.GetString("alpha.nmap.target")

	nmapBinary, err := findNmapBinary(flagNmap)
	if err != nil {
		return err
	}

	var scanner nmap.Scanner
	if !flagSSH {
		scanner = nmap.NewTLS()
	} else {
		scanner = nmap.NewSSH()
	}
	scanner = scanner.WithNmapBinary(nmapBinary)

	b := bom.NewBuilder()
	pmap := parallel.NewMap(ctx, 4, func(ctx context.Context, addr netip.Addr) ([]model.Detection, error) {
		var tmoutCtx = ctx
		if flagTimeout > 0 {
			var cancel context.CancelFunc
			tmoutCtx, cancel = context.WithTimeout(ctx, flagTimeout)
			defer cancel()
		}
		ret, err := scanner.Detect(tmoutCtx, addr)
		return ret, err
	})

	var seq iter.Seq2[netip.Addr, error]
	if flagTarget == "" {
		seq = maps.All(map[netip.Addr]error{
			netip.MustParseAddr("127.0.0.1"): nil,
			netip.MustParseAddr("::1"):       nil,
		})
	} else {
		host, port, ok := strings.Cut(flagTarget, ":")
		if ok {
			scanner = scanner.WithPorts(port)
		}
		ip, err := resolveToAddr(host)
		if err != nil {
			return err
		}
		seq = maps.All(map[netip.Addr]error{
			ip: nil,
		})
	}

	now := time.Now()
	cntDetections := 0
	for detections, err := range pmap.Iter(seq) {
		if err != nil {
			slog.ErrorContext(ctx, "nmap scan failed", "err", err)
			continue
		}

		cntDetections++
		for _, detection := range detections {
			b.AppendComponents(detection.Components...)
			b.AppendDependencies(detection.Dependencies...)
		}
	}

	slog.InfoContext(ctx, "nmap finished",
		"addresses", "127.0.0.1, [::1]",
		"detections", cntDetections,
		"elapsed", time.Since(now).String(),
	)
	if cntDetections > 0 {
		return b.AsJSON(os.Stdout)
	}
	return model.ErrNoMatch
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

func resolveToAddr(host string) (netip.Addr, error) {
	// Try parsing directly as IP first
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip, nil
	}

	// Otherwise, resolve hostname via DNS
	ips, err := net.LookupIP(host)
	if err != nil {
		return netip.Addr{}, err
	}

	// Pick the first IPv4 or IPv6 address
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			return addr, nil
		}
	}

	return netip.Addr{}, fmt.Errorf("no valid IP found for host %q", host)
}

func findNmapBinary(flag string) (string, error) {
	if flag == "" {
		nmap, err := exec.LookPath("nmap")
		if err != nil {
			return "", err
		}
		return nmap, nil
	}
	_, err := os.Stat(flag)
	if err != nil {
		return "", err
	}
	return flag, nil
}

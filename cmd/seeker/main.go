package main

import (
	"fmt"
	"iter"
	"log"
	"os"

	"github.com/CZERTAINLY/Seeker/internal/bom"
	"github.com/CZERTAINLY/Seeker/internal/scan"
	"github.com/CZERTAINLY/Seeker/internal/walk"
	"github.com/CZERTAINLY/Seeker/internal/x509"
	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/spf13/cobra"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func doScan(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	flagPath, _ := cmd.Flags().GetString("path")
	flagDocker, _ := cmd.Flags().GetString("docker")

	var source iter.Seq2[walk.Entry, error]

	if flagDocker == "" {
		root, err := os.OpenRoot(flagPath)
		if err != nil {
			return fmt.Errorf("can't open -path %s: %w", flagPath, err)
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
			return fmt.Errorf("can't open -docker image, please docker pull %s first: %w", flagDocker, err)
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

func init() {
	// root flags
	// root commands
	rootCmd.AddCommand(alphaCmd)

	// alpha commands
	alphaCmd.AddCommand(scanCmd)

	// seeker alpha scan
	// -path
	scanCmd.Flags().String("path", ".", "local path to inspect")
	// - docker
	scanCmd.Flags().String("docker", "", "docker image to inspect, must be pulled-in")
}

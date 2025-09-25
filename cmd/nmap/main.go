package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"

	"github.com/CZERTAINLY/Seeker/internal/netscan"
)

func main() {
	ctx := context.Background()
	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	var addrPort = netip.MustParseAddrPort("23.88.35.44:443")
	log.Printf("Inspecting %s", addrPort.String())
	log.Printf("Inspecting port: %d", addrPort.Port())
	res, err := netscan.InspectTLS(ctx, addrPort)
	if err != nil {
		return fmt.Errorf("inspect TLS: %w", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

package main

import (
	"context"
	"fmt"
	"log"
	"net/netip"

	"github.com/CZERTAINLY/Seeker/internal/nmap"
)

func main() {
	s := nmap.NewTLS().WithPorts("443")

	a, err := netip.ParseAddr("23.88.35.44")
	if err != nil {
		log.Fatal(err)
	}
	d, err := s.Detect(context.Background(), a)
	if err != nil {
		log.Fatal(err)
	}

	for _, x := range d {
		fmt.Printf("%+v", x)
	}
}

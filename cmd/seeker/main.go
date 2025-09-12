package main

import (
	"context"
	"log"
	"os"

	"github.com/CZERTAINLY/Seeker/internal/walk"
)

func main() {
	if err := run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, _ []string) error {
	root, err := os.OpenRoot(".")
	if err != nil {
		return err
	}
	for entry, err := range walk.Root(ctx, root) {
		if err != nil {
			log.Printf("E: err=%+v", err)
		} else {
			log.Printf("F: path=%s", entry.Path())
		}
	}
	return nil
}

package service

import (
	"context"
	"fmt"
	"os"

	"github.com/CZERTAINLY/Seeker/internal/model"
)

// Run implements CLI run command
func Run(ctx context.Context, configPath string, config model.Config) error {
	if config.Service.Mode != model.ServiceModeManual {
		return fmt.Errorf("only manual mode is supported now")
	}

	return fmt.Errorf("not yet implemented")
}

func Scan(ctx context.Context, config model.Config) error {
	scanner, err := NewScanner(ctx, config)
	if err != nil {
		return err
	}
	return scanner.Do(ctx, os.Stdout)
}

package service

import (
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Command struct {
		Path    string            `mapstructure:"path"`
		Args    []string          `mapstructure:"args"`
		Env     map[string]string `mapstructure:"env"`
		Timeout time.Duration     `mapstructure:"timeout"`
	} `mapstructure:"command"`
	ScanEach time.Duration `mapstructure:"scan_each"`
}

func ParseConfig(key string) (Config, error) {
	var svc Config
	err := viper.UnmarshalKey(key, &svc)
	return svc, err
}

func (c Config) Cmd() Command {
	env := make([]string, len(c.Command.Env))
	for k, v := range c.Command.Env {
		if strings.HasPrefix(v, "$") {
			v = os.ExpandEnv(v)
		}
		env = append(env, strings.ToUpper(k)+"="+v)
	}
	return Command{
		Path:    c.Command.Path,
		Args:    c.Command.Args,
		Env:     env,
		Timeout: c.Command.Timeout,
	}
}

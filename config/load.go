package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// Load loads configuration into the provided struct 'cfg'.
// It searches for configuration files in the following order, with each subsequent file overriding the previous:
//
// 1. /etc/${appName}/config.yaml
// 2. ~/.${appName}/config.yaml (in the user's home directory)
// 3. ./config.yaml (in the current directory)
//
// After processing config files, it applies any matching environment variables.
//
// Parameters:
//   - ctx: context for logging
//   - appName: name of the application, used for directory and environment variable prefixing
//   - cfg: pointer to a struct where the configuration will be loaded
//
// Returns an error if unable to read config files or unmarshal the configuration.
func Load(ctx context.Context, appName string, cfg interface{}) error {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")

	// 1. Add /etc directory
	v.AddConfigPath(filepath.Join("/etc", appName))

	// 2. Add home directory
	home, err := os.UserHomeDir()
	if err == nil {
		v.AddConfigPath(filepath.Join(home, "."+appName))
	} else {
		slog.WarnContext(ctx, "failed to get user home directory, will skip evaluating home directory config file",
			"error", err.Error())
	}

	// 3. Add current directory
	v.AddConfigPath(".")

	// Try to read the config file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return fmt.Errorf("error reading config file: %w", err)
		}
		slog.DebugContext(ctx, "no configuration file found")
	} else {
		slog.DebugContext(ctx, "configuration file loaded", "file", v.ConfigFileUsed())
	}

	// 4. Override with environment variables
	v.SetEnvPrefix(appName)
	v.AutomaticEnv()

	// Log all keys that have been set
	allSettings := v.AllSettings()
	for key := range allSettings {
		slog.DebugContext(ctx, "environment variable set", "key", key, "value", v.Get(key))
	}

	// Unmarshal the configuration into the provided struct
	if err := v.Unmarshal(cfg); err != nil {
		return fmt.Errorf("unable to decode config into struct: %w", err)
	}

	slog.DebugContext(ctx, "configuration loaded")
	return nil
}

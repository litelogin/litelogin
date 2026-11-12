package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// EnvConfig overrides the config file's location.
const EnvConfig = "LITELOGIN_CONFIG"

// Config is the CLI config file. It maps AWS profiles to the Admin API
// endpoint of the deployment their credentials manage, so --profile alone
// is enough once `litelogin configure` has run.
type Config struct {
	Profiles map[string]ProfileConfig `json:"profiles"`
}

// ProfileConfig is the config for one AWS profile.
type ProfileConfig struct {
	Endpoint string `json:"endpoint"`
}

// ConfigPath returns the config file's path: $LITELOGIN_CONFIG, or
// litelogin/config.json in the user's config directory.
func ConfigPath() (string, error) {
	if p := os.Getenv(EnvConfig); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "litelogin", "config.json"), nil
}

// LoadConfig reads the config file. A missing file is an empty config.
func LoadConfig(path string) (*Config, error) {
	cfg := &Config{Profiles: map[string]ProfileConfig{}}
	raw, err := os.ReadFile(path) //nolint:gosec // the path is the user's own config file
	if errors.Is(err, fs.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]ProfileConfig{}
	}
	return cfg, nil
}

// Save writes the config file.
func (c *Config) Save(path string) error {
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

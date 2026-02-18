package config

import (
	"encoding/json"
	"os"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Port                  string            `json:"port"`
	DefaultSourcePassword string            `json:"default_source_password"`
	Mounts                map[string]string `json:"mounts"`
	AdminPassword         string            `json:"admin_password"`
	AdminUser             string            `json:"admin_user"`
	Location              string            `json:"location"`
	AdminEmail            string            `json:"admin_email"`
	HostName              string            `json:"hostname"`
	ConfigPath            string            `json:"-"`
	LowLatencyMode        bool              `json:"low_latency_mode"`
	MaxListeners          int               `json:"max_listeners"`
	DisabledMounts        map[string]bool   `json:"disabled_mounts"`
}

func HashPassword(p string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(p), 12)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	config := &Config{}
	err = decoder.Decode(config)
	if err != nil {
		return nil, err
	}

	config.ConfigPath = path

	if config.Port == "" { config.Port = "8000" }
	if config.AdminUser == "" { config.AdminUser = "admin" }
	if config.Mounts == nil { config.Mounts = make(map[string]string) }
	if config.MaxListeners == 0 { config.MaxListeners = 100 }
	if config.DisabledMounts == nil { config.DisabledMounts = make(map[string]bool) }

	return config, nil
}

func (c *Config) SaveConfig() error {
	data, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.ConfigPath, data, 0600)
}

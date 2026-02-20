package config

import (
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"os"
)

const (
	RoleSuperAdmin = "superadmin"
	RoleAdmin      = "admin"
)

type User struct {
	Username string            `json:"username"`
	Password string            `json:"password"` // Hashed
	Role     string            `json:"role"`
	Mounts   map[string]string `json:"mounts"` // Backward compatibility
}

type RelayConfig struct {
	URL       string `json:"url"`      // e.g. http://master:8000/stream
	Mount     string `json:"mount"`    // Local mount point
	Password  string `json:"password"` // If the master requires one
	BurstSize int    `json:"burst_size"`
	Enabled   bool   `json:"enabled"`
}

type MountSettings struct {
	Password  string `json:"password"` // Hashed
	BurstSize int    `json:"burst_size"`
}

type TranscoderConfig struct {
	Name        string `json:"name"`
	InputMount  string `json:"input_mount"`
	OutputMount string `json:"output_mount"`
	Format      string `json:"format"` // "mp3" or "opus"
	Bitrate     int    `json:"bitrate"`
	Enabled     bool   `json:"enabled"`
}

type Config struct {
	BindHost              string            `json:"bind_host"`
	Port                  string            `json:"port"`
	DefaultSourcePassword string            `json:"default_source_password"`
	Mounts                map[string]string `json:"mounts"` // Legacy global mounts

	// New Advanced Settings
	AdvancedMounts map[string]*MountSettings `json:"advanced_mounts"`
	Relays         []*RelayConfig            `json:"relays"`
	Transcoders    []*TranscoderConfig       `json:"transcoders"`
	BannedIPs      []string                  `json:"banned_ips"`

	AdminPassword  string            `json:"admin_password"`
	AdminUser      string            `json:"admin_user"`
	Location       string            `json:"location"`
	AdminEmail     string            `json:"admin_email"`
	BaseURL        string            `json:"base_url"` // e.g. https://radio.example.com
	HostName       string            `json:"hostname"`
	ConfigPath     string            `json:"-"`
	LowLatencyMode bool              `json:"low_latency_mode"`
	MaxListeners   int               `json:"max_listeners"`
	DisabledMounts map[string]bool   `json:"disabled_mounts"`
	VisibleMounts  map[string]bool   `json:"visible_mounts"`  // map[mount]is_visible
	FallbackMounts map[string]string `json:"fallback_mounts"` // map[source]fallback

	// UI Customization
	PageTitle    string `json:"page_title"`
	PageSubtitle string `json:"page_subtitle"`

	// HTTPS Configuration
	UseHTTPS         bool     `json:"use_https"`
	AutoHTTPS        bool     `json:"auto_https"` // ACME
	HTTPSPort        string   `json:"https_port"`
	CertFile         string   `json:"cert_file"`
	KeyFile          string   `json:"key_file"`
	ACMEEmail        string   `json:"acme_email"`
	ACMEDirectoryURL string   `json:"acme_directory_url"` // Support for custom CAs (Step-CA, etc)
	Domains          []string `json:"domains"`

	// Directory Listing (YP)
	DirectoryListing bool   `json:"directory_listing"`
	DirectoryServer  string `json:"directory_server"`

	// Multi-tenant
	Users map[string]*User `json:"users"`
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
	config.setDefaults()

	return config, nil
}

func (config *Config) setDefaults() {
	config.setBasicDefaults()
	config.initMapsAndArrays()
	config.handleMigrations()
}

func (config *Config) setBasicDefaults() {
	if config.BindHost == "" {
		config.BindHost = "0.0.0.0"
	}
	if config.Port == "" {
		config.Port = "8000"
	}
	if config.AdminUser == "" {
		config.AdminUser = "admin"
	}
	if config.MaxListeners == 0 {
		config.MaxListeners = 100
	}
	if config.PageTitle == "" {
		config.PageTitle = "TinyIce"
	}
	if config.PageSubtitle == "" {
		config.PageSubtitle = "Live Streaming Server powered by Go"
	}
	if config.HTTPSPort == "" {
		config.HTTPSPort = "443"
	}
	if config.DirectoryServer == "" {
		config.DirectoryServer = "http://dir.xiph.org/cgi-bin/yp-cgi"
	}
}

func (config *Config) initMapsAndArrays() {
	if config.Mounts == nil {
		config.Mounts = make(map[string]string)
	}
	if config.DisabledMounts == nil {
		config.DisabledMounts = make(map[string]bool)
	}
	if config.VisibleMounts == nil {
		config.VisibleMounts = make(map[string]bool)
	}
	if config.FallbackMounts == nil {
		config.FallbackMounts = make(map[string]string)
	}
	if config.Users == nil {
		config.Users = make(map[string]*User)
	}
	if config.AdvancedMounts == nil {
		config.AdvancedMounts = make(map[string]*MountSettings)
	}
	if config.Relays == nil {
		config.Relays = make([]*RelayConfig, 0)
	}
	if config.Transcoders == nil {
		config.Transcoders = make([]*TranscoderConfig, 0)
	}
	if config.BannedIPs == nil {
		config.BannedIPs = make([]string, 0)
	}
}

func (config *Config) handleMigrations() {
	for _, r := range config.Relays {
		r.Enabled = true // Migration logic
	}

	// Migration/Backward compatibility
	if config.AdminUser != "" && config.Users[config.AdminUser] == nil {
		config.Users[config.AdminUser] = &User{
			Username: config.AdminUser,
			Password: config.AdminPassword,
			Role:     RoleSuperAdmin,
			Mounts:   make(map[string]string),
		}
	}
}

func (c *Config) SaveConfig() error {
	data, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.ConfigPath, data, 0600)
}

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/server"
	"github.com/sirupsen/logrus"
)

var (
	configPath  = flag.String("config", "tinyice.json", "Path to configuration file")
	bindHost    = flag.String("host", "0.0.0.0", "Network interface to bind to")
	bindPort    = flag.String("port", "", "Network port to bind to (overrides config)")
	httpsPort   = flag.String("https-port", "", "Network port for HTTPS (overrides config)")
	useHTTPS    = flag.Bool("use-https", false, "Enable HTTPS (overrides config)")
	autoHTTPS   = flag.Bool("auto-https", false, "Enable Auto-HTTPS via ACME (overrides config)")
	domains     = flag.String("domains", "", "Comma-separated list of domains for SSL (overrides config)")
	logFile     = flag.String("log-file", "", "Path to log file (default is stdout)")
	logLevel    = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	jsonLogs    = flag.Bool("json-logs", false, "Enable JSON logging format")
	daemon      = flag.Bool("daemon", false, "Run in background (daemon mode)")
	pidFile     = flag.String("pid-file", "", "Path to PID file")
	authLogFile = flag.String("auth-log-file", "", "Path to separate authentication audit log")
)

func generateRandomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "insecure_fallback"
	}
	return hex.EncodeToString(b)
}

func initLogging() *logrus.Logger {
	// Set Level
	level, err := logrus.ParseLevel(strings.ToLower(*logLevel))
	if err != nil {
		logrus.Warnf("Invalid log level '%s', defaulting to info", *logLevel)
		level = logrus.InfoLevel
	}
	logrus.SetLevel(level)

	// Set Format
	var formatter logrus.Formatter
	if *jsonLogs {
		formatter = &logrus.JSONFormatter{}
	} else {
		formatter = &logrus.TextFormatter{
			FullTimestamp: true,
		}
	}
	logrus.SetFormatter(formatter)

	// Set Output
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logrus.Fatalf("Failed to open log file %s: %v", *logFile, err)
		}
		logrus.SetOutput(f)
	} else {
		logrus.SetOutput(os.Stdout)
	}

	// Create Auth Logger if needed
	if *authLogFile != "" {
		authLogger := logrus.New()
		authLogger.SetLevel(level)
		authLogger.SetFormatter(formatter)
		f, err := os.OpenFile(*authLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logrus.Fatalf("Failed to open auth log file %s: %v", *authLogFile, err)
		}
		authLogger.SetOutput(f)
		return authLogger
	}

	return nil
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of TinyIce:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nSubcommands:\n")
		fmt.Fprintf(os.Stderr, "  get <option>          Get a configuration value\n")
		fmt.Fprintf(os.Stderr, "  set <option> <value>  Set a configuration value\n")
		fmt.Fprintf(os.Stderr, "  dump-config           Pretty-print the current configuration\n")
	}
	flag.Parse()

	authLogger := initLogging()
	handleDaemonMode()

	actualPidFile := *pidFile
	if actualPidFile == "" {
		actualPidFile = "tinyice.pid"
	}

	if err := os.WriteFile(actualPidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
		logrus.Errorf("Failed to write PID file: %v", err)
	}
	defer os.Remove(actualPidFile)

	ensureConfigExists()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logrus.Fatalf("Failed to load config: %v", err)
	}

	if handleCommands(cfg) {
		return
	}

	// Override config with CLI flags if provided
	if *bindHost != "0.0.0.0" || cfg.BindHost == "" {
		cfg.BindHost = *bindHost
	}
	if *bindPort != "" {
		cfg.Port = *bindPort
	}
	if *httpsPort != "" {
		cfg.HTTPSPort = *httpsPort
	}
	if *useHTTPS {
		cfg.UseHTTPS = true
	}
	if *autoHTTPS {
		cfg.AutoHTTPS = true
	}
	if *domains != "" {
		cfg.Domains = strings.Split(*domains, ",")
	}

	srv := server.NewServer(cfg, authLogger)

	// Signal handling
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		if err := srv.Start(); err != nil && err.Error() != "http: Server closed" {
			logrus.Fatalf("Server failed: %v", err)
		}
	}()

	runEventLoop(srv, sigs)
}

func handleCommands(cfg *config.Config) bool {
	args := flag.Args()
	if len(args) == 0 {
		return false
	}

	cmd := args[0]
	switch cmd {
	case "dump-config":
		data, _ := json.MarshalIndent(cfg, "", "    ")
		colorized := colorizeJSON(string(data))
		fmt.Println(colorized)
		return true

	case "help":
		printHelp()
		return true

	case "reload":
		data, err := os.ReadFile("tinyice.pid")
		if err != nil {
			fmt.Println("Error: TinyIce does not appear to be running (could not read tinyice.pid)")
			return true
		}
		var pid int
		fmt.Sscanf(string(data), "%d", &pid)
		process, err := os.FindProcess(pid)
		if err != nil {
			fmt.Printf("Error: Could not find process with PID %d\n", pid)
			return true
		}
		err = process.Signal(syscall.SIGHUP)
		if err != nil {
			fmt.Printf("Error signaling process: %v\n", err)
		} else {
			fmt.Printf("Sent reload signal (SIGHUP) to process %d\n", pid)
		}
		return true

	case "get":
		if len(args) < 2 {
			fmt.Println("Usage: get <option>")
			return true
		}
		val := getField(cfg, args[1])
		fmt.Printf("%s = %v\n", args[1], val)
		return true

	case "set":
		if len(args) < 3 {
			fmt.Println("Usage: set <option> <value>")
			return true
		}
		if setField(cfg, args[1], args[2]) {
			cfg.SaveConfig()
			fmt.Printf("Updated %s to %s\n", args[1], args[2])
		} else {
			fmt.Printf("Unknown or unsupported option: %s\n", args[1])
		}
		return true
	}

	return false
}

func getField(cfg *config.Config, field string) interface{} {
	switch strings.ToLower(field) {
	case "host", "bind_host":
		return cfg.BindHost
	case "port":
		return cfg.Port
	case "hostname":
		return cfg.HostName
	case "use_https":
		return cfg.UseHTTPS
	case "auto_https":
		return cfg.AutoHTTPS
	case "https_port":
		return cfg.HTTPSPort
	case "page_title":
		return cfg.PageTitle
	case "page_subtitle":
		return cfg.PageSubtitle
	case "acme_email":
		return cfg.ACMEEmail
	case "acme_directory_url":
		return cfg.ACMEDirectoryURL
	case "domains":
		return cfg.Domains
	case "location":
		return cfg.Location
	case "admin_email":
		return cfg.AdminEmail
	case "base_url":
		return cfg.BaseURL
	case "low_latency_mode":
		return cfg.LowLatencyMode
	case "max_listeners":
		return cfg.MaxListeners
	case "directory_listing":
		return cfg.DirectoryListing
	case "directory_server":
		return cfg.DirectoryServer
	case "cert_file":
		return cfg.CertFile
	case "key_file":
		return cfg.KeyFile
	}
	return "unknown"
}

func setField(cfg *config.Config, field, value string) bool {
	switch strings.ToLower(field) {
	case "host", "bind_host":
		cfg.BindHost = value
	case "port":
		cfg.Port = value
	case "hostname":
		cfg.HostName = value
	case "use_https":
		cfg.UseHTTPS = (value == "true")
	case "auto_https":
		cfg.AutoHTTPS = (value == "true")
	case "https_port":
		cfg.HTTPSPort = value
	case "page_title":
		cfg.PageTitle = value
	case "page_subtitle":
		cfg.PageSubtitle = value
	case "acme_email":
		cfg.ACMEEmail = value
	case "acme_directory_url":
		cfg.ACMEDirectoryURL = value
	case "domains":
		cfg.Domains = strings.Split(value, ",")
	case "location":
		cfg.Location = value
	case "admin_email":
		cfg.AdminEmail = value
	case "base_url":
		cfg.BaseURL = value
	case "low_latency_mode":
		cfg.LowLatencyMode = (value == "true")
	case "max_listeners":
		fmt.Sscanf(value, "%d", &cfg.MaxListeners)
	case "directory_listing":
		cfg.DirectoryListing = (value == "true")
	case "directory_server":
		cfg.DirectoryServer = value
	case "cert_file":
		cfg.CertFile = value
	case "key_file":
		cfg.KeyFile = value
	default:
		return false
	}
	return true
}

func printHelp() {
	fmt.Println("\033[1mTinyIce CLI Help\033[0m")
	fmt.Println("\nUsage:")
	fmt.Println("  tinyice <command> [args]")
	fmt.Println("\nCommands:")
	fmt.Println("  get <option>          Display the current value of a configuration option")
	fmt.Println("  set <option> <value>  Update a configuration option and save to tinyice.json")
	fmt.Println("  reload                Trigger a hot configuration reload of the running server")
	fmt.Println("  dump-config           Display the full configuration with syntax highlighting")
	fmt.Println("  help                  Display this help message")
	fmt.Println("\nConfiguration Options (use with get/set):")
	fmt.Println("  \033[36mBasic Settings:\033[0m")
	fmt.Println("    bind_host, port, hostname, location, base_url, max_listeners")
	fmt.Println("\n  \033[36mHTTPS & SSL:\033[0m")
	fmt.Println("    use_https (bool), auto_https (bool), https_port, domains (comma-sep)")
	fmt.Println("    acme_email, acme_directory_url, cert_file, key_file")
	fmt.Println("\n  \033[36mUI Customization:\033[0m")
	fmt.Println("    page_title, page_subtitle")
	fmt.Println("\n  \033[36mAdvanced:\033[0m")
	fmt.Println("    low_latency_mode (bool), directory_listing (bool), directory_server")
	fmt.Println("\nExamples:")
	fmt.Println("  ./tinyice set auto_https true")
	fmt.Println("  ./tinyice set domains stream.example.com,radio.example.com")
	fmt.Println("  ./tinyice get max_listeners")
}

func colorizeJSON(input string) string {
	// Simple ANSI colorizer for JSON
	// Colors: Keys (Cyan), Strings (Green), Numbers (Yellow), Booleans/Null (Magenta)
	lines := strings.Split(input, "\n")
	for i, line := range lines {
		// Colorize Keys
		if strings.Contains(line, "\":") {
			parts := strings.SplitN(line, "\":", 2)
			lines[i] = "\033[36m" + parts[0] + "\"\033[0m: " + colorValue(parts[1])
		}
	}
	return strings.Join(lines, "\n")
}

func colorValue(val string) string {
	val = strings.TrimSpace(val)
	if strings.HasPrefix(val, "\"") {
		return "\033[32m" + val + "\033[0m" // Green string
	}
	if val == "true" || val == "false" || val == "null" {
		return "\033[35m" + val + "\033[0m" // Magenta bool/null
	}
	// Assume number
	return "\033[33m" + val + "\033[0m" // Yellow number
}

func handleDaemonMode() {
	if *daemon && os.Getenv("TINYICE_DAEMON") != "1" {
		args := []string{}
		for _, arg := range os.Args[1:] {
			if arg != "-daemon" && !strings.HasPrefix(arg, "-daemon=") {
				args = append(args, arg)
			}
		}
		cmd := exec.Command(os.Args[0], args...)
		cmd.Env = append(os.Environ(), "TINYICE_DAEMON=1")
		if err := cmd.Start(); err != nil {
			logrus.Fatalf("Failed to start daemon: %v", err)
		}
		fmt.Printf("TinyIce starting in background (PID: %d)\n", cmd.Process.Pid)
		os.Exit(0)
	}
}

func ensureConfigExists() {
	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		logrus.Info("Config file not found, generating secure defaults...")

		defaultSourcePass := generateRandomString(12)
		liveMountPass := generateRandomString(12)
		adminPass := generateRandomString(12)

		hDefaultSource, _ := config.HashPassword(defaultSourcePass)
		hLiveMount, _ := config.HashPassword(liveMountPass)
		hAdmin, _ := config.HashPassword(adminPass)

		defaultCfg := config.Config{
			BindHost:              *bindHost,
			Port:                  "8000",
			DefaultSourcePassword: hDefaultSource,
			Mounts: map[string]string{
				"/live": hLiveMount,
			},
			AdminUser:     "admin",
			AdminPassword: hAdmin,
			Users: map[string]*config.User{
				"admin": {
					Username: "admin",
					Password: hAdmin,
					Role:     config.RoleSuperAdmin,
					Mounts:   make(map[string]string),
				},
			},
			HostName:     "localhost",
			Location:     "Earth",
			AdminEmail:   "admin@localhost",
			PageTitle:    "TinyIce",
			PageSubtitle: "Live streaming network powered by Go",
			UseHTTPS:     false,
			HTTPSPort:    "443",
		}

		data, _ := json.MarshalIndent(defaultCfg, "", "    ")
		if err := os.WriteFile(*configPath, data, 0600); err != nil {
			logrus.Fatalf("Failed to create secure config: %v", err)
		}

		fmt.Println("**************************************************")
		fmt.Println("  FIRST RUN: SECURE CREDENTIALS GENERATED")
		fmt.Printf("  Admin User:      admin\n")
		fmt.Printf("  Admin Password:  %s\n", adminPass)
		fmt.Printf("  Default Source Pass: %s\n", defaultSourcePass)
		fmt.Printf("  Mount /live Pass:    %s\n", liveMountPass)
		fmt.Println("  Stored in:", *configPath)
		fmt.Println("**************************************************")
	} else {
		logrus.WithField("path", *configPath).Info("Starting TinyIce with existing configuration")
		fmt.Printf("Note: To reset all credentials, run: rm %s && ./tinyice\n", *configPath)
	}
}

func runEventLoop(srv *server.Server, sigs chan os.Signal) {
	for {
		sig := <-sigs
		switch sig {
		case syscall.SIGHUP:
			logrus.Info("Received SIGHUP, reloading configuration...")
			newCfg, err := config.LoadConfig(*configPath)
			if err != nil {
				logrus.Errorf("Failed to reload config: %v", err)
				continue
			}
			srv.ReloadConfig(newCfg)
		case syscall.SIGINT, syscall.SIGTERM:
			logrus.Infof("Received %v, shutting down...", sig)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				logrus.Errorf("Graceful shutdown failed: %v", err)
			}
			logrus.Info("TinyIce stopped")
			return
		}
	}
}

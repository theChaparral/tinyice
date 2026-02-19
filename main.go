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
	}
	flag.Parse()

	authLogger := initLogging()
	handleDaemonMode()

	if *pidFile != "" {
		if err := os.WriteFile(*pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
			logrus.Errorf("Failed to write PID file: %v", err)
		}
		defer os.Remove(*pidFile)
	}

	ensureConfigExists()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logrus.Fatalf("Failed to load config: %v", err)
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

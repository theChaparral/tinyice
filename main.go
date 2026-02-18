package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/syso/tinyice/config"
	"github.com/syso/tinyice/server"
)

var (
	configPath = flag.String("config", "tinyice.json", "Path to configuration file")
	logFile    = flag.String("log-file", "", "Path to log file (default is stdout)")
	logLevel   = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	jsonLogs   = flag.Bool("json-logs", false, "Enable JSON logging format")
)

func generateRandomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "insecure_fallback"
	}
	return hex.EncodeToString(b)
}

func initLogging() {
	// Set Level
	level, err := logrus.ParseLevel(strings.ToLower(*logLevel))
	if err != nil {
		logrus.Warnf("Invalid log level '%s', defaulting to info", *logLevel)
		level = logrus.InfoLevel
	}
	logrus.SetLevel(level)

	// Set Format
	if *jsonLogs {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}

	// Set Output
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logrus.Fatalf("Failed to open log file %s: %v", *logFile, err)
		}
		// MultiWriter to log to both file and stdout if needed, 
		// but standard practice for "background" is just file.
		// Let's stick to the file if provided.
		logrus.SetOutput(f)
	} else {
		logrus.SetOutput(os.Stdout)
	}
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of TinyIce:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	initLogging()

	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		logrus.Info("Config file not found, generating secure defaults...")
		
		defaultSourcePass := generateRandomString(12)
		liveMountPass := generateRandomString(12)
		adminPass := generateRandomString(12)

		hDefaultSource, _ := config.HashPassword(defaultSourcePass)
		hLiveMount, _ := config.HashPassword(liveMountPass)
		hAdmin, _ := config.HashPassword(adminPass)

		defaultCfg := config.Config{
			Port:                  "8000",
			DefaultSourcePassword: hDefaultSource,
			Mounts: map[string]string{
				"/live": hLiveMount,
			},
			AdminUser:     "admin",
			AdminPassword: hAdmin,
			HostName:      "localhost",
			Location:      "Earth",
			AdminEmail:    "admin@localhost",
			PageTitle:     "TinyIce",
			PageSubtitle:  "Live streaming network powered by Go",
			UseHTTPS:      false,
			HTTPSPort:     "443",
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

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logrus.Fatalf("Failed to load config: %v", err)
	}

	srv := server.NewServer(cfg)
	if err := srv.Start(); err != nil {
		logrus.Fatalf("Server failed: %v", err)
	}
}

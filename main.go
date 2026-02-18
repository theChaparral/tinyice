package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/syso/tinyice/config"
	"github.com/syso/tinyice/server"
)

func generateRandomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "insecure_fallback"
	}
	return hex.EncodeToString(b)
}

func main() {
	configPath := flag.String("config", "tinyice.json", "Path to configuration file")
	flag.Parse()

	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		log.Println("Config file not found, generating secure defaults...")
		
		defaultSourcePass := generateRandomString(12)
		liveMountPass := generateRandomString(12)
		adminPass := generateRandomString(12)

		defaultCfg := config.Config{
			Port:                  "8000",
			DefaultSourcePassword: config.HashPassword(defaultSourcePass),
			Mounts: map[string]string{
				"/live": config.HashPassword(liveMountPass),
			},
			AdminUser:     "admin",
			AdminPassword: config.HashPassword(adminPass),
			HostName:      "localhost",
			Location:      "Earth",
			AdminEmail:    "admin@localhost",
		}

		data, _ := json.MarshalIndent(defaultCfg, "", "    ")
		if err := os.WriteFile(*configPath, data, 0600); err != nil {
			log.Fatalf("Failed to create secure config: %v", err)
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
		log.Printf("Starting TinyIce with existing configuration: %s", *configPath)
		fmt.Printf("Note: To reset all credentials, run: rm %s && ./tinyice\n", *configPath)
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	srv := server.NewServer(cfg)
	if err := srv.Start(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

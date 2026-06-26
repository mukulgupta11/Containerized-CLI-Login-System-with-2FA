package main

import (
	"log"
	"os"

	"github.com/osto-cybersecurity/cli-login/internal/auth"
	"github.com/osto-cybersecurity/cli-login/internal/cli"
	"github.com/osto-cybersecurity/cli-login/internal/config"
	"github.com/osto-cybersecurity/cli-login/internal/db"
)

func main() {
	// 1. Load Configurations
	cfg := config.LoadConfig()

	// 2. Connect to database
	database, err := db.ConnectDB(cfg)
	if err != nil {
		log.Fatalf("Critical error connecting to database: %v\n", err)
	}
	defer database.Close()

	// 3. Run database migrations
	err = db.Migrate(database)
	if err != nil {
		log.Fatalf("Critical error running migrations: %v\n", err)
	}

	// 4. Initialize services
	authService := auth.NewAuthService(database, cfg)

	// 5. Initialize & Run Shell
	shell := cli.NewShell(authService)

	// Handle clean exits triggered by the shell panic(nil) pattern
	defer func() {
		if r := recover(); r != nil {
			// If r is nil (from panic(nil)), it means it was a normal exit
			if r != nil {
				log.Printf("Process panicked: %v\n", r)
				os.Exit(1)
			}
		}
		os.Exit(0)
	}()

	shell.Run()
}

package db

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/osto-cybersecurity/cli-login/internal/config"
	_ "github.com/lib/pq"
)

// ConnectDB establishes a connection to the PostgreSQL database, retrying if necessary.
func ConnectDB(cfg *config.Config) (*sql.DB, error) {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBSSLMode)

	var db *sql.DB
	var err error

	// Retry database connection as the DB container might take a few seconds to spin up completely
	maxRetries := 10
	for i := 1; i <= maxRetries; i++ {
		db, err = sql.Open("postgres", connStr)
		if err == nil {
			err = db.Ping()
			if err == nil {
				log.Printf("Successfully connected to the database after %d attempts.\n", i)
				return db, nil
			}
		}

		log.Printf("Failed to connect to database (attempt %d/%d): %v. Retrying in 2s...\n", i, maxRetries, err)
		time.Sleep(2 * time.Second)
	}

	return nil, fmt.Errorf("could not connect to database after %d retries: %w", maxRetries, err)
}

// Migrate database schema to ensure tables and indexes are present
func Migrate(db *sql.DB) error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(50) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			totp_secret VARCHAR(255) DEFAULT '',
			totp_enabled BOOLEAN DEFAULT FALSE,
			failed_attempts INT DEFAULT 0,
			locked_until TIMESTAMP WITH TIME ZONE NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			last_login_at TIMESTAMP WITH TIME ZONE NULL
		);`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id VARCHAR(255) PRIMARY KEY,
			user_id INT REFERENCES users(id) ON DELETE CASCADE,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);`,
	}

	for _, query := range migrations {
		_, err := db.Exec(query)
		if err != nil {
			return fmt.Errorf("failed executing migration query: %w", err)
		}
	}

	log.Println("Database schema migrations executed successfully.")
	return nil
}

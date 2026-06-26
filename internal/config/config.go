package config

import (
	"os"
	"strconv"
)

// Config holds all the configuration parameters for the application.
type Config struct {
	DBHost                 string
	DBPort                 string
	DBUser                 string
	DBPassword             string
	DBName                 string
	DBSSLMode              string
	SessionTimeoutMinutes  int
	LockoutAttempts        int
	LockoutDurationMinutes int
}

// LoadConfig reads configuration from environment variables and sets defaults if they are missing.
func LoadConfig() *Config {
	return &Config{
		DBHost:                 getEnv("DB_HOST", "localhost"),
		DBPort:                 getEnv("DB_PORT", "5432"),
		DBUser:                 getEnv("DB_USER", "postgres"),
		DBPassword:             getEnv("DB_PASSWORD", "postgres"),
		DBName:                 getEnv("DB_NAME", "cli_login_db"),
		DBSSLMode:              getEnv("DB_SSLMODE", "disable"),
		SessionTimeoutMinutes:  getEnvAsInt("SESSION_TIMEOUT_MINUTES", 15),
		LockoutAttempts:        getEnvAsInt("LOCKOUT_ATTEMPTS", 5),
		LockoutDurationMinutes: getEnvAsInt("LOCKOUT_DURATION_MINUTES", 15),
	}
}

// getEnv retrieves the value of the environment variable named by the key.
// It returns defaultValue if the variable is not present.
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getEnvAsInt retrieves the value of the environment variable named by the key as an integer.
// It returns defaultValue if the variable is not present or cannot be parsed.
func getEnvAsInt(name string, defaultValue int) int {
	valueStr := os.Getenv(name)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

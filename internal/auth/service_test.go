package auth

import (
	"os"
	"testing"

	"github.com/osto-cybersecurity/cli-login/internal/config"
	"github.com/osto-cybersecurity/cli-login/internal/db"
)

func TestValidatePasswordStrength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"Valid password", "P@ssw0rd123!", false},
		{"Too short", "P@s1!", true},
		{"No uppercase", "p@ssw0rd123!", true},
		{"No lowercase", "P@SSW0RD123!", true},
		{"No number", "P@ssword!!!", true},
		{"No special", "Password123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordStrength(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePasswordStrength() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestAuthServiceIntegration tests the Auth Service operations using a running DB instance.
// It is skipped if database environment variables are not available (e.g. during local offline builds).
func TestAuthServiceIntegration(t *testing.T) {
	if os.Getenv("DB_HOST") == "" {
		t.Skip("Skipping database integration tests: DB_HOST not set")
	}

	cfg := &config.Config{
		DBHost:                 os.Getenv("DB_HOST"),
		DBPort:                 os.Getenv("DB_PORT"),
		DBUser:                 os.Getenv("DB_USER"),
		DBPassword:             os.Getenv("DB_PASSWORD"),
		DBName:                 os.Getenv("DB_NAME"),
		DBSSLMode:              os.Getenv("DB_SSLMODE"),
		SessionTimeoutMinutes:  1,
		LockoutAttempts:        3, // lower threshold for testing
		LockoutDurationMinutes: 1,
	}

	// Connect to test database
	database, err := db.ConnectDB(cfg)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	// Perform migrations
	err = db.Migrate(database)
	if err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	// Clean up previous test runs if any
	_, _ = database.Exec("DELETE FROM users WHERE username LIKE 'test_%'")

	s := NewAuthService(database, cfg)

	t.Run("Register and Login flow", func(t *testing.T) {
		username := "test_user_1"
		password := "P@ssw0rd123!"

		// 1. Register User
		user, err := s.Register(username, password)
		if err != nil {
			t.Fatalf("Register failed: %v", err)
		}
		if user.Username != username {
			t.Errorf("Expected username %s, got %s", username, user.Username)
		}

		// 2. Register Duplicate User
		_, err = s.Register(username, password)
		if err == nil {
			t.Error("Expected error registering duplicate user, got nil")
		}

		// 3. Login with wrong password
		_, _, err = s.Login(username, "wrong_pass", "")
		if err == nil {
			t.Error("Expected login failure with wrong password, got nil")
		}

		// 4. Login with correct password (no 2FA)
		session, loggedInUser, err := s.Login(username, password, "")
		if err != nil {
			t.Fatalf("Login failed: %v", err)
		}
		if loggedInUser.ID != user.ID {
			t.Errorf("Expected user ID %d, got %d", user.ID, loggedInUser.ID)
		}
		if session.ID == "" {
			t.Error("Expected non-empty session ID")
		}

		// 5. Verify session
		verifiedSession, verifiedUser, err := s.VerifySession(session.ID)
		if err != nil {
			t.Fatalf("Session verification failed: %v", err)
		}
		if verifiedUser.ID != user.ID {
			t.Errorf("Expected user ID %d, got %d", user.ID, verifiedUser.ID)
		}
		if verifiedSession.ID != session.ID {
			t.Errorf("Expected session ID %s, got %s", session.ID, verifiedSession.ID)
		}

		// 6. Invalidate session (logout)
		err = s.InvalidateSession(session.ID)
		if err != nil {
			t.Fatalf("Invalidate session failed: %v", err)
		}

		// 7. Verify session again (should fail)
		_, _, err = s.VerifySession(session.ID)
		if err == nil {
			t.Error("Expected error verifying invalidated session, got nil")
		}
	})

	t.Run("Lockout flow", func(t *testing.T) {
		username := "test_lockout_user"
		password := "P@ssw0rd123!"

		_, err := s.Register(username, password)
		if err != nil {
			t.Fatalf("Register failed: %v", err)
		}

		// Attempt login with wrong password multiple times
		// Lockout limit is configured to 3 in this test.
		_, _, err = s.Login(username, "wrong_pass", "") // Attempt 1
		if err == nil {
			t.Error("Expected login failure, got nil")
		}

		_, _, err = s.Login(username, "wrong_pass", "") // Attempt 2
		if err == nil {
			t.Error("Expected login failure, got nil")
		}

		_, _, err = s.Login(username, "wrong_pass", "") // Attempt 3 -> Should lock account
		if err == nil {
			t.Error("Expected login failure, got nil")
		}

		// Try logging in with the CORRECT password now - should still fail because of lockout
		_, _, err = s.Login(username, password, "")
		if err == nil {
			t.Fatal("Expected login failure due to lockout, but login succeeded")
		}
		if err != ErrAccountLocked {
			// It might be wrapped, check if contains lockout message
			// Wait, the error is returned as fmt.Errorf("%w: try again...", ErrAccountLocked)
			// so errors.Is(err, ErrAccountLocked) is true
			var isLocked bool
			for {
				if err == ErrAccountLocked {
					isLocked = true
					break
				}
				// Unwrap manually if needed, but %+v or errors.Is works.
				u, ok := err.(interface{ Unwrap() error })
				if !ok {
					break
				}
				err = u.Unwrap()
			}
			if !isLocked {
				t.Errorf("Expected ErrAccountLocked, got %v", err)
			}
		}

		// Wait for lockout duration (1 minute) to expire or manually update the DB to simulate expiration
		_, err = database.Exec("UPDATE users SET locked_until = NOW() - INTERVAL '1 minute' WHERE username = $1", username)
		if err != nil {
			t.Fatalf("Failed to reset locked_until for test: %v", err)
		}

		// Try logging in again - should succeed now and reset failed attempts
		session, _, err := s.Login(username, password, "")
		if err != nil {
			t.Fatalf("Expected login to succeed after lockout expired, got %v", err)
		}
		_ = s.InvalidateSession(session.ID)
	})
}

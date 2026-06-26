package models

import "time"

// User represents a registered system user.
type User struct {
	ID             int        `db:"id"`
	Username       string     `db:"username"`
	PasswordHash   string     `db:"password_hash"`
	TOTPSecret     string     `db:"totp_secret"`
	TOTPEnabled    bool       `db:"totp_enabled"`
	FailedAttempts int        `db:"failed_attempts"`
	LockedUntil    *time.Time `db:"locked_until"`
	CreatedAt      time.Time  `db:"created_at"`
	LastLoginAt    *time.Time `db:"last_login_at"`
}

// Session represents an authenticated user session.
type Session struct {
	ID             string    `db:"id"`
	UserID         int       `db:"user_id"`
	ExpiresAt      time.Time `db:"expires_at"`
	CreatedAt      time.Time `db:"created_at"`
	LastActivityAt time.Time `db:"last_activity_at"`
}

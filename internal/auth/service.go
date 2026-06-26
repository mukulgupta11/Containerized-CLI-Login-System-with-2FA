package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/osto-cybersecurity/cli-login/internal/config"
	"github.com/osto-cybersecurity/cli-login/internal/models"
	"github.com/osto-cybersecurity/cli-login/internal/totp"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountLocked      = errors.New("account is locked")
	ErrTOTPRequired       = errors.New("2FA code required")
	ErrInvalidTOTP        = errors.New("invalid 2FA code")
	ErrSessionExpired     = errors.New("session expired")
)

type AuthService struct {
	db  *sql.DB
	cfg *config.Config
}

func NewAuthService(db *sql.DB, cfg *config.Config) *AuthService {
	return &AuthService{
		db:  db,
		cfg: cfg,
	}
}

// ValidatePasswordStrength checks password against security policy requirements
func ValidatePasswordStrength(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	var (
		hasUpper   = regexp.MustCompile(`[A-Z]`).MatchString(password)
		hasLower   = regexp.MustCompile(`[a-z]`).MatchString(password)
		hasNumber  = regexp.MustCompile(`[0-9]`).MatchString(password)
		hasSpecial = regexp.MustCompile(`[!@#\$%\^&\*\(\)_\+\-=\[\]\{\};':",\./<>\?~\\|]`).MatchString(password)
	)
	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasNumber {
		return errors.New("password must contain at least one number")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}
	return nil
}

// Register registers a new user securely
func (s *AuthService) Register(username, password string) (*models.User, error) {
	if len(username) < 3 {
		return nil, errors.New("username must be at least 3 characters long")
	}
	if err := ValidatePasswordStrength(password); err != nil {
		return nil, err
	}

	// Check if username is already taken
	var exists bool
	err := s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)", username).Scan(&exists)
	if err != nil {
		return nil, fmt.Errorf("failed to query users: %w", err)
	}
	if exists {
		return nil, errors.New("username is already taken")
	}

	// Hash password using bcrypt
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &models.User{
		Username:     username,
		PasswordHash: string(hashedBytes),
	}

	err = s.db.QueryRow(
		"INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, created_at",
		user.Username, user.PasswordHash,
	).Scan(&user.ID, &user.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to save user: %w", err)
	}

	return user, nil
}

// Login authenticates user with password and optional TOTP.
// It tracks failed login attempts and handles lockouts.
func (s *AuthService) Login(username, password, totpCode string) (*models.Session, *models.User, error) {
	var user models.User
	var lockedUntilNull sql.NullTime
	var lastLoginNull sql.NullTime

	err := s.db.QueryRow(
		"SELECT id, username, password_hash, totp_secret, totp_enabled, failed_attempts, locked_until, created_at, last_login_at FROM users WHERE username = $1",
		username,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.TOTPSecret, &user.TOTPEnabled, &user.FailedAttempts, &lockedUntilNull, &user.CreatedAt, &lastLoginNull)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// To mitigate side-channel timing attacks, perform a dummy bcrypt comparison
			_ = bcrypt.CompareHashAndPassword([]byte("$2a$12$N9qo8uLOtvI77vDJBtWtd.c1B.q4rFpEqgL8wW0XyQe1mYn0VlG2C"), []byte(password))
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, fmt.Errorf("database query error: %w", err)
	}

	if lockedUntilNull.Valid {
		user.LockedUntil = &lockedUntilNull.Time
	}
	if lastLoginNull.Valid {
		user.LastLoginAt = &lastLoginNull.Time
	}

	// 1. Check account lockout
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		timeLeft := time.Until(*user.LockedUntil).Round(time.Second)
		return nil, nil, fmt.Errorf("%w: try again in %v", ErrAccountLocked, timeLeft)
	}

	// 2. Validate password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		s.handleFailedAttempt(&user)
		attemptsRemaining := s.cfg.LockoutAttempts - (user.FailedAttempts + 1)
		if attemptsRemaining <= 0 {
			return nil, nil, fmt.Errorf("%w: too many failed attempts, account has been locked for %d minutes", ErrInvalidCredentials, s.cfg.LockoutDurationMinutes)
		}
		return nil, nil, fmt.Errorf("%w: %d attempts remaining before lockout", ErrInvalidCredentials, attemptsRemaining)
	}

	// 3. Handle optional 2FA
	if user.TOTPEnabled {
		if totpCode == "" {
			return nil, &user, ErrTOTPRequired
		}
		if !totp.VerifyCode(user.TOTPSecret, totpCode) {
			s.handleFailedAttempt(&user)
			attemptsRemaining := s.cfg.LockoutAttempts - (user.FailedAttempts + 1)
			if attemptsRemaining <= 0 {
				return nil, nil, fmt.Errorf("%w: too many failed attempts, account has been locked for %d minutes", ErrInvalidTOTP, s.cfg.LockoutDurationMinutes)
			}
			return nil, nil, fmt.Errorf("%w: %d attempts remaining before lockout", ErrInvalidTOTP, attemptsRemaining)
		}
	}

	// 4. Login successful - Reset failures and generate session
	_, err = s.db.Exec("UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = NOW() WHERE id = $1", user.ID)
	if err != nil {
		logError("failed to reset user stats: %v", err)
	}

	session, err := s.CreateSession(user.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create session: %w", err)
	}

	return session, &user, nil
}

// handleFailedAttempt increments user failed attempt count and locks if threshold is reached
func (s *AuthService) handleFailedAttempt(user *models.User) {
	newAttempts := user.FailedAttempts + 1
	var query string
	var args []interface{}

	if newAttempts >= s.cfg.LockoutAttempts {
		lockUntil := time.Now().Add(time.Duration(s.cfg.LockoutDurationMinutes) * time.Minute)
		query = "UPDATE users SET failed_attempts = $1, locked_until = $2 WHERE id = $3"
		args = []interface{}{newAttempts, lockUntil, user.ID}
	} else {
		query = "UPDATE users SET failed_attempts = $1 WHERE id = $2"
		args = []interface{}{newAttempts, user.ID}
	}

	_, err := s.db.Exec(query, args...)
	if err != nil {
		logError("failed to update failed attempts: %v", err)
	}
}

// CreateSession generates a new secure session token and saves it to the database
func (s *AuthService) CreateSession(userID int) (*models.Session, error) {
	// Generate 32-byte secure random token (64 hex characters)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}
	token := hex.EncodeToString(tokenBytes)

	expiresAt := time.Now().Add(time.Duration(s.cfg.SessionTimeoutMinutes) * time.Minute)

	session := &models.Session{
		ID:             token,
		UserID:         userID,
		ExpiresAt:      expiresAt,
		CreatedAt:      time.Now(),
		LastActivityAt: time.Now(),
	}

	_, err := s.db.Exec(
		"INSERT INTO sessions (id, user_id, expires_at, created_at, last_activity_at) VALUES ($1, $2, $3, $4, $5)",
		session.ID, session.UserID, session.ExpiresAt, session.CreatedAt, session.LastActivityAt,
	)
	if err != nil {
		return nil, err
	}

	return session, nil
}

// VerifySession verifies token, handles expiration, and implements sliding window timeout
func (s *AuthService) VerifySession(token string) (*models.Session, *models.User, error) {
	var session models.Session
	var user models.User
	var lockedUntilNull sql.NullTime
	var lastLoginNull sql.NullTime

	query := `
		SELECT s.id, s.user_id, s.expires_at, s.created_at, s.last_activity_at,
		       u.id, u.username, u.password_hash, u.totp_secret, u.totp_enabled, u.failed_attempts, u.locked_until, u.created_at, u.last_login_at
		FROM sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.id = $1`

	err := s.db.QueryRow(query, token).Scan(
		&session.ID, &session.UserID, &session.ExpiresAt, &session.CreatedAt, &session.LastActivityAt,
		&user.ID, &user.Username, &user.PasswordHash, &user.TOTPSecret, &user.TOTPEnabled, &user.FailedAttempts, &lockedUntilNull, &user.CreatedAt, &lastLoginNull,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrSessionExpired
		}
		return nil, nil, err
	}

	if lockedUntilNull.Valid {
		user.LockedUntil = &lockedUntilNull.Time
	}
	if lastLoginNull.Valid {
		user.LastLoginAt = &lastLoginNull.Time
	}

	// Check if session has expired absolutely
	if session.ExpiresAt.Before(time.Now()) {
		_ = s.InvalidateSession(token)
		return nil, nil, ErrSessionExpired
	}

	// Check sliding window timeout (inactive timeout)
	inactiveDuration := time.Duration(s.cfg.SessionTimeoutMinutes) * time.Minute
	if time.Since(session.LastActivityAt) > inactiveDuration {
		_ = s.InvalidateSession(token)
		return nil, nil, ErrSessionExpired
	}

	// Update activity and extend expiration (sliding window)
	newActivity := time.Now()
	newExpires := newActivity.Add(inactiveDuration)

	_, err = s.db.Exec(
		"UPDATE sessions SET last_activity_at = $1, expires_at = $2 WHERE id = $3",
		newActivity, newExpires, token,
	)
	if err != nil {
		logError("failed to update session activity: %v", err)
	}

	// Update local struct values
	session.LastActivityAt = newActivity
	session.ExpiresAt = newExpires

	return &session, &user, nil
}

// InvalidateSession logs out a user session by deleting it
func (s *AuthService) InvalidateSession(token string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE id = $1", token)
	return err
}

// Enable2FA confirms and activates TOTP for a user
func (s *AuthService) Enable2FA(userID int, secret, code string) error {
	if !totp.VerifyCode(secret, code) {
		return ErrInvalidTOTP
	}

	_, err := s.db.Exec("UPDATE users SET totp_secret = $1, totp_enabled = TRUE WHERE id = $2", secret, userID)
	if err != nil {
		return fmt.Errorf("failed to enable 2FA in database: %w", err)
	}
	return nil
}

// Disable2FA disables TOTP for a user. It requires their password as verification.
func (s *AuthService) Disable2FA(userID int, password string) error {
	var hash string
	err := s.db.QueryRow("SELECT password_hash FROM users WHERE id = $1", userID).Scan(&hash)
	if err != nil {
		return fmt.Errorf("user lookup error: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return ErrInvalidCredentials
	}

	_, err = s.db.Exec("UPDATE users SET totp_secret = '', totp_enabled = FALSE WHERE id = $2", userID)
	if err != nil {
		return fmt.Errorf("failed to disable 2FA in database: %w", err)
	}
	return nil
}

// logError helper to standardise non-fatal logging
func logError(format string, v ...interface{}) {
	// Standard error log format
	fmt.Printf("[Error] "+format+"\n", v...)
}

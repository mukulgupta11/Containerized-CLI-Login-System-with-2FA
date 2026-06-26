package totp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestGenerateSecret(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if secret == "" {
		t.Fatal("Expected secret to not be empty")
	}

	// Verify it is valid base32
	_, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Errorf("Secret is not valid base32: %v", err)
	}
}

func TestVerifyCode(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	// Generate a valid code for right now using the library directly
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate TOTP code: %v", err)
	}

	// Verify code is valid
	if !VerifyCode(secret, code) {
		t.Error("Expected code to be valid, but verification failed")
	}

	// Verify invalid code is rejected
	if VerifyCode(secret, "123456") {
		t.Error("Expected invalid code 123456 to be rejected, but it was verified successfully")
	}
}

func TestGenerateASCIIQRCode(t *testing.T) {
	uri := GenerateURI("testuser", "MFSG22LOONUXG5LSMF2GK5DUMV2A")
	qr, err := GenerateASCIIQRCode(uri)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if qr == "" {
		t.Fatal("Expected QR code ASCII to not be empty")
	}

	if !strings.Contains(qr, "██") {
		t.Error("Expected QR code to contain block characters '██'")
	}
}

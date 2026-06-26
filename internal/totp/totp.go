package totp

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

// GenerateSecret generates a secure base32 encoded random secret key for a user.
func GenerateSecret() (string, error) {
	// 20 bytes is standard for TOTP (160 bits)
	secretBytes := make([]byte, 20)
	_, err := rand.Read(secretBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes), nil
}

// GenerateURI creates the standard OTP Auth URI that can be scanned by Authenticator apps.
func GenerateURI(username, secret string) string {
	opts := totp.GenerateOpts{
		Issuer:      "OstoSecureCLI",
		AccountName: username,
		Secret:      []byte(secret),
	}
	// We don't use Generate directly because it returns an image key. We just need the URI.
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		opts.Issuer, opts.AccountName, secret, opts.Issuer)
}

// VerifyCode checks if the provided TOTP code is valid for the given secret at the current time.
// It includes a small grace window (prev/next 30 seconds) to account for client time drift.
func VerifyCode(secret, code string) bool {
	valid, err := totp.ValidateCustom(
		code,
		secret,
		time.Now(),
		totp.ValidateOpts{
			Period:    30,
			Skew:      1, // 1 step of 30 seconds skew allowed (prev/next)
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
	)
	if err != nil {
		return false
	}
	return valid
}

// GenerateASCIIQRCode generates an ASCII representation of the QR code suitable for a dark terminal.
// It uses half-block characters (▀, ▄, █) to render two vertical pixels in a single character row,
// reducing the overall size by 75% so it fits in any standard terminal pane.
func GenerateASCIIQRCode(uri string) (string, error) {
	q, err := qrcode.New(uri, qrcode.Low)
	if err != nil {
		return "", fmt.Errorf("failed to generate QR code: %w", err)
	}

	bitmap := q.Bitmap()
	var result string

	height := len(bitmap)
	width := len(bitmap[0])

	// Top padding: a row of full white blocks
	for x := -1; x <= width; x++ {
		result += "█"
	}
	result += "\n"

	for y := 0; y < height; y += 2 {
		// Left padding
		result += "█"

		for x := 0; x < width; x++ {
			top := bitmap[y][x]
			bottom := true // default to black/empty for out of bounds
			if y+1 < height {
				bottom = bitmap[y+1][x]
			}

			// In a dark terminal, black pixels are empty space " ", and white is "█"
			// top/bottom are true for black, false for white.
			if !top && !bottom {
				// both white
				result += "█"
			} else if !top && bottom {
				// top white, bottom black
				result += "▀"
			} else if top && !bottom {
				// top black, bottom white
				result += "▄"
			} else {
				// both black
				result += " "
			}
		}

		// Right padding
		result += "█\n"
	}

	// Bottom padding: a row of full white blocks
	for x := -1; x <= width; x++ {
		result += "█"
	}
	result += "\n"

	return result, nil
}

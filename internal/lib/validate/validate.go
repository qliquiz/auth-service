// Package validate provides input validation helpers for user-facing fields.
package validate

import (
	"fmt"
	"regexp"
	"unicode"
)

// emailRe is a practical email format validator — not RFC 5321 complete,
// but catches all common mistakes without false positives.
var emailRe = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// Email returns a non-nil error if the address does not look like a valid email.
func Email(email string) error {
	if email == "" {
		return fmt.Errorf("email is required")
	}
	if !emailRe.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// Password checks minimum complexity requirements:
//   - at least 8 characters
//   - at least one letter
//   - at least one digit
func Password(pwd string) error {
	if len(pwd) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	var hasLetter, hasDigit bool
	for _, r := range pwd {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			hasDigit = true
		}
		if hasLetter && hasDigit {
			break
		}
	}

	if !hasLetter {
		return fmt.Errorf("password must contain at least one letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}
	return nil
}

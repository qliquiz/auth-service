package validate_test

import (
	"testing"

	"auth-service/internal/lib/validate"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmail_Valid(t *testing.T) {
	t.Parallel()

	cases := []string{
		"user@example.com",
		"alice.bob+tag@sub.domain.io",
		"x@y.co",
		"user123@company.org",
		"first.last@email.co.uk",
	}

	for _, email := range cases {
		t.Run(email, func(t *testing.T) {
			t.Parallel()
			require.NoError(t, validate.Email(email))
		})
	}
}

func TestEmail_Invalid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input   string
		wantErr string
	}{
		{"", "email is required"},
		{"notanemail", "invalid email format"},
		{"@nodomain", "invalid email format"},
		{"noatsign.com", "invalid email format"},
		{"two@@signs.com", "invalid email format"},
		{"user@", "invalid email format"},
		{"user@.com", "invalid email format"},
		{"user@domain", "invalid email format"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			err := validate.Email(tc.input)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestPassword_Valid(t *testing.T) {
	t.Parallel()

	cases := []string{
		"password1",
		"s3cureP@ssw0rd",
		"abc12345",
		"UPPER1lower",
		"12345678a",
	}

	for _, pwd := range cases {
		t.Run(pwd, func(t *testing.T) {
			t.Parallel()
			require.NoError(t, validate.Password(pwd))
		})
	}
}

func TestPassword_Invalid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"too_short", "pass1", "at least 8 characters"},
		{"no_digit", "passwordonly", "at least one digit"},
		{"no_letter", "12345678", "at least one letter"},
		{"empty", "", "at least 8 characters"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validate.Password(tc.input)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

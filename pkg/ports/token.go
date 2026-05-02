// token.go defines the interface for issuing and validating access tokens.
// The service depends only on this interface — the signing algorithm is an
// implementation detail selected at startup via config.
package ports

// Claims holds the payload extracted from a validated access token.
type Claims struct {
	UserID string
	Email  string
	Roles  []string
}

// AccessTokenManager issues and validates short-lived access tokens.
// Implementations must be safe for concurrent use.
type AccessTokenManager interface {
	// GenerateAccessToken creates a signed access token for the given user.
	GenerateAccessToken(userID, email string, roles []string) (token string, err error)
	// ValidateAccessToken parses and validates a token, returning its claims.
	// Returns a non-nil error if the token is expired, invalid, or from a
	// foreign issuer.
	ValidateAccessToken(token string) (*Claims, error)
}

package ports

type Claims struct {
	UserID string
	Email  string
	Roles  []string
}

type AccessTokenManager interface {
	GenerateAccessToken(userID, email string, roles []string) (token string, err error)
	ValidateAccessToken(token string) (*Claims, error)
}

package jwt

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zhavkk/gRPC_auth_service/internal/domain"
)

const (
	ClaimUUID  = "uuid"
	ClaimEmail = "email"
	ClaimExp   = "exp"
	ClaimRole  = "role"
)

// TODO: unit test
func NewToken(user domain.User, duration time.Duration) (string, error) {
	claims := jwt.MapClaims{
		ClaimUUID:  user.ID,
		ClaimEmail: user.Email,
		ClaimExp:   time.Now().Add(duration).Unix(),
		ClaimRole:  user.Role,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	secret := os.Getenv("SECRET")
	if secret == "" {
		return "", errors.New("secret is not set")
	}
	tokenString, err := token.SignedString([]byte(secret))

	if err != nil {
		return "", err
	}

	return tokenString, nil

}

func ValidateToken(tokenString string, secret string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(secret), nil
		},
	)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	exp, ok := claims[ClaimExp].(float64)
	if !ok {
		return nil, errors.New("invalid expiration time")
	}
	if time.Now().Unix() > int64(exp) {
		return nil, errors.New("token expired")
	}

	return claims, nil
}

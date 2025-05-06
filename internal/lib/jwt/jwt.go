package jwt

import (
	"errors"
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

type Config struct {
	Secret   string
	TokenTTL time.Duration
}

// TODO: unit test
func NewToken(user domain.User, config Config) (string, error) {
	claims := jwt.MapClaims{
		ClaimUUID:  user.ID,
		ClaimEmail: user.Email,
		ClaimExp:   time.Now().Add(config.TokenTTL).Unix(),
		ClaimRole:  user.Role,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ValidateToken(tokenString string, config Config) (jwt.MapClaims, error) {
	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(config.Secret), nil
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

	// Проверяем expiration
	exp, ok := claims[ClaimExp].(float64)
	if !ok {
		return nil, errors.New("invalid expiration time")
	}
	if time.Now().Unix() > int64(exp) {
		return nil, errors.New("token expired")
	}

	return claims, nil
}

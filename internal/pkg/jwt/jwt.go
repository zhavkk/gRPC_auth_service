// Package jwt предоставляет функции для генерации и валидации JWT токенов.
package jwt

import (
	"errors"
	"fmt"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/zhavkk/gRPC_auth_service/internal/models"
)

const (
	ClaimUUID  = "uuid"
	ClaimEmail = "email"
	ClaimExp   = "exp"
	ClaimRole  = "role"
	ClaimJTI   = "jti"
)

type Config struct {
	Secret          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

func NewAccessToken(profile models.Profile, config Config) (string, error) {
	claims := gojwt.MapClaims{
		ClaimUUID: profile.ID,
		ClaimExp:  time.Now().Add(config.AccessTokenTTL).Unix(),
		ClaimRole: profile.Role,
	}

	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func NewRefreshToken(profileID string, jti string, config Config) (string, error) {
	claims := gojwt.MapClaims{
		ClaimUUID: profileID,
		ClaimJTI:  jti,
		ClaimExp:  time.Now().Add(config.RefreshTokenTTL).Unix(),
	}

	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ValidateToken(tokenString string,
	config Config,
) (gojwt.MapClaims, error) {
	token, err := gojwt.Parse(
		tokenString,
		func(token *gojwt.Token) (interface{}, error) {
			if token.Method != gojwt.SigningMethodHS256 {
				return nil, ErrUnexpectedSigningMethod
			}
			return []byte(config.Secret), nil
		},
	)
	if err != nil {
		if errors.Is(err, gojwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not structurally valid: %w", ErrInvalidToken)
	}

	claims, ok := token.Claims.(gojwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type after parsing: %w", ErrInvalidToken)
	}

	expClaim, ok := claims[ClaimExp]
	if !ok {
		return nil, fmt.Errorf("expiration claim (exp) not found in parsed token: %w", ErrInvalidToken)
	}

	expFloat, ok := expClaim.(float64)
	if !ok {
		return nil, fmt.Errorf("expiration claim (exp) is not a number: %w", ErrInvalidToken)
	}

	if time.Now().Unix() > int64(expFloat) {
		return nil, ErrTokenExpired
	}

	return claims, nil
}

func ParseAndValidateRefreshToken(tokenString string,
	config Config,
) (profileID string,
	jti string,
	err error,
) {
	claims, err := ValidateToken(tokenString, config)
	if err != nil {
		return "", "", err
	}

	profileIDClaim, okProfileID := claims[ClaimUUID].(string)
	jtiClaim, okJTI := claims[ClaimJTI].(string)

	if !okProfileID || !okJTI {
		return "", "", ErrInvalidRefreshToken
	}
	return profileIDClaim, jtiClaim, nil
}

package jwt

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zhavkk/gRPC_auth_service/internal/models"
)

func TestNewAccessToken(t *testing.T) {
	config := Config{Secret: "secret", AccessTokenTTL: 1 * time.Hour, RefreshTokenTTL: 24 * time.Hour}

	t.Run("success", func(t *testing.T) {
		user := models.Profile{
			ID:   uuid.New(),
			Role: models.RoleUser.String(),
		}
		token, err := NewAccessToken(user, config)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		claims, err := ValidateToken(token, config)
		require.NoError(t, err)
		assert.Equal(t, user.ID.String(), claims[ClaimUUID])
		assert.Equal(t, user.Role, claims[ClaimRole])
	})

	t.Run("empty id", func(t *testing.T) {
		user := models.Profile{
			ID:   uuid.Nil,
			Role: models.RoleUser.String(),
		}
		token, err := NewAccessToken(user, config)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		claims, err := ValidateToken(token, config)
		require.NoError(t, err)
		assert.Equal(t, uuid.Nil.String(), claims[ClaimUUID])
	})
}

func TestNewRefreshToken(t *testing.T) {
	config := Config{Secret: "secret", AccessTokenTTL: 1 * time.Hour, RefreshTokenTTL: 24 * time.Hour}
	userID := "user-123"
	jti := "jti-abc"

	t.Run("success", func(t *testing.T) {
		token, err := NewRefreshToken(userID, jti, config)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		claims, err := ValidateToken(token, config)
		require.NoError(t, err)
		assert.Equal(t, userID, claims[ClaimUUID])
		assert.Equal(t, jti, claims[ClaimJTI])
		_, emailOk := claims[ClaimEmail]
		assert.False(t, emailOk, "Email should not be in refresh token claims")
		_, roleOk := claims[ClaimRole]
		assert.False(t, roleOk, "Role should not be in refresh token claims")
	})
}

func TestValidateToken(t *testing.T) {
	config := Config{
		Secret:          "secret",
		AccessTokenTTL:  1 * time.Second,
		RefreshTokenTTL: 24 * time.Hour,
	}

	t.Run("success access token", func(t *testing.T) {
		user := models.Profile{
			ID:   uuid.New(),
			Role: models.RoleUser.String(),
		}
		token, err := NewAccessToken(user, config)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		claims, err := ValidateToken(token, config)
		require.NoError(t, err)
		assert.Equal(t, user.ID.String(), claims[ClaimUUID])
		assert.Equal(t, user.Role, claims[ClaimRole])
	})

	t.Run("success refresh token", func(t *testing.T) {
		userID := "user-123"
		jti := "jti-abc"
		token, err := NewRefreshToken(userID, jti, config)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		claims, err := ValidateToken(token, config)
		require.NoError(t, err)
		assert.Equal(t, userID, claims[ClaimUUID])
		assert.Equal(t, jti, claims[ClaimJTI])
	})

	t.Run("invalid token string", func(t *testing.T) {
		token := "invalid_token_string"
		claims, err := ValidateToken(token, config)
		require.Error(t, err)
		assert.Nil(t, claims)
	})

	t.Run("expired access token", func(t *testing.T) {
		user := models.Profile{
			ID:   uuid.New(),
			Role: models.RoleUser.String(),
		}
		expiredConfig := Config{Secret: "secret", AccessTokenTTL: 1 * time.Millisecond, RefreshTokenTTL: 24 * time.Hour}
		token, err := NewAccessToken(user, expiredConfig)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		time.Sleep(5 * time.Millisecond)
		claims, err := ValidateToken(token, expiredConfig)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenExpired)
		assert.Nil(t, claims)
	})

	t.Run("token signed with different secret", func(t *testing.T) {
		user := models.Profile{ID: uuid.New(), Role: models.RoleUser.String()}
		token, err := NewAccessToken(user, config)
		require.NoError(t, err)

		wrongConfig := Config{Secret: "wrong-secret", AccessTokenTTL: 1 * time.Hour}
		_, err = ValidateToken(token, wrongConfig)
		require.Error(t, err)
		assert.ErrorIs(t, err, jwt.ErrSignatureInvalid)
	})

	t.Run("token with unexpected signing method", func(t *testing.T) {
		claims := jwt.MapClaims{
			ClaimUUID: "123",
			ClaimExp:  time.Now().Add(1 * time.Hour).Unix(),
			ClaimRole: "user",
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
		tokenString, err := token.SignedString([]byte(config.Secret))
		require.NoError(t, err)

		_, err = ValidateToken(tokenString, config)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUnexpectedSigningMethod)
	})
}

func TestParseAndValidateRefreshToken(t *testing.T) {
	config := Config{Secret: "secret", AccessTokenTTL: 1 * time.Hour, RefreshTokenTTL: 24 * time.Hour}
	userID := "user-123"
	jti := "jti-abc"

	t.Run("success", func(t *testing.T) {
		refreshTokenString, err := NewRefreshToken(userID, jti, config)
		require.NoError(t, err)

		parsedUserID, parsedJTI, err := ParseAndValidateRefreshToken(refreshTokenString, config)
		require.NoError(t, err)
		assert.Equal(t, userID, parsedUserID)
		assert.Equal(t, jti, parsedJTI)
	})

	t.Run("invalid token string", func(t *testing.T) {
		_, _, err := ParseAndValidateRefreshToken("invalid-token", config)
		require.Error(t, err)
	})

	t.Run("expired refresh token", func(t *testing.T) {
		expiredConfig := Config{Secret: "secret", RefreshTokenTTL: 1 * time.Millisecond}
		refreshTokenString, err := NewRefreshToken(userID, jti, expiredConfig)
		require.NoError(t, err)

		time.Sleep(5 * time.Millisecond)
		_, _, err = ParseAndValidateRefreshToken(refreshTokenString, expiredConfig)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenExpired)
	})

	userID2 := uuid.New()
	t.Run("token is not a refresh token (missing jti)", func(t *testing.T) {
		user := models.Profile{ID: userID2, Role: string(models.RoleUser)}
		accessTokenString, err := NewAccessToken(user, config)
		require.NoError(t, err)

		_, _, err = ParseAndValidateRefreshToken(accessTokenString, config)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidRefreshToken)
	})

	t.Run("token is not a refresh token (missing uuid)", func(t *testing.T) {
		claims := jwt.MapClaims{
			ClaimJTI: jti,
			ClaimExp: time.Now().Add(config.RefreshTokenTTL).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		badTokenString, err := token.SignedString([]byte(config.Secret))
		require.NoError(t, err)

		_, _, err = ParseAndValidateRefreshToken(badTokenString, config)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidRefreshToken)
	})
}

package jwt

import (
	"testing"
	"time"

	"github.com/zhavkk/gRPC_auth_service/internal/domain"
)

func TestNewToken(t *testing.T) {
	config := Config{Secret: "secret", TokenTTL: 1 * time.Second}

	t.Run("success", func(t *testing.T) {
		user := domain.User{
			ID:    "1",
			Email: "test@test.com",
			Role:  "user",
		}
		token, err := NewToken(user, config)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if token == "" {
			t.Fatalf("expected non-empty token")
		}

		claims, err := ValidateToken(token, config)
		if err != nil {
			t.Fatalf("token should be valid, got error: %v", err)
		}
		if claims[ClaimUUID] != user.ID {
			t.Errorf("expected uuid %s, got %s", user.ID, claims[ClaimUUID])
		}
		if claims[ClaimEmail] != user.Email {
			t.Errorf("expected email %s, got %s", user.Email, claims[ClaimEmail])
		}
		if claims[ClaimRole] != user.Role {
			t.Errorf("expected role %s, got %s", user.Role, claims[ClaimRole])
		}
	})

	t.Run("empty id", func(t *testing.T) {
		user := domain.User{
			ID:    "",
			Email: "test@test.com",
			Role:  "user",
		}
		token, err := NewToken(user, config)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if token == "" {
			t.Fatalf("expected non-empty token")
		}
		claims, err := ValidateToken(token, config)
		if err != nil {
			t.Fatalf("token should be valid, got error: %v", err)
		}
		if claims[ClaimUUID] != "" {
			t.Errorf("expected empty uuid, got %s", claims[ClaimUUID])
		}
	})
}

func TestValidateToken(t *testing.T) {
	config := Config{Secret: "secret", TokenTTL: 1 * time.Second}

	t.Run("success", func(t *testing.T) {
		user := domain.User{
			ID:    "1",
			Email: "test@test.com",
			Role:  "user",
		}
		token, err := NewToken(user, config)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if token == "" {
			t.Fatalf("expected non-empty token")
		}

		claims, err := ValidateToken(token, config)
		if err != nil {
			t.Fatalf("token should be valid, got error: %v", err)
		}
		if claims[ClaimUUID] != user.ID {
			t.Errorf("expected uuid %s, got %s", user.ID, claims[ClaimUUID])
		}
		if claims[ClaimEmail] != user.Email {
			t.Errorf("expected email %s, got %s", user.Email, claims[ClaimEmail])
		}
		if claims[ClaimRole] != user.Role {
			t.Errorf("expected role %s, got %s", user.Role, claims[ClaimRole])
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		token := "invalid_token"
		claims, err := ValidateToken(token, config)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if claims != nil {
			t.Errorf("expected nil claims, got %v", claims)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		user := domain.User{
			ID:    "1",
			Email: "test@test.com",
			Role:  "user",
		}
		token, err := NewToken(user, config)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if token == "" {
			t.Fatalf("expected non-empty token")
		}
		time.Sleep(2 * time.Second)
		claims, err := ValidateToken(token, config)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if claims != nil {
			t.Errorf("expected nil claims, got %v", claims)
		}
	})
}

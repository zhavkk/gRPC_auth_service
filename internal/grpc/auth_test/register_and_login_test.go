package auth_test

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	authproto "github.com/zhavkk/Auth-protobuf/gen/go/auth"
	"github.com/zhavkk/gRPC_auth_service/internal/config"
	"github.com/zhavkk/gRPC_auth_service/internal/grpc/auth"
	"github.com/zhavkk/gRPC_auth_service/internal/lib/jwt"
	"github.com/zhavkk/gRPC_auth_service/internal/repository/postgres"
	"github.com/zhavkk/gRPC_auth_service/internal/service"
	"github.com/zhavkk/gRPC_auth_service/internal/storage"
)

const bufSize = 1024 * 1024

func setupTestServer(t *testing.T) (*grpc.ClientConn, func()) {
	lis := bufconn.Listen(bufSize)
	s := grpc.NewServer()

	cfg := config.Config{
		DB: config.DB{
			Host:     "localhost",
			Port:     "5433",
			User:     "testuser",
			Password: "testpass",
			Name:     "testdb",
		},
	}

	storage, err := storage.NewStorage(context.Background(), &cfg)
	require.NoError(t, err, "failed to create storage")

	_, err = storage.GetPool().Exec(context.Background(), "TRUNCATE TABLE users CASCADE")
	require.NoError(t, err, "failed to clean up database")

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	repo := postgres.NewUserRepository(storage, logger)

	jwtConfig := jwt.Config{
		Secret:   "testsecret",
		TokenTTL: time.Hour,
	}
	service := service.NewAuthService(repo, logger, jwtConfig)

	auth.Register(s, service)

	go func() {
		if err := s.Serve(lis); err != nil {
			t.Fatalf("Server exited with error: %v", err)
		}
	}()

	conn, err := grpc.Dial("bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err, "Failed to dial bufnet")

	return conn, func() {
		conn.Close()
		s.Stop()
		// Clean up the database after tests
		_, err := storage.GetPool().Exec(context.Background(), "TRUNCATE TABLE users CASCADE")
		require.NoError(t, err, "failed to clean up database")
	}
}

func TestRegister(t *testing.T) {
	conn, cleanup := setupTestServer(t)
	defer cleanup()

	client := authproto.NewAuthClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	tests := []struct {
		name        string
		req         *authproto.RegisterRequest
		wantErr     bool
		errCode     codes.Code
		description string
	}{
		{
			name: "successful registration",
			req: &authproto.RegisterRequest{
				Username: "testuser1",
				Email:    "test1@example.com",
				Password: "Password123!",
				Gender:   true,
				Country:  "RU",
				Age:      25,
			},
			wantErr: false,
		},
		{
			name: "invalid email format",
			req: &authproto.RegisterRequest{
				Username: "testuser2",
				Email:    "invalid-email",
				Password: "Password123!",
				Gender:   true,
				Country:  "RU",
				Age:      25,
			},
			wantErr:     true,
			errCode:     codes.InvalidArgument,
			description: "invalid email format",
		},
		{
			name: "password too short",
			req: &authproto.RegisterRequest{
				Username: "testuser3",
				Email:    "test3@example.com",
				Password: "123",
				Gender:   true,
				Country:  "RU",
				Age:      25,
			},
			wantErr:     true,
			errCode:     codes.InvalidArgument,
			description: "password must be at least 8 characters long",
		},
		{
			name: "age too young",
			req: &authproto.RegisterRequest{
				Username: "testuser4",
				Email:    "test4@example.com",
				Password: "Password123!",
				Gender:   true,
				Country:  "RU",
				Age:      -1,
			},
			wantErr:     true,
			errCode:     codes.InvalidArgument,
			description: "age must be between 0 and 150",
		},
		{
			name: "age too old",
			req: &authproto.RegisterRequest{
				Username: "testuser5",
				Email:    "test5@example.com",
				Password: "Password123!",
				Gender:   true,
				Country:  "RU",
				Age:      151,
			},
			wantErr:     true,
			errCode:     codes.InvalidArgument,
			description: "age must be between 0 and 150",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.Register(ctx, tt.req)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errCode != codes.OK {
					st, ok := status.FromError(err)
					assert.True(t, ok)
					assert.Equal(t, tt.errCode, st.Code())
					if tt.description != "" {
						assert.Contains(t, st.Message(), tt.description)
					}
				}
				return
			}
			assert.NoError(t, err)
			assert.NotEmpty(t, resp.GetId())
		})
	}
}

func TestLogin(t *testing.T) {
	conn, cleanup := setupTestServer(t)
	defer cleanup()

	client := authproto.NewAuthClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Register a new user for login test
	regResp, err := client.Register(ctx, &authproto.RegisterRequest{
		Username: "logintest",
		Email:    "login@example.com",
		Password: "Password123!",
		Gender:   true,
		Country:  "RU",
		Age:      25,
	})
	require.NoError(t, err)
	require.NotEmpty(t, regResp.GetId())

	tests := []struct {
		name        string
		req         *authproto.LoginRequest
		wantErr     bool
		errCode     codes.Code
		description string
	}{
		{
			name: "successful login",
			req: &authproto.LoginRequest{
				Email:    "login@example.com",
				Password: "Password123!",
			},
			wantErr: false,
		},
		{
			name: "wrong password",
			req: &authproto.LoginRequest{
				Email:    "login@example.com",
				Password: "WrongPassword123!",
			},
			wantErr:     true,
			errCode:     codes.Internal,
			description: "invalid email or password",
		},
		{
			name: "non-existent email",
			req: &authproto.LoginRequest{
				Email:    "nonexistent@example.com",
				Password: "Password123!",
			},
			wantErr:     true,
			errCode:     codes.Internal,
			description: "invalid email or password",
		},
		{
			name: "invalid email format",
			req: &authproto.LoginRequest{
				Email:    "invalid-email",
				Password: "Password123!",
			},
			wantErr:     true,
			errCode:     codes.InvalidArgument,
			description: "invalid email format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.Login(ctx, tt.req)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errCode != codes.OK {
					st, ok := status.FromError(err)
					assert.True(t, ok)
					assert.Equal(t, tt.errCode, st.Code())
					if tt.description != "" {
						assert.Contains(t, st.Message(), tt.description)
					}
				}
				return
			}
			assert.NoError(t, err)
			assert.NotEmpty(t, resp.GetToken())
			assert.Equal(t, "logintest", resp.GetUsername())
		})
	}
}

func TestConcurrentRegistration(t *testing.T) {
	conn, cleanup := setupTestServer(t)
	defer cleanup()

	client := authproto.NewAuthClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Test concurrent registration with the same email
	done := make(chan bool)
	email := "concurrent@example.com"

	for i := 0; i < 5; i++ {
		go func(i int) {
			_, err := client.Register(ctx, &authproto.RegisterRequest{
				Username: "concurrentuser",
				Email:    email,
				Password: "Password123!",
				Gender:   true,
				Country:  "RU",
				Age:      25,
			})
			if err == nil {
				done <- true
			} else {
				done <- false
			}
		}(i)
	}

	successCount := 0
	for i := 0; i < 5; i++ {
		if <-done {
			successCount++
		}
	}

	// Only one registration should be successful
	assert.Equal(t, 1, successCount)
}

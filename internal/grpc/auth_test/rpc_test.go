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
	"google.golang.org/grpc/metadata"
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

	// Create a test interceptor that will add claims to context
	testInterceptor := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if ok {
			if authHeader := md.Get("authorization"); len(authHeader) > 0 {
				token := authHeader[0]
				if len(token) > 7 && token[:7] == "Bearer " {
					token = token[7:]
					claims, err := jwt.ValidateToken(token, jwtConfig)
					if err == nil {
						ctx = context.WithValue(ctx, "claims", claims)
					}
				}
			}
		}
		return handler(ctx, req)
	}

	s = grpc.NewServer(grpc.UnaryInterceptor(testInterceptor))
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
			name: "successful registration as user",
			req: &authproto.RegisterRequest{
				Username: "testuser1",
				Email:    "test1@example.com",
				Password: "Password123!",
				Gender:   true,
				Country:  "RU",
				Age:      25,
				Role:     "user",
			},
			wantErr: false,
		},
		{
			name: "successful registration as artist",
			req: &authproto.RegisterRequest{
				Username: "testuser2",
				Email:    "test2@example.com",
				Password: "Password123!",
				Gender:   true,
				Country:  "RU",
				Age:      25,
				Role:     "artist",
			},
			wantErr: false,
		},
		{
			name: "invalid registration role as admin",
			req: &authproto.RegisterRequest{
				Username: "testuser3",
				Email:    "test3@example.com",
				Password: "Password123!",
				Gender:   true,
				Country:  "RU",
				Age:      25,
				Role:     "admin",
			},
			wantErr:     true,
			errCode:     codes.InvalidArgument,
			description: "role must be either 'user' or 'artist'",
		},
		{
			name: "invalid role",
			req: &authproto.RegisterRequest{
				Username: "testuser3",
				Email:    "test3@example.com",
				Password: "Password123!",
				Gender:   true,
				Country:  "RU",
				Age:      25,
				Role:     "admin",
			},
			wantErr:     true,
			errCode:     codes.InvalidArgument,
			description: "role must be either 'user' or 'artist'",
		},
		{
			name: "missing role",
			req: &authproto.RegisterRequest{
				Username: "testuser4",
				Email:    "test4@example.com",
				Password: "Password123!",
				Gender:   true,
				Country:  "RU",
				Age:      25,
			},
			wantErr:     true,
			errCode:     codes.InvalidArgument,
			description: "role is required",
		},
		{
			name: "invalid email format",
			req: &authproto.RegisterRequest{
				Username: "testuser5",
				Email:    "invalid-email",
				Password: "Password123!",
				Gender:   true,
				Country:  "RU",
				Age:      25,
				Role:     "user",
			},
			wantErr:     true,
			errCode:     codes.InvalidArgument,
			description: "invalid email format",
		},
		{
			name: "password too short",
			req: &authproto.RegisterRequest{
				Username: "testuser6",
				Email:    "test6@example.com",
				Password: "123",
				Gender:   true,
				Country:  "RU",
				Age:      25,
				Role:     "user",
			},
			wantErr:     true,
			errCode:     codes.InvalidArgument,
			description: "password must be at least 8 characters long",
		},
		{
			name: "age too young",
			req: &authproto.RegisterRequest{
				Username: "testuser7",
				Email:    "test7@example.com",
				Password: "Password123!",
				Gender:   true,
				Country:  "RU",
				Age:      -1,
				Role:     "user",
			},
			wantErr:     true,
			errCode:     codes.InvalidArgument,
			description: "age must be between 0 and 150",
		},
		{
			name: "age too old",
			req: &authproto.RegisterRequest{
				Username: "testuser8",
				Email:    "test8@example.com",
				Password: "Password123!",
				Gender:   true,
				Country:  "RU",
				Age:      151,
				Role:     "user",
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
		Role:     "artist",
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
				Role:     "user",
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

func TestSetUserRole(t *testing.T) {
	conn, cleanup := setupTestServer(t)
	defer cleanup()

	client := authproto.NewAuthClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Register admin user
	adminRegResp, err := client.Register(ctx, &authproto.RegisterRequest{
		Username: "admin",
		Email:    "admin@example.com",
		Password: "Password123!",
		Gender:   true,
		Country:  "RU",
		Age:      25,
		Role:     "user",
	})
	require.NoError(t, err)

	// Set admin role directly in database
	storage, err := storage.NewStorage(ctx, &config.Config{
		DB: config.DB{
			Host:     "localhost",
			Port:     "5433",
			User:     "testuser",
			Password: "testpass",
			Name:     "testdb",
		},
	})
	require.NoError(t, err)

	_, err = storage.GetPool().Exec(ctx, "UPDATE users SET role = 'admin' WHERE id = $1", adminRegResp.GetId())
	require.NoError(t, err)

	// Login as admin
	adminLoginResp, err := client.Login(ctx, &authproto.LoginRequest{
		Email:    "admin@example.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	ctxWithAdminToken := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+adminLoginResp.GetToken())

	// Register regular user
	userRegResp, err := client.Register(ctx, &authproto.RegisterRequest{
		Username: "regularuser",
		Email:    "regular@example.com",
		Password: "Password123!",
		Gender:   true,
		Country:  "RU",
		Age:      25,
		Role:     "user",
	})
	require.NoError(t, err)

	// Login as regular user
	userLoginResp, err := client.Login(ctx, &authproto.LoginRequest{
		Email:    "regular@example.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	ctxWithUserToken := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+userLoginResp.GetToken())

	tests := []struct {
		name        string
		ctx         context.Context
		req         *authproto.SetUserRoleRequest
		wantErr     bool
		errCode     codes.Code
		description string
	}{
		{
			name: "successful role set by admin",
			ctx:  ctxWithAdminToken,
			req: &authproto.SetUserRoleRequest{
				Id:   userRegResp.GetId(),
				Role: "artist",
			},
			wantErr: false,
		},
		{
			name: "unauthorized access by regular user",
			ctx:  ctxWithUserToken,
			req: &authproto.SetUserRoleRequest{
				Id:   userRegResp.GetId(),
				Role: "artist",
			},
			wantErr:     true,
			errCode:     codes.PermissionDenied,
			description: "only admin can set user role",
		},
		{
			name: "invalid token",
			ctx:  ctx,
			req: &authproto.SetUserRoleRequest{
				Id:   userRegResp.GetId(),
				Role: "artist",
			},
			wantErr:     true,
			errCode:     codes.Unauthenticated,
			description: "invalid token",
		},
		{
			name: "invalid user ID",
			ctx:  ctxWithAdminToken,
			req: &authproto.SetUserRoleRequest{
				Id:   "11111111-1111-1111-1111-111111111111",
				Role: "artist",
			},
			wantErr:     true,
			errCode:     codes.Internal,
			description: "user not found",
		},
		{
			name: "invalid role",
			ctx:  ctxWithAdminToken,
			req: &authproto.SetUserRoleRequest{
				Id:   userRegResp.GetId(),
				Role: "invalid_role",
			},
			wantErr:     true,
			errCode:     codes.InvalidArgument,
			description: "invalid role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.SetUserRole(tt.ctx, tt.req)
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
			assert.Equal(t, tt.req.GetRole(), resp.GetRole())
		})
	}
}

func TestUpdateUser(t *testing.T) {
	conn, cleanup := setupTestServer(t)
	defer cleanup()

	client := authproto.NewAuthClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Register a test user
	regResp, err := client.Register(ctx, &authproto.RegisterRequest{
		Username: "updateuser",
		Email:    "update@example.com",
		Password: "Password123!",
		Gender:   true,
		Country:  "RU",
		Age:      25,
		Role:     "user",
	})
	require.NoError(t, err)
	require.NotEmpty(t, regResp.GetId())

	// Login to get token
	loginResp, err := client.Login(ctx, &authproto.LoginRequest{
		Email:    "update@example.com",
		Password: "Password123!",
	})
	require.NoError(t, err)
	require.NotEmpty(t, loginResp.GetToken())

	ctxWithToken := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+loginResp.GetToken())

	tests := []struct {
		name        string
		req         *authproto.UpdateUserRequest
		wantErr     bool
		errCode     codes.Code
		description string
	}{
		{
			name: "successful update",
			req: &authproto.UpdateUserRequest{
				Id:       regResp.GetId(),
				Username: "updated_username",
				Country:  "US",
				Age:      30,
			},
			wantErr: false,
		},
		{
			name: "update by admin",
			req: &authproto.UpdateUserRequest{
				Id:       regResp.GetId(),
				Username: "admin_updated",
				Country:  "UK",
				Age:      35,
			},
			wantErr: false,
		},
		{
			name: "unauthorized access",
			req: &authproto.UpdateUserRequest{
				Id:       "other_user_id",
				Username: "hacker",
				Country:  "RU",
				Age:      25,
			},
			wantErr:     true,
			errCode:     codes.PermissionDenied,
			description: "you can only update your own profile",
		},
		{
			name: "invalid username",
			req: &authproto.UpdateUserRequest{
				Id:       regResp.GetId(),
				Username: "ab",
				Country:  "RU",
				Age:      25,
			},
			wantErr:     true,
			errCode:     codes.InvalidArgument,
			description: "username must be between 3 and 20 characters",
		},
		{
			name: "invalid age",
			req: &authproto.UpdateUserRequest{
				Id:       regResp.GetId(),
				Username: "valid_username",
				Country:  "RU",
				Age:      -1,
			},
			wantErr:     true,
			errCode:     codes.InvalidArgument,
			description: "age must be between 0 and 150",
		},
		{
			name: "invalid token",
			req: &authproto.UpdateUserRequest{
				Id:       regResp.GetId(),
				Username: "valid_username",
				Country:  "RU",
				Age:      25,
			},
			wantErr:     true,
			errCode:     codes.Unauthenticated,
			description: "invalid token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testCtx context.Context
			if tt.name == "invalid token" {
				testCtx = ctx // Use context without token
			} else {
				testCtx = ctxWithToken
			}

			resp, err := client.UpdateUser(testCtx, tt.req)
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
			assert.Equal(t, tt.req.GetUsername(), resp.GetUsername())
		})
	}
}

func TestChangePassword(t *testing.T) {
	conn, cleanup := setupTestServer(t)
	defer cleanup()

	client := authproto.NewAuthClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Register a test user
	regResp, err := client.Register(ctx, &authproto.RegisterRequest{
		Username: "passworduser",
		Email:    "password@example.com",
		Password: "OldPassword123!",
		Gender:   true,
		Country:  "RU",
		Age:      25,
		Role:     "user",
	})
	require.NoError(t, err)
	require.NotEmpty(t, regResp.GetId())

	// Login to get token
	loginResp, err := client.Login(ctx, &authproto.LoginRequest{
		Email:    "password@example.com",
		Password: "OldPassword123!",
	})
	require.NoError(t, err)
	require.NotEmpty(t, loginResp.GetToken())

	ctxWithToken := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+loginResp.GetToken())

	tests := []struct {
		name        string
		req         *authproto.ChangePasswordRequest
		wantErr     bool
		errCode     codes.Code
		description string
	}{
		{
			name: "successful change",
			req: &authproto.ChangePasswordRequest{
				Id:          regResp.GetId(),
				OldPassword: "OldPassword123!",
				NewPassword: "NewPassword123!",
			},
			wantErr: false,
		},
		{
			name: "wrong old password",
			req: &authproto.ChangePasswordRequest{
				Id:          regResp.GetId(),
				OldPassword: "WrongPassword123!",
				NewPassword: "NewPassword123!",
			},
			wantErr:     true,
			errCode:     codes.Internal,
			description: "invalid old password",
		},
		{
			name: "invalid new password",
			req: &authproto.ChangePasswordRequest{
				Id:          regResp.GetId(),
				OldPassword: "OldPassword123!",
				NewPassword: "short",
			},
			wantErr:     true,
			errCode:     codes.InvalidArgument,
			description: "password must be at least 8 characters long",
		},
		{
			name: "unauthorized access",
			req: &authproto.ChangePasswordRequest{
				Id:          "other_user_id",
				OldPassword: "OldPassword123!",
				NewPassword: "NewPassword123!",
			},
			wantErr:     true,
			errCode:     codes.PermissionDenied,
			description: "you can only change your own password",
		},
		{
			name: "invalid token",
			req: &authproto.ChangePasswordRequest{
				Id:          regResp.GetId(),
				OldPassword: "OldPassword123!",
				NewPassword: "NewPassword123!",
			},
			wantErr:     true,
			errCode:     codes.Unauthenticated,
			description: "claims not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testCtx context.Context
			if tt.name == "invalid token" {
				testCtx = ctx // Use context without token
			} else {
				testCtx = ctxWithToken
			}

			resp, err := client.ChangePassword(testCtx, tt.req)
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
			assert.True(t, resp.GetSuccess())
		})
	}
}

func TestGetUser(t *testing.T) {
	conn, cleanup := setupTestServer(t)
	defer cleanup()

	client := authproto.NewAuthClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Register test user
	regResp, err := client.Register(ctx, &authproto.RegisterRequest{
		Username: "getuser",
		Email:    "getuser@example.com",
		Password: "Password123!",
		Gender:   true,
		Country:  "RU",
		Age:      25,
		Role:     "user",
	})
	require.NoError(t, err)
	require.NotEmpty(t, regResp.GetId())

	// Create storage connection for verification
	storage, err := storage.NewStorage(ctx, &config.Config{
		DB: config.DB{
			Host:     "localhost",
			Port:     "5433",
			User:     "testuser",
			Password: "testpass",
			Name:     "testdb",
		},
	})
	require.NoError(t, err)

	// Verify user exists using transaction
	tx, err := storage.GetPool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	var exists bool
	err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", regResp.GetId()).Scan(&exists)
	require.NoError(t, err)
	require.True(t, exists, "User should exist in database")

	// Commit transaction
	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Login to get token
	loginResp, err := client.Login(ctx, &authproto.LoginRequest{
		Email:    "getuser@example.com",
		Password: "Password123!",
	})
	require.NoError(t, err)
	require.NotEmpty(t, loginResp.GetToken())

	ctxWithToken := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+loginResp.GetToken())

	tests := []struct {
		name        string
		ctx         context.Context
		req         *authproto.GetUserRequest
		wantErr     bool
		errCode     codes.Code
		description string
	}{
		{
			name: "successful get own profile",
			ctx:  ctxWithToken,
			req: &authproto.GetUserRequest{
				Id: regResp.GetId(),
			},
			wantErr: false,
		},
		{
			name: "unauthorized access to other profile",
			ctx:  ctxWithToken,
			req: &authproto.GetUserRequest{
				Id: "other_user_id",
			},
			wantErr:     true,
			errCode:     codes.PermissionDenied,
			description: "you can only access your own profile",
		},
		{
			name: "invalid token",
			ctx:  ctx,
			req: &authproto.GetUserRequest{
				Id: regResp.GetId(),
			},
			wantErr:     true,
			errCode:     codes.Unauthenticated,
			description: "invalid token",
		},
		{
			name: "invalid user ID",
			ctx:  ctxWithToken,
			req: &authproto.GetUserRequest{
				Id: "invalid_user_id",
			},
			wantErr:     true,
			errCode:     codes.PermissionDenied,
			description: "you can only access your own profile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.GetUser(tt.ctx, tt.req)
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
			assert.Equal(t, regResp.GetId(), resp.GetId())
			assert.Equal(t, "getuser", resp.GetUsername())
			assert.Equal(t, "getuser@example.com", resp.GetEmail())
			assert.Equal(t, "user", resp.GetRole())
		})
	}
}

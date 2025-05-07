package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	authproto "github.com/zhavkk/Auth-protobuf/gen/go/auth"
	"google.golang.org/grpc"
)

func TestE2E_RegisterLoginGetUser(t *testing.T) {
	grpcAddr := os.Getenv("GRPC_HOST")
	require.NotEmpty(t, grpcAddr, "GRPC_HOST must be set")
	time.Sleep(3 * time.Second)
	conn, err := grpc.Dial(grpcAddr, grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(5*time.Second))
	require.NoError(t, err)
	defer conn.Close()

	client := authproto.NewAuthClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Example test flow
	regResp, err := client.Register(ctx, &authproto.RegisterRequest{
		Username: "e2euser",
		Email:    "e2e@example.com",
		Password: "Password123!",
		Gender:   true,
		Country:  "RU",
		Age:      30,
		Role:     "user",
	})
	require.NoError(t, err)
	require.NotEmpty(t, regResp.GetId())

	loginResp, err := client.Login(ctx, &authproto.LoginRequest{
		Email:    "e2e@example.com",
		Password: "Password123!",
	})
	require.NoError(t, err)
	require.NotEmpty(t, loginResp.GetToken())
}

package auth

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	authproto "github.com/zhavkk/Auth-protobuf/gen/go/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *serverAPI) SetUserRole(ctx context.Context, req *authproto.SetUserRoleRequest) (*authproto.SetUserRoleResponse, error) {
	if err := s.validator.ValidateSetUserRoleRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	claims, ok := ctx.Value("claims").(jwt.MapClaims)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	role := claims["role"].(string)
	if role != "admin" {
		return nil, status.Error(codes.PermissionDenied, "only admin can set user role")
	}

	resp, err := s.service.SetUserRole(ctx, req.GetId(), req.GetRole())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &authproto.SetUserRoleResponse{
		Id:   resp.ID,
		Role: resp.Role,
	}, nil
}

func (s *serverAPI) UpdateUser(ctx context.Context, req *authproto.UpdateUserRequest) (*authproto.UpdateUserResponse, error) {
	if err := s.validator.ValidateUpdateUserRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	claims, ok := ctx.Value("claims").(jwt.MapClaims)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	userID := claims["uuid"].(string)
	role := claims["role"].(string)

	if userID != req.GetId() && role != "admin" {
		return nil, status.Error(codes.PermissionDenied, "you can only update your own profile")
	}

	resp, err := s.service.UpdateUser(ctx, req.GetId(), req.GetUsername(), req.GetCountry(), req.GetAge())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &authproto.UpdateUserResponse{
		Id:       resp.ID,
		Username: resp.Username,
	}, nil
}

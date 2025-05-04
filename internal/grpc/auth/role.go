package auth

import (
	"context"

	authproto "github.com/zhavkk/Auth-protobuf/gen/go/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *serverAPI) SetUserRole(ctx context.Context, req *authproto.SetUserRoleRequest) (*authproto.SetUserRoleResponse, error) {
	if err := s.validator.ValidateSetUserRoleRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
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

	resp, err := s.service.UpdateUser(ctx, req.GetId(), req.GetUsername(), req.GetCountry(), req.GetAge())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &authproto.UpdateUserResponse{
		Id:       resp.ID,
		Username: resp.Username,
	}, nil
}

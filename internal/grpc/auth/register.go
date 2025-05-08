package auth

import (
	"context"

	authproto "github.com/zhavkk/Auth-protobuf/gen/go/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *serverAPI) Register(ctx context.Context,
	req *authproto.RegisterRequest,
) (*authproto.RegisterResponse, error) {
	if err := s.validator.ValidateRegisterRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := s.service.Register(
		ctx, req.GetUsername(),
		req.GetEmail(),
		req.GetPassword(),
		req.GetGender(),
		req.GetCountry(),
		req.GetAge(),
		req.GetRole(),
	)

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &authproto.RegisterResponse{
		Id: resp.ID,
	}, nil
}

func (s *serverAPI) GetUser(ctx context.Context,
	req *authproto.GetUserRequest,
) (*authproto.GetUserResponse, error) {
	if err := s.validator.ValidateGetUserRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	userID, err := GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if userID != req.GetId() {
		return nil, status.Error(codes.PermissionDenied, "you can only access your own profile")
	}

	resp, err := s.service.GetUser(ctx, req.GetId())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &authproto.GetUserResponse{
		Id:       resp.ID,
		Username: resp.Username,
		Email:    resp.Email,
		Gender:   resp.Gender,
		Country:  resp.Country,
		Age:      resp.Age,
		Role:     resp.Role,
	}, nil
}

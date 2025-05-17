package auth

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	authproto "github.com/zhavkk/gRPC_auth_service/pkg/authpb"
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

	callerUserID, err := GetUserIDFromContext(ctx)
	if err != nil {
		logger.Log.Warn("GetUser: Failed to get caller UserID from context", "error", err)
		return nil, err
	}

	callerUserRole, err := GetRoleFromContext(ctx)
	if err != nil {
		logger.Log.Warn("GetUser: Failed to get caller UserRole from context", "error", err)
		return nil, err
	}

	logger.Log.Debug("GetUser: Attempting to get user profile",
		slog.String("caller_id", callerUserID),
		slog.String("caller_role", callerUserRole),
		slog.String("target_user_id", req.GetId()))

	if callerUserRole != "admin" && callerUserID != req.GetId() {
		logger.Log.Warn("GetUser: Permission denied",
			slog.String("caller_id", callerUserID),
			slog.String("caller_role", callerUserRole),
			slog.String("target_user_id", req.GetId()))
		return nil, status.Error(codes.PermissionDenied, "you can only access your own profile or you are not an admin")
	}

	logger.Log.Info("GetUser: Access granted",
		slog.String("caller_id", callerUserID),
		slog.String("caller_role", callerUserRole),
		slog.String("target_user_id", req.GetId()))

	resp, err := s.service.GetUser(ctx, req.GetId())
	if err != nil {
		logger.Log.Error("GetUser: Service call to GetUser failed", "error", err, "target_user_id", req.GetId())
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

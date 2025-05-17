package auth

import (
	"context"
	"log/slog"

	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	authproto "github.com/zhavkk/gRPC_auth_service/pkg/authpb"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *serverAPI) SetUserRole(ctx context.Context,
	req *authproto.SetUserRoleRequest,
) (*authproto.SetUserRoleResponse, error) {
	if err := s.validator.ValidateSetUserRoleRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	currentUserRole, err := GetRoleFromContext(ctx)
	if err != nil {
		logger.Log.Warn("SetUserRole: Failed to get current user role from context", "error", err)
		return nil, err
	}

	if currentUserRole != "admin" {
		logger.Log.Warn("SetUserRole: Permission denied",
			slog.String("user_role", currentUserRole),
			slog.String("target_user_id", req.GetId()))
		return nil, status.Error(codes.PermissionDenied, "only admin can set user role")
	}

	logger.Log.Info("SetUserRole: Admin user performing role update",
		slog.String("admin_role", currentUserRole),
		slog.String("target_user_id", req.GetId()),
		slog.String("new_role", req.GetRole()))

	resp, err := s.service.SetUserRole(ctx, req.GetId(), req.GetRole())
	if err != nil {
		logger.Log.Error("SetUserRole: Service call to SetUserRole failed",
			slog.String("error", err.Error()),
			slog.String("target_user_id", req.GetId()))
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &authproto.SetUserRoleResponse{
		Id:   resp.ID,
		Role: resp.Role,
	}, nil
}

func (s *serverAPI) UpdateUser(ctx context.Context,
	req *authproto.UpdateUserRequest,
) (*authproto.UpdateUserResponse, error) {
	if err := s.validator.ValidateUpdateUserRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	callerUserID, err := GetUserIDFromContext(ctx)
	if err != nil {
		logger.Log.Warn("UpdateUser: Failed to get caller UserID from context", "error", err)
		return nil, err
	}

	callerUserRole, err := GetRoleFromContext(ctx)
	if err != nil {
		logger.Log.Warn("UpdateUser: Failed to get caller UserRole from context", "error", err)
		return nil, err
	}
	logger.Log.Debug("UpdateUser: Attempting to update user profile",
		slog.String("caller_id", callerUserID),
		slog.String("caller_role", callerUserRole),
		slog.String("target_user_id", req.GetId()))

	if callerUserRole != "admin" && callerUserID != req.GetId() {
		logger.Log.Warn("UpdateUser: Permission denied",
			slog.String("caller_id", callerUserID),
			slog.String("caller_role", callerUserRole),
			slog.String("target_user_id", req.GetId()))
		return nil, status.Error(codes.PermissionDenied,
			"you can only update your own profile or you are not an admin")
	}

	logger.Log.Info("UpdateUser: Access granted",
		slog.String("caller_id", callerUserID),
		slog.String("caller_role", callerUserRole),
		slog.String("target_user_id", req.GetId()))

	resp, err := s.service.UpdateUser(ctx, req.GetId(), req.GetUsername(), req.GetCountry(), req.GetAge())
	if err != nil {
		logger.Log.Error("UpdateUser: Service call to UpdateUser failed",
			slog.String("error", err.Error()),
			slog.String("target_user_id", req.GetId()))
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &authproto.UpdateUserResponse{
		Id:       resp.ID,
		Username: resp.Username,
	}, nil
}

package auth

import (
	"context"
	"errors"
	"log/slog"

	"github.com/zhavkk/gRPC_auth_service/internal/dto"
	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	"github.com/zhavkk/gRPC_auth_service/internal/models"
	"github.com/zhavkk/gRPC_auth_service/internal/service"
	authproto "github.com/zhavkk/gRPC_auth_service/pkg/authpb"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *serverAPI) UpdateUser(
	ctx context.Context,
	req *authproto.UpdateUserRequest,
) (*authproto.UpdateUserResponse, error) {
	const op = "serverAPI.UpdateUser"
	if err := s.validator.ValidateUpdateUserRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	callerID, err := GetUserIDFromContext(ctx)
	if err != nil {
		logger.Log.Warn(op, "err", err)
		return nil, status.Error(codes.Unauthenticated, errInvalidToken)
	}
	callerRole, err := GetRoleFromContext(ctx)
	if err != nil {
		logger.Log.Warn(op, "err", err)
		return nil, status.Error(codes.Unauthenticated, errInvalidToken)
	}

	if callerRole != string(models.RoleAdmin) && callerID != req.GetId() {
		logger.Log.Warn(op, "permission denied",
			slog.String("caller_id", callerID),
			slog.String("caller_role", string(callerRole)),
			slog.String("target_id", req.GetId()),
		)
		return nil, status.Error(codes.PermissionDenied, ErrPermissionDenied)
	}

	params := dto.UpdateUserParams{
		ID:       req.GetId(),
		Username: req.GetUsername(),
		Country:  req.GetCountry(),
		Age:      req.GetAge(),
	}
	out, err := s.service.UpdateUser(ctx, params)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		if errors.Is(err, service.ErrUsernameAlreadyTaken) {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}

		logger.Log.Error(op, "err", err)
		return nil, status.Error(codes.Internal, ErrPermissionDenied)

	}
	return &authproto.UpdateUserResponse{
		Success: out.Success,
	}, nil
}

func (s *serverAPI) UpdateArtist(
	ctx context.Context,
	req *authproto.UpdateArtistRequest,
) (*authproto.UpdateArtistResponse, error) {
	const op = "serverAPI.UpdateArtist"

	if err := s.validator.ValidateUpdateArtistRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	callerID, err := GetUserIDFromContext(ctx)
	if err != nil {
		logger.Log.Warn(op, "err", err)
		return nil, status.Error(codes.Unauthenticated, ErrInvalidToken)
	}
	callerRole, err := GetRoleFromContext(ctx)
	if err != nil {
		logger.Log.Warn(op, "err", err)
		return nil, status.Error(codes.Unauthenticated, ErrInvalidToken)
	}

	if callerRole != string(models.RoleAdmin) && callerID != req.GetId() {
		logger.Log.Warn(op, "permission denied",
			slog.String("caller_id", callerID),
			slog.String("caller_role", string(callerRole)),
			slog.String("target_id", req.GetId()),
		)
		return nil, status.Error(codes.PermissionDenied, ErrPermissionDenied)
	}

	params := dto.UpdateArtistParams{
		ID:          req.GetId(),
		Author:      req.GetAuthor(),
		Producer:    req.GetProducer(),
		Country:     req.GetCountry(),
		Description: req.GetDescription(),
	}
	out, err := s.service.UpdateArtist(ctx, params)
	if err != nil {
		if errors.Is(err, service.ErrArtistNotFound) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		logger.Log.Error(op, "service.UpdateArtist failed", "err", slog.Any("err", err))
		return nil, status.Error(codes.Internal, ErrPermissionDenied)

	}
	return &authproto.UpdateArtistResponse{
		Success: out.Success,
	}, nil
}

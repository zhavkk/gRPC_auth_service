package auth

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zhavkk/gRPC_auth_service/internal/dto"
	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	"github.com/zhavkk/gRPC_auth_service/internal/models"
	"github.com/zhavkk/gRPC_auth_service/internal/service"
	authproto "github.com/zhavkk/gRPC_auth_service/pkg/authpb"
)

func (s *serverAPI) RegisterUser(ctx context.Context,
	req *authproto.RegisterUserRequest,
) (*authproto.RegisterUserResponse, error) {
	if err := s.validator.ValidateRegisterUserRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	params := dto.RegisterUserParams{
		Username: req.GetUsername(),
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
		Gender:   req.GetGender(),
		Country:  req.GetCountry(),
		Age:      req.GetAge(),
	}

	out, err := s.service.RegisterUser(ctx, params)

	if err != nil {

		if errors.Is(err, service.ErrUserAlreadyExists) {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		if errors.Is(err, service.ErrUsernameAlreadyTaken) {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &authproto.RegisterUserResponse{
		Id: out.ID,
	}, nil
}

func (s *serverAPI) RegisterArtist(ctx context.Context,
	req *authproto.RegisterArtistRequest,
) (*authproto.RegisterArtistResponse, error) {
	if err := s.validator.ValidateRegisterArtistRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	params := dto.RegisterArtistParams{
		Username:    req.GetUsername(),
		Password:    req.GetPassword(),
		Author:      req.GetAuthor(),
		Producer:    req.GetProducer(),
		Country:     req.GetCountry(),
		Description: req.GetDescription(),
	}

	out, err := s.service.RegisterArtist(ctx, params)

	if err != nil {
		if errors.Is(err, service.ErrArtistAlreadyExists) {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		if errors.Is(err, service.ErrUsernameAlreadyTaken) {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &authproto.RegisterArtistResponse{
		Id: out.ID,
	}, nil
}

func (s *serverAPI) GetUser(
	ctx context.Context,
	req *authproto.GetUserRequest,
) (*authproto.GetUserResponse, error) {
	const op = "serverAPI.GetUser"

	if err := s.validator.ValidateGetUserRequest(req); err != nil {
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

	logger.Log.Debug(op,
		slog.String("caller_id", callerID),
		slog.String("caller_role", string(callerRole)),
		slog.String("target_id", req.GetId()),
	)
	if callerRole != string(models.RoleAdmin) && callerID != req.GetId() {
		logger.Log.Warn(op, "permission denied",
			slog.String("caller_id", callerID),
			slog.String("caller_role", string(callerRole)),
			slog.String("target_id", req.GetId()),
		)
		return nil, status.Error(codes.PermissionDenied, ErrPermissionDenied)
	}

	params := dto.GetUserParams{ID: req.GetId()}
	userDto, err := s.service.GetUser(ctx, params)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		logger.Log.Error(op, "err", err)
		return nil, status.Error(codes.Internal, ErrInternal)
	}

	return &authproto.GetUserResponse{
		Id:        userDto.ID,
		Username:  userDto.Username,
		Email:     userDto.Email,
		Gender:    userDto.Gender,
		Country:   userDto.Country,
		Age:       userDto.Age,
		Role:      toProtoRole(userDto.Role),
		CreatedAt: timestamppb.New(userDto.CreatedAt),
		UpdatedAt: timestamppb.New(userDto.UpdatedAt),
	}, nil
}

func (s *serverAPI) GetArtist(
	ctx context.Context,
	req *authproto.GetArtistRequest,
) (*authproto.GetArtistResponse, error) {
	const op = "serverAPI.GetArtist"

	if err := s.validator.ValidateGetArtistRequest(req); err != nil {
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

	logger.Log.Debug(op,
		slog.String("caller_id", callerID),
		slog.String("caller_role", string(callerRole)),
		slog.String("target_id", req.GetId()),
	)
	if callerRole != string(models.RoleAdmin) && callerID != req.GetId() {
		logger.Log.Warn(op, "permission denied",
			slog.String("caller_id", callerID),
			slog.String("caller_role", string(callerRole)),
			slog.String("target_id", req.GetId()),
		)
		return nil, status.Error(codes.PermissionDenied, ErrPermissionDenied)
	}

	params := dto.GetArtistParams{ID: req.GetId()}
	artistDto, err := s.service.GetArtist(ctx, params)
	if err != nil {
		if errors.Is(err, service.ErrArtistNotFound) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		logger.Log.Error(op, "err", err)
		return nil, status.Error(codes.Internal, ErrInternal)
	}

	return &authproto.GetArtistResponse{
		Id:          artistDto.ID,
		Username:    artistDto.Username,
		Author:      artistDto.Author,
		Producer:    artistDto.Producer,
		Country:     artistDto.Country,
		Description: artistDto.Description,
		CreatedAt:   timestamppb.New(artistDto.CreatedAt),
		UpdatedAt:   timestamppb.New(artistDto.UpdatedAt),
	}, nil
}

package auth

import (
	"github.com/zhavkk/gRPC_auth_service/internal/models"
	authproto "github.com/zhavkk/gRPC_auth_service/pkg/authpb"
)

func toProtoRole(r models.Role) authproto.Role {
	switch r {
	case models.RoleUser:
		return authproto.Role_USER
	case models.RoleArtist:
		return authproto.Role_ARTIST
	case models.RoleAdmin:
		return authproto.Role_ADMIN
	default:
		return authproto.Role_ROLE_UNSPECIFIED
	}
}

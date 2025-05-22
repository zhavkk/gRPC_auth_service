package models

type Role string

const (
	RoleUser   Role = "user"
	RoleArtist Role = "artist"
	RoleAdmin  Role = "admin"
)

func (r Role) IsValid() bool {
	return r == RoleUser || r == RoleArtist || r == RoleAdmin
}

func (r Role) String() string {
	return string(r)
}

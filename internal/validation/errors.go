package validation

import "errors"

var (
	ErrInvalidEmail             = errors.New("invalid email format")
	ErrInvalidPassword          = errors.New("invalid password")
	ErrPasswordTooShort         = errors.New("password must be at least 8 characters long")
	ErrPasswordMissingUppercase = errors.New("password must contain at least one uppercase letter")
	ErrPasswordMissingLowercase = errors.New("password must contain at least one lowercase letter")
	ErrPasswordMissingDigit     = errors.New("password must contain at least one digit")
	ErrPasswordMissingSpecial   = errors.New("password must contain at least one special character")
	ErrInvalidUsername          = errors.New("invalid username")
	ErrInvalidAge               = errors.New("invalid age")
	ErrInvalidRole              = errors.New("invalid role")
	ErrUserIDRequired           = errors.New("user ID is required")
	ErrOldPasswordRequired      = errors.New("old password is required")
	ErrNewPasswordRequired      = errors.New("new password is required")
	ErrRefreshTokenRequired     = errors.New("refresh token is required")
	ErrRoleRequired             = errors.New("role is required")
	ErrRoleMustBeUserOrArtist   = errors.New("role must be either 'user' or 'artist'")
	ErrPermissionDenied         = errors.New("permission denied")
	ErrArtistIDRequired         = errors.New("artist ID is required")
	ErrInvalidAuthor            = errors.New("invalid author")
)

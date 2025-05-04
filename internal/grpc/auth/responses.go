package auth

type RegisterResponse struct {
	ID string
}

type LoginResponse struct {
	ID       string
	Username string
	Email    string
	Role     string
	Token    string
}

type SetUserRoleResponse struct {
	ID   string
	Role string
}

type GetUserResponse struct {
	ID       string
	Username string
	Email    string
	Gender   bool
	Country  string
	Age      int32
	Role     string
}

type UpdateUserResponse struct {
	ID       string
	Username string
	Email    string
	Gender   bool
	Country  string
	Age      int32
	Role     string
}

type ChangePasswordResponse struct {
	Success bool
}

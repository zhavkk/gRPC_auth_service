package validation

import "testing"

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		{
			name:     "valid username",
			username: "testuser",
			wantErr:  false,
		},
		{
			name:     "invalid username",
			username: "ab",
			wantErr:  true,
		},
		{
			name:     "empty username",
			username: "",
			wantErr:  true,
		},
		{
			name:     "username too long",
			username: "thisusernameiswaytoolong",
			wantErr:  true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateUsername(test.username)
			if (err != nil) != test.wantErr {
				t.Errorf("ValidateUsername(%q) = %v, want %v", test.username, err, test.wantErr)
			}
		})
	}

}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{
			name:    "valid email",
			email:   "test@example.com",
			wantErr: false,
		},
		{
			name:    "invalid email",
			email:   "invalid-email",
			wantErr: true,
		},
		{
			name:    "empty email",
			email:   "",
			wantErr: true,
		},
		{
			name:    "missing @",
			email:   "test.com",
			wantErr: true,
		},
		{
			name:    "missing domain",
			email:   "test@",
			wantErr: true,
		},
		{
			name:    "missing local part",
			email:   "@example.com",
			wantErr: true,
		},
		{
			name:    "missing @ and domain",
			email:   "test",
			wantErr: true,
		},
		{
			name:    "missing @ and local part",
			email:   "test.com",
			wantErr: true,
		},
		{
			name:    "missing @ and local part and domain",
			email:   "test",
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateEmail(test.email)
			if (err != nil) != test.wantErr {
				t.Errorf("ValidateEmail(%q) = %v, want %v", test.email, err, test.wantErr)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid password",
			password: "Password123!",
			wantErr:  false,
		},
		{
			name:     "short password",
			password: "short",
			wantErr:  true,
		},
		{
			name:     "missing uppercase",
			password: "password123!",
			wantErr:  true,
		},
		{
			name:     "missing lowercase",
			password: "PASSWORD123!",
			wantErr:  true,
		},
		{
			name:     "missing number",
			password: "Password!",
			wantErr:  true,
		},
		{
			name:     "missing special character",
			password: "Password123",
			wantErr:  true,
		},
		{
			name:     "missing uppercase, lowercase, number, and special character",
			password: "password",
			wantErr:  true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidatePassword(test.password)
			if (err != nil) != test.wantErr {
				t.Errorf("ValidatePassword(%q) = %v, want %v", test.password, err, test.wantErr)
			}
		})
	}
}

func TestValidateAge(t *testing.T) {
	tests := []struct {
		name    string
		age     int32
		wantErr bool
	}{
		{
			name:    "valid age",
			age:     25,
			wantErr: false,
		},
		{
			name:    "invalid age",
			age:     151,
			wantErr: true,
		},
		{
			name:    "negative age",
			age:     -1,
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateAge(test.age)
			if (err != nil) != test.wantErr {
				t.Errorf("ValidateAge(%d) = %v, want %v", test.age, err, test.wantErr)
			}
		})
	}
}

func TestValidateRole(t *testing.T) {
	tests := []struct {
		name    string
		role    string
		wantErr bool
	}{
		{
			name:    "valid role",
			role:    "admin",
			wantErr: false,
		},
		{
			name:    "invalid role",
			role:    "invalid-role",
			wantErr: true,
		},
		{
			name:    "empty role",
			role:    "",
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateRole(test.role)
			if (err != nil) != test.wantErr {
				t.Errorf("ValidateRole(%q) = %v, want %v", test.role, err, test.wantErr)
			}
		})
	}
}

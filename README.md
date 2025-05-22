# gRPC Authentication Service

A robust authentication service built with gRPC, providing secure user authentication and authorization capabilities. The service is designed to handle user registration, login, token management, and profile management with support for both regular users and artists.

## Features

- **User Authentication**
  - User registration with email and password
  - Secure login with JWT token generation
  - Token refresh mechanism
  - Secure password hashing using bcrypt
  - Logout functionality

- **Artist Management**
  - Artist registration
  - Artist profile management
  - Artist-specific operations

- **Security**
  - JWT-based authentication
  - Access and refresh token support
  - Secure password storage
  - Role-based access control
  - Token blacklisting using Redis

- **Database**
  - PostgreSQL for persistent storage
  - Redis for token management
  - Transaction support for data consistency

## Prerequisites

- Go 1.24.2 or higher
- PostgreSQL 15
- Redis
- Protocol Buffers compiler (protoc)
- Docker and Docker Compose (for containerized deployment)

## Project Structure

```
gRPC_auth_service/
├── api/            # Protocol Buffer definitions
├── cmd/            # Application entry points
├── config/         # Configuration files
├── internal/       # Internal packages
│   ├── app/       # Application setup
│   ├── dto/       # Data Transfer Objects
│   ├── grpc/      # gRPC server implementation
│   ├── models/    # Domain models
│   ├── pkg/       # Shared packages
│   ├── repository/# Database repositories
│   ├── service/   # Business logic
│   └── storage/   # Database connections
├── migrations/     # Database migrations
├── pkg/           # Public packages
└── bin/           # Compiled binaries
```

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/gRPC_auth_service.git
   cd gRPC_auth_service
   ```

2. Install dependencies:
   ```bash
   go mod download
   ```

3. Set up environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. Start the required services using Docker Compose:
   ```bash
   make compose-up
   ```

5. Run database migrations:
   ```bash
   make migrate-up
   ```

6. Build and run the service:
   ```bash
   make build
   make run
   ```

## Development

### Generating Protocol Buffers

To generate gRPC code from proto files:
```bash
make gen-pb
```

### Running Tests

```bash
go test ./...
```

### Available Make Commands

- `make build` - Build the service
- `make run` - Run the service
- `make compose-up` - Start Docker containers
- `make compose-down` - Stop Docker containers
- `make migrate-up` - Run database migrations
- `make migrate-down` - Rollback database migrations
- `make gen-pb` - Generate Protocol Buffer code
- `make test-deps-up` - Start test dependencies

## API Endpoints

The service exposes the following gRPC endpoints:

- `RegisterUser` - Register a new user
- `RegisterArtist` - Register a new artist
- `Login` - Authenticate user and get tokens
- `GetUser` - Get user information
- `GetArtist` - Get artist information
- `UpdateUser` - Update user profile
- `UpdateArtist` - Update artist profile
- `ChangePassword` - Change user password
- `RefreshToken` - Refresh access token
- `Logout` - Invalidate refresh token

## Configuration

The service can be configured using environment variables or a YAML configuration file. Key configuration options include:

- Database connection string
- Redis connection details
- JWT secret and token TTLs
- gRPC server port
- Log level

## Security

- All passwords are hashed using bcrypt
- JWT tokens are used for authentication
- Refresh tokens are stored in Redis with expiration
- Role-based access control is implemented
- Input validation is performed on all requests

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

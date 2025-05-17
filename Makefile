CONFIG_PATH=./config/config.yaml
COMPOSE_PATH=./config/docker-compose.yml
MIGRATIONS_DIR=./migrations
DB_URL=postgres://testuser:testpass@localhost:5432/auth_db

.PHONY: build
build: gen-pb
	@go build -o bin/auth_service cmd/auth_service/main.go

.PHONY: run
run: build
	bin/auth_service --path $(CONFIG_PATH)

# Docker
.PHONY: compose-up
compose-up:
	@docker compose -f $(COMPOSE_PATH) up -d
	@docker compose -f $(COMPOSE_PATH) exec -T postgres bash -c \
	'until pg_isready -U testuser -d auth_db; do sleep 1; done'


.PHONY: compose-down
compose-down:
	@docker compose -f $(COMPOSE_PATH) down 

# Migrations
.PHONY: migrate-up
migrate-up:
	goose -dir $(MIGRATIONS_DIR) postgres "$(DB_URL)" up

.PHONY: migrate-down
migrate-down:
	goose -dir $(MIGRATIONS_DIR) postgres "$(DB_URL)" down

# Protobuf
.PHONY: gen-pb
gen-pb:
	@protoc --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative \
		    --go_out=pkg/authpb --go-grpc_out=pkg/authpb \
		    -I api api/auth_proto.proto

# for tests
.PHONY: test-deps-up
test-deps-up: compose-up migrate-up

.PHONY: test-deps-down
test-deps-down: compose-down
FROM golang:1.24.2-alpine

WORKDIR /app
RUN apk add --no-cache git curl

RUN go install github.com/pressly/goose/v3/cmd/goose@latest

COPY migrations ./migrations

ENV DB_URL=postgres://testuser:testpass@postgres:5432/testdb?sslmode=disable
ENV MIGRATIONS_DIR=./migrations

CMD ["goose", "-dir", "./migrations", "postgres", "postgres://testuser:testpass@postgres:5432/testdb?sslmode=disable", "up"]

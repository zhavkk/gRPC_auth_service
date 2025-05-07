FROM golang:1.24.2-alpine

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go test -c ./test/e2e -o e2e.test

ENTRYPOINT ["./e2e.test"]

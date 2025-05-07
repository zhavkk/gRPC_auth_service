FROM golang:1.24.2-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o main ./cmd/main

FROM alpine:3.18

WORKDIR /app

COPY --from=builder /app/main .
COPY config ./config  
COPY .env .            

EXPOSE 50051

CMD ["./main"]

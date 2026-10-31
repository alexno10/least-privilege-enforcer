# Stage 1: Build the static Go binary
FROM golang:1.22-alpine AS builder

WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/least-privilege-enforcer ./cmd/enforcer

# Stage 2: Minimal hardened runtime image for GitHub Actions execution
FROM alpine:3.20

RUN apk add --no-cache ca-certificates git

COPY --from=builder /out/least-privilege-enforcer /usr/local/bin/least-privilege-enforcer

ENTRYPOINT ["/usr/local/bin/least-privilege-enforcer"]

# Build stage
FROM golang:1.24-alpine AS build
WORKDIR /app

# Install upx for binary compression
RUN apk add --no-cache upx

# Copy and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and build the binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -trimpath -o /checker && \
    upx --best --lzma /checker

# Final stage
FROM alpine:3.18
RUN apk add --no-cache ca-certificates
COPY --from=build /checker /checker
ENTRYPOINT ["/checker"]

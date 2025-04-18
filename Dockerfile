FROM golang:1.24-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /checker

# Final stage
FROM alpine:3.18
RUN apk add --no-cache ca-certificates
COPY --from=build /checker /checker
ENTRYPOINT ["/checker"]
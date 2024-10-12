FROM golang:1.23-alpine AS build-stage

RUN apk add --no-cache --update gcc musl-dev git

WORKDIR /app

# Copy go.mod and go.sum files first to cache dependency downloads
COPY go.mod go.sum ./
# Download dependencies
RUN go mod download

COPY . ./

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags="-X main.BuildVersion=$(./version.sh)" -o /app/gitea-act-dynamic

# Deploy the application binary into a lean image
FROM alpine AS build-release-stage

WORKDIR /

COPY --from=build-stage /app/gitea-act-dynamic /gitea-act-dynamic

ENTRYPOINT ["/gitea-act-dynamic"]
FROM golang:1.23-alpine AS build-stage

WORKDIR /app

COPY . ./

RUN GOOS=linux go build -ldflags="-X main.BuildVersion=$(./version.sh)" -o /app/gitea-act-dynamic

# Deploy the application binary into a lean image
FROM alpine AS build-release-stage

WORKDIR /

COPY --from=build-stage /app/gitea-act-dynamic /gitea-act-dynamic

ENTRYPOINT ["/gitea-act-dynamic"]
FROM golang:1.23-alpine AS build

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY cmd/ ./cmd/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/mikrotik-wg-easy ./cmd/mikrotik-wg-easy

FROM scratch

COPY --from=build /out/mikrotik-wg-easy /mikrotik-wg-easy

ENV APP_HOST=0.0.0.0 \
    APP_PORT=8080 \
    APP_DATA=/data \
    APP_TRUST_PROXY_HEADERS=0

VOLUME ["/data"]
EXPOSE 8080
USER 10001
ENTRYPOINT ["/mikrotik-wg-easy"]

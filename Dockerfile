# syntax=docker/dockerfile:1

FROM golang:1.27rc2-alpine AS build
WORKDIR /src
# Download modules first so they cache independently of source changes.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/wg-status ./cmd/wg-status

# Minimal runtime. For the "wg" collector in production you would instead run
# the binary under systemd on the host: it talks to WireGuard over netlink, so
# it needs the host network namespace and CAP_NET_ADMIN. This image is aimed at
# local/demo use with the fake collector, where no privileges are required.
FROM alpine:3.24
RUN adduser -D -u 10001 app
COPY --from=build /out/wg-status /usr/local/bin/wg-status
USER app
EXPOSE 8080
ENV WG_LISTEN=:8080 WG_COLLECTOR=fake
ENTRYPOINT ["/usr/local/bin/wg-status"]

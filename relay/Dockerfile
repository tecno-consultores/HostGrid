FROM golang:1.22-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/hostgrid-relay ./cmd/hostgrid-relay

FROM alpine:3.21

RUN addgroup -S -g 10001 hostgrid \
    && adduser -S -u 10001 -G hostgrid -H -s /sbin/nologin hostgrid \
    && mkdir -p /var/cache/hostgrid-relay \
    && chown -R hostgrid:hostgrid /var/cache/hostgrid-relay

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/hostgrid-relay /usr/local/bin/hostgrid-relay

USER 10001:10001
EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/hostgrid-relay"]

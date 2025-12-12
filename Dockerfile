FROM golang:1.25-alpine AS builder

RUN apk add --no-cache \
    ca-certificates \
    git \
    build-base \
    linux-headers

WORKDIR /app

COPY agent/go.mod agent/go.sum ./

RUN go mod download

COPY agent/ ./

RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-extldflags "-static"' -installsuffix cgo -o agent .

FROM alpine:latest

RUN apk --no-cache add \
    ca-certificates \
    iptables \
    libpcap-dev

RUN addgroup -g 65532 -S agent && \
    adduser -S agent -u 65532 -G agent

RUN mkdir -p /app

COPY --from=builder /app/agent /app/agent

RUN chmod +x /app/agent

RUN modprobe nfnetlink_queue || true

RUN chown agent:agent /app/agent

WORKDIR /app

USER agent

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep agent || exit 1

EXPOSE 8080

ENTRYPOINT ["/app/agent"]
CMD ["--firewall-mode=audit", "--tetragon-address=localhost:54321", "--nfqueue-num=0"]

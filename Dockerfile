# syntax=docker/dockerfile:1.7

FROM golang:1.27.0-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
      -buildvcs=false \
      -trimpath \
      -ldflags="-s -w -buildid=" \
      -o /out/proxygen \
      ./cmd/proxygen && \
    mkdir -p /runtime/tmp /runtime/etc/proxygen && \
    chown -R 65532:65532 /runtime

FROM gcr.io/distroless/static-debian12:nonroot

ENV TMPDIR=/tmp

COPY --from=build --chown=65532:65532 /out/proxygen /proxygen
COPY --from=build --chown=65532:65532 /runtime/tmp /tmp
COPY --from=build --chown=65532:65532 /runtime/etc/proxygen /etc/proxygen

USER 65532:65532

EXPOSE 51820/udp

ENTRYPOINT ["/proxygen"]
CMD ["-config", "/etc/proxygen/config.json"]

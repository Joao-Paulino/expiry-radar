# syntax=docker/dockerfile:1
# Two images from one file:
#   docker build --target collector -t expiry-radar-collector .
#   docker build --target agent     -t expiry-radar-agent .
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN for c in collector agent; do \
      CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" -o /out/$c ./cmd/$c; \
    done && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot AS collector
COPY --from=build /out/collector /usr/local/bin/collector
COPY --from=build --chown=65532:65532 /out/data /data
USER nonroot:nonroot
EXPOSE 8443
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/collector"]
CMD ["/etc/expiry-radar/collector.json"]

FROM gcr.io/distroless/static-debian12:nonroot AS agent
COPY --from=build /out/agent /usr/local/bin/agent
COPY --from=build --chown=65532:65532 /out/data /data
USER nonroot:nonroot
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/agent"]
CMD ["/etc/expiry-radar/agent.json"]

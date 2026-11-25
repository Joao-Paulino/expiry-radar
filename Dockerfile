# syntax=docker/dockerfile:1
# Three images from one file:
#   docker build --target collector -t expiry-radar-collector .
#   docker build --target agent     -t expiry-radar-agent .
#   docker build --target demo      -t expiry-radar-demo .   (see docker-compose.demo.yml)
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN for c in collector agent demoinit demoseed; do \
      CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" -o /out/$c ./cmd/$c; \
    done && mkdir -p /out/data
# Demo config, pre-staged with its final directory/file permissions
# here (where a real shell exists) rather than via COPY --chmod in the
# distroless "demo" stage below: some buildkit versions apply --chmod
# to the directory COPY auto-creates too, leaving it non-traversable
# (0600 has no execute bit) even for its own owner.
RUN mkdir -p /out/etc/expiry-radar && \
    cp deploy/demo/collector.json /out/etc/expiry-radar/collector.json && \
    cp deploy/demo/agent.json /out/etc/expiry-radar/agent.json && \
    chmod 0755 /out/etc/expiry-radar && \
    chmod 0600 /out/etc/expiry-radar/collector.json /out/etc/expiry-radar/agent.json

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

# Demo image for docker-compose.demo.yml only: never used in a real
# deployment, and a single container (unlike a real deployment, which
# always runs collector and agent separately): demoinit (see
# cmd/demoinit), itself a static Go binary with no shell dependency,
# sets up the admin account, seeds example data, starts a real Agent
# as a background process to live-check a handful of real public
# domains' TLS certificates (deploy/demo/agent.json, pushed over
# localhost to the collector below, exactly as a real agent would push
# to a real collector), and finally execs into the real collector
# binary, becoming its PID 1.
#
# Both collector.json and agent.json are baked into the image (COPY,
# not a host bind mount) so configperm.Check's "not group/other
# readable" rule is satisfied with real, buildkit-set Unix permissions
# on every host OS. A bind mount of these files from a Windows host
# would show up inside the container as mode 0777 (Windows has no
# POSIX permission bits), which configperm.Check correctly refuses to
# run with — they only hold fixed, non-secret config for this demo
# anyway, so there's nothing an operator needs to edit here.
FROM gcr.io/distroless/static-debian12:nonroot AS demo
COPY --from=build /out/collector /usr/local/bin/collector
COPY --from=build /out/agent /usr/local/bin/agent
COPY --from=build /out/demoinit /usr/local/bin/demoinit
COPY --from=build /out/demoseed /usr/local/bin/demoseed
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=65532:65532 /out/etc /etc
USER nonroot:nonroot
EXPOSE 8443
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/demoinit"]
CMD ["/etc/expiry-radar/collector.json"]

# Thin optional wrapper around the single static binary. Docker is no longer the
# primary run model (that was the v1 compose stack this rewrite retires) — it is
# just a convenient way to run the one binary in a container.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO-free build (pure-Go SQLite) → a fully static binary.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/nubicustos ./cmd/nubicustos

# Distroless static base: no shell, no package manager, minimal attack surface.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/nubicustos /usr/local/bin/nubicustos
# The nonroot user's home is writable; default the working dir there so the
# default SQLite results DB (relative "nubicustos.db") can be created without an
# explicit --db or a mounted volume.
WORKDIR /home/nonroot
ENTRYPOINT ["/usr/local/bin/nubicustos"]
CMD ["--help"]

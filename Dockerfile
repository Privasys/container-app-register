# The Privasys register: a schema-driven, tamper-evident register of
# records, built as a reproducible single-binary image.
#
# Nothing is fetched at runtime and nothing is generated at first boot
# except key material on the sealed volume, so the image the platform
# measures is the whole of what runs. The build is single-arch and
# provenance-free on purpose: an OCI attestation index would change the
# manifest digest the enclave pins at OID 1.3.6.1.4.1.65230.3.2.

FROM golang:1.24-alpine AS builder

WORKDIR /src

# Dependencies first, so a source-only change does not refetch them.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/register ./cmd/register \
 && CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/register-verify ./cmd/register-verify

# The register talks outward only to the identity provider's published
# key set, over HTTPS, so it needs a trust store and nothing else.
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /out/register /usr/local/bin/register
# The customer-side verifier ships in the image as well, so an operator
# can hand someone a binary that checks the register's evidence without
# trusting the register.
COPY --from=builder /out/register-verify /usr/local/bin/register-verify

# The app manifest. CI also embeds it as the org.privasys.manifest OCI
# label; the file serves GET /privasys.json for runtime introspection.
COPY privasys.json /privasys.json

# Schema packs baked into the image. A configure call may name one with
# `pack_ref`, or deliver its own inline.
COPY packs /packs

# No fixed port and no EXPOSE: the platform runs containers on the host
# network and injects a unique $PORT per app, which the register binds.
# A hard-coded port would collide with a co-located app and fail the
# readiness probe.
ENTRYPOINT ["/usr/local/bin/register"]

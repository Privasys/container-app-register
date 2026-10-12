# The Privasys register: a schema-driven, tamper-evident register of
# records, built as a reproducible single-binary image.
#
# Nothing is fetched at runtime and nothing is generated at first boot
# except key material on the sealed volume, so the image the platform
# measures is the whole of what runs. The build is single-arch and
# provenance-free on purpose: an OCI attestation index would change the
# manifest digest the enclave pins at OID 1.3.6.1.4.1.65230.3.2.

# The console is built first and copied in as static files: it is part of
# the measured image, so the page a person runs is code a verifier can
# read, and no unattested web server ever gets to serve it.
FROM node:22-alpine AS ui
WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY ui ./
RUN npm run build

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

# The console.
COPY --from=ui /src/ui/dist /web

# Everything stays behind the configure gate until the attested configure
# call succeeds.
LABEL org.privasys.config_api="POST /configure"
# The browser shell (public, measured code, no data) loads in the clear so
# a sealed session can be established; "/" covers the root document only,
# and /api is always sealed whatever is declared here. The label is
# measured, so a verifier reads off the image exactly which paths this
# register answers without a sealed session.
LABEL org.privasys.static-unsealed-prefixes="/,/app-config.js,/assets/,/vendor/,/brand/,/favicon.svg,/openapi.yaml"
LABEL org.opencontainers.image.source="https://github.com/Privasys/container-app-register"
LABEL org.opencontainers.image.title="Privasys Register"
LABEL org.opencontainers.image.description="A schema-driven, tamper-evident register of records"

# No fixed port and no EXPOSE: the platform runs containers on the host
# network and injects a unique $PORT per app, which the register binds.
# A hard-coded port would collide with a co-located app and fail the
# readiness probe.
ENTRYPOINT ["/usr/local/bin/register"]

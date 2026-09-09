# Demo fleet host: a deliberately outdated Ubuntu image with the real
# Ubuntu Pro client and the exporter built from this checkout. BASE_IMAGE
# should be a dated Ubuntu tag (e.g. ubuntu:jammy-20230308) so the
# installed packages genuinely lag the archive, giving the exporter real
# pending updates and CVEs to report.
#
# Build context is the repository root:
#   docker build -f examples/demo/Dockerfile .

ARG BASE_IMAGE=ubuntu:jammy-20230308

FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /ubuntu-pro-updates-exporter .

FROM ${BASE_IMAGE}
ARG EXTRA_PACKAGES=""
ENV DEBIAN_FRONTEND=noninteractive

# Refresh apt lists and install the pro client (plus a package mix that
# makes the host look like it has a job), but never apt-get upgrade: the
# point is to keep the base image's stale packages stale. The lists are
# kept so `pro api` can compute pending updates.
RUN apt-get update -q && \
    apt-get install -y --no-install-recommends \
        ubuntu-advantage-tools ca-certificates ${EXTRA_PACKAGES}

# The package-manifest endpoint shells out to `snap list`; containers have
# no snapd, so stub it as "no snaps" or the installed-packages log (and its
# dashboard table) stays empty in the demo.
RUN printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/snap && chmod +x /usr/local/bin/snap

COPY --from=build /ubuntu-pro-updates-exporter /usr/local/bin/ubuntu-pro-updates-exporter
COPY examples/demo/entrypoint.sh /usr/local/bin/demo-entrypoint

EXPOSE 10052
ENTRYPOINT ["/usr/local/bin/demo-entrypoint"]

# Image for the local 3-node cluster harness (dev/cluster/harness.sh).
#
# dqlite is not packaged at a usable version for Ubuntu 24.04 (libdqlite-dev is
# 1.16.0, which predates symbols go-dqlite v3 needs), so it is built from source
# here. The same image both compiles Notary and runs it, so the runtime always
# has the shared libraries the binary was linked against.
FROM ubuntu:24.04

ARG DQLITE_VERSION=v1.17.0
ARG GO_VERSION=1.26.2

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libuv1-dev \
    liblz4-dev \
    libsqlite3-dev \
    ca-certificates \
    curl \
    git \
    jq \
    openssl \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "${DQLITE_VERSION}" https://github.com/canonical/dqlite.git /tmp/dqlite \
    && cd /tmp/dqlite \
    && autoreconf -i \
    && ./configure --prefix=/usr/local --enable-build-raft \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig \
    && rm -rf /tmp/dqlite

RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-$(dpkg --print-architecture).tar.gz" \
    -o /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz

ENV PATH=/usr/local/go/bin:/usr/local/bin:$PATH
ENV GOTOOLCHAIN=local
ENV GOFLAGS=-buildvcs=false

WORKDIR /src

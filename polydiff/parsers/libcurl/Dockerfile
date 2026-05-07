# Pinned for reproducibility against devcontainer/ Clang 18 + libcurl line.
# Two-stage: build with clang and libcurl-dev; run from a slim image with
# only libcurl4 in the runtime.

FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang-18 \
        libcurl4-openssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/parser
COPY wrapper.c /opt/parser/wrapper.c
RUN clang-18 -O2 -Wall -Wextra -o wrapper wrapper.c -lcurl

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        libcurl4 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system parser && useradd --system --gid parser --uid 10001 parser
USER 10001:10001
WORKDIR /opt/parser
COPY --from=build --chown=10001:10001 /opt/parser/wrapper /opt/parser/wrapper
ENTRYPOINT ["/opt/parser/wrapper"]

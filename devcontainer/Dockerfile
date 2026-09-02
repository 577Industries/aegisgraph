# AegisGraph Tier 3 research devcontainer.
#
# Pins every required toolchain version so reprochain harness builds, polydiff
# parser builds, smabench corpora processing, and validator-export sanitize
# checks are deterministic across maintainer machines, CI runners, and (later)
# DARPA/ASEMA reviewer reproductions.
#
# Versions are pinned by intent:
#   * Python 3.11.9 — CPython, matches pyproject `requires-python = ">=3.11"`
#   * Clang 18 — needed for `-fsanitize=address,fuzzer` libFuzzer integration
#                in reprochain harness builds (libwebp differential).
#   * OpenJDK 21 (Temurin) — required by CodeQL Java packs and for SMA
#                            (Signal/Element-X Android) source extraction.
#   * Android SDK 34.0.0 build-tools + NDK r26d — Android SMA builds.
#   * CodeQL CLI 2.26.4 — pinned to match Java/Python query packs below.
#   * Semgrep 1.86.0 — installed via pipx in post-create.sh.
#   * Go 1.22.5 — polydiff Go parser corpus.
#   * Rust 1.79.0 — polydiff Rust parser corpus.
#   * Node 20 LTS — polydiff JS parser corpus + extraction adapters.
#   * Docker 24+ — supplied via `docker-outside-of-docker` devcontainer
#                  feature (declared in devcontainer.json, NOT here).
#   * MobSF — pulled at runtime by extract-deep target as
#             `opensecurity/mobile-security-framework-mobsf:latest`.
#             For reproducibility the digest is pinned in
#             extraction/mobsf/README.md (validator-export populates it).
#
# When bumping versions update BOTH this Dockerfile and the REQUIRED_TOOLS
# table in aegisgraph/tooling.py so `make tooling-strict` stays consistent.

FROM mcr.microsoft.com/devcontainers/python:1-3.11-bookworm

# Pin Debian-side noise.
ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# ---- Base build deps + JVM + LLVM/Clang 18 + Go + Node + Rust prereqs ------
# bullseye/bookworm doesn't ship clang-18 by default; we pull it from
# llvm.org's apt repo for reproducibility.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        gnupg \
        lsb-release \
        software-properties-common \
        unzip \
        wget \
        zip \
        git \
        make \
        pkg-config \
        libssl-dev \
        cmake \
        ninja-build \
        # LLVM/Clang 18 prerequisites
        # libFuzzer libraries ship under /usr/lib/llvm-18/
        # together with libclang_rt.fuzzer*.a and libclang_rt.asan*.so.
 && rm -rf /var/lib/apt/lists/*

# Clang 18 from LLVM apt repo (deterministic, matches their release artefacts).
RUN curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key \
        -o /usr/share/keyrings/llvm-archive-keyring.gpg.asc \
 && echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg.asc] http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-18 main" \
        > /etc/apt/sources.list.d/llvm.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        clang-18 \
        lld-18 \
        llvm-18 \
        libclang-18-dev \
        # libFuzzer + ASan runtimes ride along with compiler-rt below
        libfuzzer-18-dev \
        libclang-rt-18-dev \
 && update-alternatives --install /usr/bin/clang clang /usr/bin/clang-18 100 \
 && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-18 100 \
 && rm -rf /var/lib/apt/lists/*

# OpenJDK 21 (Temurin).
RUN mkdir -p /etc/apt/keyrings \
 && curl -fsSL https://packages.adoptium.net/artifactory/api/gpg/key/public \
        -o /etc/apt/keyrings/adoptium.asc \
 && echo "deb [signed-by=/etc/apt/keyrings/adoptium.asc] https://packages.adoptium.net/artifactory/deb bookworm main" \
        > /etc/apt/sources.list.d/adoptium.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends temurin-21-jdk \
 && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/temurin-21-jdk-amd64 \
    PATH=/usr/lib/jvm/temurin-21-jdk-amd64/bin:$PATH

# Go 1.22.5 (deterministic tarball, not apt — apt's go is too old/unstable).
ARG GO_VERSION=1.22.5
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
        -o /tmp/go.tgz \
 && tar -C /usr/local -xzf /tmp/go.tgz \
 && rm /tmp/go.tgz
ENV PATH=/usr/local/go/bin:$PATH

# Rust 1.79.0 via rustup (pinned).
ARG RUST_VERSION=1.79.0
RUN curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
        | sh -s -- -y --no-modify-path --default-toolchain ${RUST_VERSION} --profile minimal
ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:$PATH

# Node 20 LTS via NodeSource.
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/*

# CodeQL CLI 2.26.4 + Java/Python query packs.
ARG CODEQL_VERSION=2.26.4
ARG CODEQL_INSTALL=/opt/codeql
# CODEQL_SHA256 is the release-asset digest of codeql-linux64.zip for
# CODEQL_VERSION (gh api repos/github/codeql-cli-binaries/releases/tags/v<ver>
# → assets[].digest). Bump both together, and the bundle sha256 in
# .github/workflows/invariants-ground-truth.yml plus aegisgraph.tooling.REQUIRED_TOOLS.
ARG CODEQL_SHA256=d372d54345e058fe6f7ff8074acd155522fff6770b8d72ee1371ea89deafa193
RUN curl -fsSL "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip" \
        -o /tmp/codeql.zip \
 && echo "${CODEQL_SHA256}  /tmp/codeql.zip" | sha256sum -c - \
 && unzip -q /tmp/codeql.zip -d /opt \
 && rm /tmp/codeql.zip
ENV PATH=${CODEQL_INSTALL}/codeql:$PATH
# Pre-fetch Java + Python query packs so offline reruns work.
RUN /opt/codeql/codeql pack download codeql/java-queries codeql/python-queries || true

# Android SDK build-tools 34.0.0 + cmdline-tools `latest` + NDK r26d.
ARG ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_HOME=${ANDROID_SDK_ROOT} \
    ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT}
RUN mkdir -p ${ANDROID_SDK_ROOT}/cmdline-tools \
 && curl -fsSL https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip \
        -o /tmp/cmdline.zip \
 && unzip -q /tmp/cmdline.zip -d ${ANDROID_SDK_ROOT}/cmdline-tools \
 && mv ${ANDROID_SDK_ROOT}/cmdline-tools/cmdline-tools ${ANDROID_SDK_ROOT}/cmdline-tools/latest \
 && rm /tmp/cmdline.zip
ENV PATH=${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin:${ANDROID_SDK_ROOT}/platform-tools:$PATH
RUN yes | sdkmanager --licenses >/dev/null \
 && sdkmanager \
        "platform-tools" \
        "platforms;android-34" \
        "build-tools;34.0.0" \
        "ndk;26.3.11579264"

# pipx for tool installs (semgrep) — installs as the vscode user in post-create.
RUN python3 -m pip install --no-cache-dir pipx \
 && python3 -m pipx ensurepath || true

# Workdir + non-root user are inherited from the upstream devcontainer image.

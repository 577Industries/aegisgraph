# Baseline-tool delta runner image (Wave 9A / M14).
#
# Pins the toolchain used to produce a reproducible baseline-tool delta
# report (AegisGraph vs CodeQL alone vs Semgrep alone vs MobSF):
#
#   * CodeQL CLI 2.20.6  (matches devcontainer/Dockerfile and the
#                         InvariantCheck ground-truth workflow)
#   * Semgrep 1.86.0     (matches T-M4.1 self-hosted runner toolchain)
#   * Python 3.11        (matches the engineering devcontainer)
#
# MobSF runs in its own container (see extraction/mobsf/Dockerfile) so
# this image does NOT bake in MobSF — it only needs docker on the host
# to delegate to that container. The host's docker socket is mounted
# at runtime by the calling workflow.
#
# Build:
#   docker build -t aegisgraph/baseline-delta:wave9a \
#     -f aegisgraph/baseline_delta/Dockerfile .
#
# Run (from repo root, on the self-hosted runner only):
#   docker run --rm \
#     -v "$PWD:/repo" -w /repo \
#     -v /var/run/docker.sock:/var/run/docker.sock \
#     aegisgraph/baseline-delta:wave9a \
#     python3 -m aegisgraph.baseline_delta.runner \
#       --target signal --output 03_PROPOSAL/active-package/04_evidence/v0.4/baseline-tool-delta
#
# Security posture:
#   * Outbound network policy is enforced by the runner's network
#     namespace; MobSF runs with MOBSF_DISABLE_NETWORK_FEATURES=1.
#   * APK acquisition is not performed inside this image — APKs are
#     staged into the workspace by the caller (typically on the
#     self-hosted runner; anchor-only policy means anchors are pinned,
#     binaries are NOT redistributed in the engineering repo).

FROM python:3.11-slim-bookworm

ARG CODEQL_VERSION=2.20.6
ARG SEMGREP_VERSION=1.86.0

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Minimal system deps:
#   * curl, ca-certificates  - download the CodeQL bundle
#   * unzip                  - extract the CodeQL bundle
#   * git                    - the CodeQL CLI invokes git to gather
#                              database SHA metadata
#   * jq                     - SARIF post-processing in the workflow
#   * docker.io (cli only)   - delegate to the MobSF container at run
#                              time. The daemon comes from the host.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        jq \
        unzip \
        docker.io \
 && rm -rf /var/lib/apt/lists/*

# CodeQL CLI 2.20.6 — pin the bundle URL so a digest bump is explicit
# (CodeQL bundles do not currently publish digest tags publicly; pin
# the bundle version and rely on GitHub Actions' caching for digest
# stability across runs).
RUN curl -fsSL -o /tmp/codeql-bundle.tar.gz \
        "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz" \
 && mkdir -p /opt/codeql \
 && tar -xzf /tmp/codeql-bundle.tar.gz -C /opt/codeql --strip-components=1 \
 && rm /tmp/codeql-bundle.tar.gz
ENV PATH="/opt/codeql:${PATH}"

# Semgrep 1.86.0 pinned via pip.
RUN pip install --upgrade pip \
 && pip install "semgrep==${SEMGREP_VERSION}"

# Engineering package install: copy the repo at build time. Workflow
# expects the repo to be checked out before docker build runs.
WORKDIR /repo
COPY pyproject.toml /repo/pyproject.toml
COPY aegisgraph /repo/aegisgraph
COPY schema /repo/schema
COPY validator /repo/validator
COPY extraction /repo/extraction
COPY tests /repo/tests
RUN pip install -e /repo

# Verify the pinned versions at build time so a bad bundle URL fails
# the build instead of producing a silently-wrong image.
RUN codeql version --format=text \
 && semgrep --version

# Non-root user: per CWE-250 (Execution with Unnecessary Privileges),
# the container must not run as root. Workflow callers that need to
# write into mounted `/repo` paths should ensure the host directories
# are owned by uid 1000 (which is the case for GitHub Actions
# self-hosted runners under our T-M4.1 provisioning).
RUN groupadd --system --gid 1000 baseline \
 && useradd  --system --uid 1000 --gid 1000 --create-home --shell /bin/bash baseline \
 && chown -R baseline:baseline /repo
USER baseline

# Default command: print versions; the workflow overrides this with
# the actual runner invocation.
CMD ["bash", "-lc", "codeql version --format=text && semgrep --version"]

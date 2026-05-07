# Pinned for reproducibility against devcontainer/ Python 3.11 line.
# The wrapper itself uses only the stdlib so this image is intentionally
# minimal.
FROM python:3.11.10-slim

# Run as non-root to satisfy supply-chain hardening rules and to bound the
# blast radius of any wrapper crash. The orchestrator never needs root
# inside the parser sandbox.
RUN groupadd --system parser && useradd --system --gid parser --uid 10001 parser
USER 10001:10001

WORKDIR /opt/parser
COPY --chown=10001:10001 wrapper.py /opt/parser/wrapper.py

ENTRYPOINT ["python3", "/opt/parser/wrapper.py"]

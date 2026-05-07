# Pinned for reproducibility against devcontainer/ Python 3.11 line.
# Adds the `whatwg-url` package on top of the slim Python image.
FROM python:3.11.10-slim

# Install the whatwg-url package. Pinning to a date-stamped release for
# reproducibility; the package is small (pure Python) so the image stays
# minimal.
RUN pip install --no-cache-dir 'whatwg-url==2024.6.0'

RUN groupadd --system parser && useradd --system --gid parser --uid 10001 parser
USER 10001:10001

WORKDIR /opt/parser
COPY --chown=10001:10001 wrapper.py /opt/parser/wrapper.py

ENTRYPOINT ["python3", "/opt/parser/wrapper.py"]

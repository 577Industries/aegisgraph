"""HarnessGen runners: docker wrapper + coverage collector.

These are the seams between the Python scaffold and the actual fuzz
execution that happens in a docker container on a self-hosted runner. At
M3.1 only the wrappers ship; live invocation is deferred and explicitly
NOT exercised in CI tests (all subprocess calls are mocked).
"""

from __future__ import annotations

"""PolyDiff image-family tests (T-M2.1).

The image family covers libwebp / libavif / libheif (native) + glide_bitmap
/ coil_decoder (JVM). Wrappers are subprocess-runnable when binaries are
present; when absent, they emit a `_crash_envelope`-equivalent shape with
`binary_missing` flag set. Tests use mocked subprocess output so they run
green without binaries installed.
"""

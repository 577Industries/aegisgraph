"""HarnessGen top-level orchestrator + CLI entry.

This module wires the extractor / template / runner / corpus pieces into:

  * `build_crash_record()` — builds an AG-CRASH-* record matching
    schema/crash.schema.json. Hash-only: the actual bytes are NEVER
    serialized into the record. The crash_sha256 + stack_trace_hash + size
    are enough for downstream triage; the bytes themselves live in
    reprochain/corpora-private/.
  * `generate_harness_for_path()` — at M3.1 wired only for path_id="libwebp"
    (the canonical first target). Generalizing to graph-driven path lookup
    is a later milestone; here we vendor a small built-in mapping.
  * `main()` / `build_parser()` — CLI entry with `--help` and the stub
    `generate-harness <path>` subcommand. `run` is deferred.

The crash-record builder is deliberately conservative:

  * crash_class is normalized to top-level category only (strips line
    numbers and source paths).
  * stack_trace_hash is the SHA-256 of a canonicalized form of the trace
    text; the raw text is NEVER stored.
  * minimized_input_size_bytes is just len(bytes).
  * novelty defaults to "unknown" — the oracle that resolves it
    (known-bugs/INDEX.json lookup) is downstream of this builder.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

from aegisgraph.constants import STATIC_GENERATED_AT
from aegisgraph.hashchain import attach_hash_chain
from aegisgraph.io import sha256_bytes, sha256_text, write_json, write_text

from .extractors.jvm_entrypoint import (
    JvmEntryPoint,
    JvmEntryPointNotFoundError,
    JvmParam,
    extract_from_source_text,
)
from .extractors.native_entrypoint import (
    EntryPoint,
    Param,
    extract_from_header_text,
)
from .templates import (
    render_jazzer_jvm,
    render_jvm_gradle,
    render_libfuzzer_native,
    render_native_makefile,
)


# ---------------------------------------------------------------------------
# Crash record builder
# ---------------------------------------------------------------------------

# Top-level sanitizer/exception categories we recognize. The list is
# intentionally small and easy to extend; anything else is normalized by
# stripping the line/path noise rather than enumerated.
_KNOWN_TOP_LEVEL_CATEGORIES = {
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "use-after-free",
    "global-buffer-overflow",
    "heap-use-after-free",
    "double-free",
    "memcpy-param-overlap",
    "negative-size-param",
    "alloc-dealloc-mismatch",
    "SIGSEGV",
    "SIGBUS",
    "SIGABRT",
    "ArrayIndexOutOfBoundsException",
    "NullPointerException",
    "StringIndexOutOfBoundsException",
    "IllegalArgumentException",
    "OutOfMemoryError",
    "StackOverflowError",
}


def _normalize_crash_class(raw: str) -> str:
    """Reduce `raw` to a top-level category string.

    The schema's crash_class description forbids line numbers and source
    paths. We strip both by stripping anything past the first ':' or '('
    and anything past the first '/'.
    """
    # First try exact match — fast path.
    candidate = raw.strip()
    for known in _KNOWN_TOP_LEVEL_CATEGORIES:
        if known in candidate:
            return known
    # Fallback: strip path/line markers.
    for sep in (":", "(", "/"):
        if sep in candidate:
            candidate = candidate.split(sep, 1)[0].strip()
    # Strip trailing digits (line numbers stuck to a token).
    candidate = re.sub(r"\d+$", "", candidate).strip()
    return candidate or "unknown"


def _canonicalize_stack_trace(text: str) -> str:
    """Canonicalize a stack trace before hashing.

    Drops addresses, normalizes whitespace, keeps frame names. This makes
    `stack_trace_hash` stable across runs (addresses vary) while still
    discriminating between different bug shapes.
    """
    canonical = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", text)
    canonical = re.sub(r"\s+", " ", canonical).strip()
    return canonical


def _short_crash_id_suffix(crash_sha256: str, harness_id: str) -> str:
    """Compose a stable, schema-valid AG-CRASH suffix.

    Schema requires `^AG-CRASH-[A-Z0-9-]+$` — uppercase alphanumeric +
    dashes only. We use the first 12 hex chars of crash_sha256
    (uppercased) prefixed by a sanitized harness_id token.
    """
    safe_harness = re.sub(r"[^A-Za-z0-9]+", "", harness_id).upper()[:16] or "HARNESS"
    digest_prefix = crash_sha256[:12].upper()
    return f"{safe_harness}-{digest_prefix}"


def build_crash_record(
    harness_id: str,
    crash_bytes: bytes,
    stack_trace_text: str,
    crash_class: str,
    discovery_engine: str = "harnessgen",
    path_id: str | None = None,
    discovery_run_id: str | None = None,
    asan_summary: str | None = None,
) -> dict[str, Any]:
    """Build an AG-CRASH-* record matching schema/crash.schema.json.

    NO raw bytes anywhere. The bytes are hashed, their length is recorded,
    and they are then discarded. The caller stores the actual bytes (if
    needed at all) under reprochain/corpora-private/<crash_sha256>.
    """
    crash_sha = sha256_bytes(crash_bytes)
    trace_canonical = _canonicalize_stack_trace(stack_trace_text)
    trace_sha = sha256_text(trace_canonical)
    record: dict[str, Any] = {
        "crash_id": f"AG-CRASH-{_short_crash_id_suffix(crash_sha, harness_id)}",
        "version": "v1.0",
        "discovery_engine": discovery_engine,
        "harness_id": harness_id,
        "path_id": path_id,
        "discovery_run_id": discovery_run_id,
        "crash_sha256": crash_sha,
        "stack_trace_hash": trace_sha,
        "crash_class": _normalize_crash_class(crash_class),
        "minimized_input_size_bytes": int(len(crash_bytes)),
        "novelty": "unknown",
        "novelty_evidence": None,
        "triage_class": None,
        "asan_summary": asan_summary,
        "confirmed_in_emulator": None,
        "provenance": {
            "generated_by": "aegisgraph.harnessgen",
            "generated_at": STATIC_GENERATED_AT,
            "source": f"harness:{harness_id}",
            "private_by_default": True,
        },
    }
    return attach_hash_chain(record)


# ---------------------------------------------------------------------------
# Built-in path -> harness spec mapping (M3.1)
# ---------------------------------------------------------------------------

# At M3.1 only `libwebp` is wired. The graph-driven lookup is a later
# milestone; for now the spec lives here as a vendored dict so the CLI
# stub can produce a real artifact.

_LIBWEBP_HEADER_TEXT = """\
// extracted from webp/decode.h (BSD-3-Clause, libwebm/webp project)
#ifndef WEBP_WEBP_DECODE_H_
#define WEBP_WEBP_DECODE_H_

#include <stddef.h>

WEBP_EXTERN uint8_t* WebPDecodeRGB(const uint8_t* data, size_t data_size,
                                   int* width, int* height);

WEBP_EXTERN void WebPFree(void* ptr);

#endif
"""


# Synthetic excerpt of Signal Android LinkPreviewUtil.java for the M5.1 JVM
# extractor smoke. The real Signal source is GPL-3.0 — we re-derive only the
# public method signature, not the implementation, so the extractor can be
# exercised offline without pulling the Signal tree.
_SIGNAL_LINK_PREVIEW_SOURCE = """\
// derived signature from Signal Android LinkPreviewUtil.java (GPL-3.0)
package org.thoughtcrime.securesms.linkpreview;

import java.util.List;

public class LinkPreviewUtil {
    public static List<Link> findValidPreviewUrls(String text) {
        // implementation omitted; aegisgraph extracts only the signature.
        return null;
    }

    public static class Link { }
}
"""


_PATH_SPECS = {
    "libwebp": {
        "engine": "native",
        "harness_id": "WebPDecodeRGB",
        "entry_function": "WebPDecodeRGB",
        "free_function": "WebPFree",
        "header": "webp/decode.h",
        "header_text": _LIBWEBP_HEADER_TEXT,
        "out_dims": ["w", "h"],
        "link_libs": ["webp"],
        "header_include_dirs": ["/usr/include/webp"],
        "compiler": "clang++",
        "sanitizers": ["address", "undefined"],
    },
    "signal_linkpreview": {
        "engine": "jvm",
        "harness_id": "LinkPreviewUtilFuzzer",
        "fuzzer_class_name": "LinkPreviewUtilFuzzer",
        "package": "org.aegisgraph.fuzz",
        "target_class": "org.thoughtcrime.securesms.linkpreview.LinkPreviewUtil",
        "target_class_simple": "LinkPreviewUtil",
        "entry_method": "findValidPreviewUrls",
        "source_text": _SIGNAL_LINK_PREVIEW_SOURCE,
        "source_path": "LinkPreviewUtil.java",
        # `target_call` mirrors Asemarefactor.md line 180 verbatim.
        "target_call": (
            "LinkPreviewUtil.findValidPreviewUrls(input)"
        ),
        "expected_exceptions": [
            "IllegalArgumentException",
            "StringIndexOutOfBoundsException",
        ],
        # Gradle stub: parser module only (no full Signal Android app).
        "target_module": "org.thoughtcrime.securesms:link-preview-parser",
        "target_module_version": "PLACEHOLDER",
        "jazzer_version": "0.22.1",
        "java_version": "17",
        "fuzzer_engine": "jazzer",
        "sanitizers": [],
    },
}


def _spec_for_path(path_id: str) -> dict[str, Any]:
    if path_id not in _PATH_SPECS:
        known = ", ".join(sorted(_PATH_SPECS))
        raise KeyError(
            f"path_id {path_id!r} is not wired at M3.1; known: {known}. "
            "Graph-driven path lookup is a later milestone."
        )
    return _PATH_SPECS[path_id]


def _context_for_entry(entry: EntryPoint, spec: dict[str, Any]) -> dict[str, Any]:
    """Compose the template render context from a parsed entry signature."""
    # Identify the data-pointer and size params from the signature. The
    # data pointer is the first `const uint8_t*` (or `uint8_t*`) param;
    # the size is the first integral param after it.
    data_param = ""
    size_param = ""
    for param in entry.params:
        type_no_space = param.type.replace(" ", "")
        if not data_param and "uint8_t*" in type_no_space:
            data_param = param.name
            continue
        if data_param and not size_param and ("size_t" in type_no_space or "int" in type_no_space):
            # Skip pointer params — those are output dims, not size.
            if "*" not in param.type:
                size_param = param.name
                continue
    return {
        "harness_id": spec["harness_id"],
        "header": spec["header"],
        "entry_function": spec["entry_function"],
        "free_function": spec["free_function"],
        "entry_return_type": entry.return_type,
        "entry_data_param": data_param or "data",
        "entry_size_param": size_param or "size",
        "out_dims": spec["out_dims"],
    }


def _generate_native_harness(
    path_id: str,
    spec: dict[str, Any],
    output_dir: Path,
) -> dict[str, Any]:
    """Native-engine flow: extract C/C++ header signature, render
    libfuzzer template + Makefile, emit hash-only manifest."""
    entry = extract_from_header_text(
        header_text=spec["header_text"],
        function_name=spec["entry_function"],
        header_path=spec["header"],
    )
    context = _context_for_entry(entry, spec)
    harness_source = render_libfuzzer_native(context)
    source_filename = f"{spec['harness_id']}.harness.cc"
    write_text(output_dir / source_filename, harness_source)

    makefile_context = {
        "harness_id": spec["harness_id"],
        "harness_source": source_filename,
        "harness_binary": f"{spec['harness_id']}_fuzzer",
        "header_include_dirs": spec["header_include_dirs"],
        "link_libs": spec["link_libs"],
        "compiler": spec["compiler"],
    }
    makefile_text = render_native_makefile(makefile_context)
    write_text(output_dir / "Makefile", makefile_text)

    manifest = {
        "harness_id": spec["harness_id"],
        "path_id": path_id,
        "entry_function": spec["entry_function"],
        "header": spec["header"],
        "harness_source_filename": source_filename,
        "harness_source_sha256": sha256_text(harness_source),
        "makefile_sha256": sha256_text(makefile_text),
        "sanitizers": spec["sanitizers"],
        "fuzzer_engine": "libfuzzer",
        "generated_by": "aegisgraph.harnessgen",
        "generated_at": STATIC_GENERATED_AT,
        "private_by_default": True,
        "notes": (
            "Hash-only manifest. Live fuzz runs happen on the self-hosted "
            "runner; this manifest does not embed crash bytes or stack traces."
        ),
    }
    write_json(output_dir / "manifest.json", manifest)
    return manifest


def _generate_jvm_harness(
    path_id: str,
    spec: dict[str, Any],
    output_dir: Path,
) -> dict[str, Any]:
    """JVM-engine flow: extract Java/Kotlin method signature, render
    Jazzer template + Gradle stub, emit hash-only manifest.

    The extracted signature is used only for sanity validation at M5.1 —
    the rendered call expression comes from the spec's `target_call`
    (kept in sync with the Asemarefactor.md canonical shape). At M5.1.b
    the extractor will drive the call composition end-to-end.
    """
    # Validate the target method exists in the supplied source text. If
    # the extractor can't find it, fail closed -- we'd otherwise render
    # a harness that doesn't compile against the target.
    extract_from_source_text(
        source_text=spec["source_text"],
        method_name=spec["entry_method"],
        source_path=spec["source_path"],
    )

    harness_context = {
        "harness_id": spec["harness_id"],
        "package": spec["package"],
        "target_import": spec["target_class"],
        "fuzzer_class_name": spec["fuzzer_class_name"],
        "target_call": spec["target_call"],
        "expected_exceptions": spec["expected_exceptions"],
    }
    harness_source = render_jazzer_jvm(harness_context)
    source_filename = f"{spec['fuzzer_class_name']}.java"
    write_text(output_dir / source_filename, harness_source)

    gradle_context = {
        "harness_id": spec["harness_id"],
        "target_module": spec["target_module"],
        "target_module_version": spec["target_module_version"],
        "jazzer_version": spec["jazzer_version"],
        "java_version": spec["java_version"],
        "fuzzer_main_class": f"{spec['package']}.{spec['fuzzer_class_name']}",
        "harness_source": source_filename,
    }
    gradle_text = render_jvm_gradle(gradle_context)
    write_text(output_dir / "build.gradle", gradle_text)

    manifest = {
        "harness_id": spec["harness_id"],
        "path_id": path_id,
        "entry_method": spec["entry_method"],
        "target_class": spec["target_class"],
        "package": spec["package"],
        "harness_source_filename": source_filename,
        "harness_source_sha256": sha256_text(harness_source),
        "build_gradle_sha256": sha256_text(gradle_text),
        "expected_exceptions": list(spec["expected_exceptions"]),
        "sanitizers": list(spec.get("sanitizers", [])),
        "fuzzer_engine": spec["fuzzer_engine"],
        "jazzer_version": spec["jazzer_version"],
        "java_version": spec["java_version"],
        "target_module": spec["target_module"],
        "target_module_version": spec["target_module_version"],
        "generated_by": "aegisgraph.harnessgen",
        "generated_at": STATIC_GENERATED_AT,
        "private_by_default": True,
        "notes": (
            "Hash-only manifest. Live Jazzer runs happen on the self-hosted "
            "runner; this manifest does not embed crash bytes or stack traces. "
            "Dependency versions are PLACEHOLDERs awaiting M5.1.b pinning."
        ),
    }
    write_json(output_dir / "manifest.json", manifest)
    return manifest


def generate_harness_for_path(
    path_id: str,
    output_dir: Path,
) -> dict[str, Any]:
    """Generate the harness artifacts for `path_id` into `output_dir`.

    Dispatch by engine:
      native -> libFuzzer C++ entrypoint + Makefile + manifest
      jvm    -> Jazzer Java entrypoint + build.gradle + manifest

    Returns the manifest dict.
    """
    spec = _spec_for_path(path_id)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    engine = spec.get("engine", "native")
    if engine == "native":
        return _generate_native_harness(path_id, spec, output_dir)
    if engine == "jvm":
        return _generate_jvm_harness(path_id, spec, output_dir)
    raise ValueError(
        f"unknown engine {engine!r} for path_id {path_id!r}; "
        "expected one of: native, jvm"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def cmd_generate_harness(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir) if args.output_dir else None
    if output_dir is None:
        # Default to the conventional reprochain harness location.
        from aegisgraph.io import repo_root

        output_dir = repo_root() / "reprochain" / "harness" / args.path_id
    manifest = generate_harness_for_path(args.path_id, output_dir=output_dir)
    print(f"harness generated: {manifest['harness_id']} -> {output_dir}")
    return 0


def cmd_run(_args: argparse.Namespace) -> int:
    """Stub for the `run` subcommand. Live fuzz runs are deferred to
    `make harnessgen-native PATH_ID=...` on the self-hosted runner."""
    print(
        "harnessgen run: deferred to self-hosted runner "
        "(make harnessgen-native PATH_ID=<path>)"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="harnessgen",
        description=(
            "AegisGraph HarnessGen (Engine 2): graph-driven fuzz harness "
            "generation. M3.1 wired libwebp/WebPDecodeRGB (native); M5.1 "
            "adds signal_linkpreview/LinkPreviewUtilFuzzer (JVM/Jazzer). "
            "Live fuzz runs are deferred to the self-hosted runner."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=False)

    gen = sub.add_parser(
        "generate-harness", help="emit harness artifacts for a path_id"
    )
    gen.add_argument(
        "path_id",
        help="path identifier (M3.1: libwebp; M5.1: signal_linkpreview)",
    )
    gen.add_argument(
        "--output-dir",
        default=None,
        help=(
            "destination directory; defaults to "
            "reprochain/harness/<path_id>/"
        ),
    )
    gen.set_defaults(func=cmd_generate_harness)

    run_p = sub.add_parser("run", help="run a generated harness (deferred)")
    run_p.add_argument("--budget", default="60s", help="fuzz budget (ignored at M3.1)")
    run_p.set_defaults(func=cmd_run)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover - script entry
    sys.exit(main())


__all__ = [
    "build_crash_record",
    "build_parser",
    "cmd_generate_harness",
    "cmd_run",
    "generate_harness_for_path",
    "main",
]

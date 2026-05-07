"""AndroidManifest.xml analyzer (pure Python, no external Android SDK).

Parses AndroidManifest.xml from a target source tree and emits a deterministic
JSON listing of:
  - exported components (Activities/Services/Receivers/Providers)
  - intent filters with scheme/host/path
  - declared permissions (uses-permission and custom <permission>)
  - declared native libraries (<uses-native-library>, <meta-data
    android:name="android.app.lib_name">, etc.)

Output is structured for consumption by
`extraction/adapters/manifest_to_graph.py`.

XXE safety: target source is *untrusted* (it's third-party code cloned into a
temp dir during build_db.sh). We use `lxml.etree` with an explicit
XMLParser configured to disable entity resolution, DTD loading, and network
access. The standard-library `xml.etree` does NOT enforce these by default
(see CWE-611) and `defusedxml` is not in our pinned dependency set, but
`lxml` is — see pyproject.toml dependencies.

Reproducibility: the analyzer is deterministic — given the same input bytes,
output JSON is byte-stable (sort_keys, no timestamps in the per-target
output; the timestamp lives in extraction/output/manifest.json owned by
aegisgraph/extraction.py).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from lxml import etree as ET  # XXE-safe with the configured parser below

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
TOOLS_NS = "{http://schemas.android.com/tools}"


def _safe_parser() -> ET.XMLParser:
    """XMLParser configured to refuse XXE / DTD / network features.

    `resolve_entities=False` disables external entity resolution.
    `no_network=True` blocks network fetches when an entity does slip through.
    `load_dtd=False` and `dtd_validation=False` keep DTDs out of the parse.
    `huge_tree=False` keeps lxml's parser memory bounds in effect.
    """
    return ET.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
        recover=False,
    )


def _strip_ns(tag: str) -> str:
    """Strip XML namespace prefix from a lxml tag for tag-name comparisons.

    AndroidManifest.xml uses default-namespaceless element tags (the
    'android' namespace lives only in attribute names), so most tags here are
    bare strings. We still strip defensively in case a manifest declares a
    custom default namespace.
    """
    if isinstance(tag, str) and tag.startswith("{") and "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _attr(el: ET._Element, name: str, ns: str = ANDROID_NS) -> str | None:
    """Return the namespaced attribute value or None."""
    value = el.get(f"{ns}{name}")
    if value is not None:
        return value
    return el.get(name)


def _bool_attr(el: ET._Element, name: str, default: bool | None = None) -> bool | None:
    raw = _attr(el, name)
    if raw is None:
        return default
    return raw.strip().lower() == "true"


@dataclass
class IntentFilterData:
    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    data: list[dict[str, str]] = field(default_factory=list)


@dataclass
class ComponentRecord:
    component_type: str  # activity|service|receiver|provider
    name: str
    exported: bool | None
    permission: str | None
    intent_filters: list[IntentFilterData] = field(default_factory=list)


@dataclass
class ManifestAnalysis:
    package: str | None
    application_name: str | None
    permissions_declared: list[dict[str, str]] = field(default_factory=list)
    permissions_used: list[str] = field(default_factory=list)
    native_libraries: list[dict[str, str]] = field(default_factory=list)
    components: list[ComponentRecord] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    manifest_path: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool_output_type": "manifest_analysis",
            "version": "v1.0",
            "manifest_path": self.manifest_path,
            "package": self.package,
            "application_name": self.application_name,
            "permissions_declared": sorted(self.permissions_declared, key=lambda p: p.get("name", "")),
            "permissions_used": sorted(self.permissions_used),
            "native_libraries": sorted(self.native_libraries, key=lambda n: n.get("name", "")),
            "components": [
                {
                    "component_type": c.component_type,
                    "name": c.name,
                    "exported": c.exported,
                    "permission": c.permission,
                    "intent_filters": [asdict(f) for f in c.intent_filters],
                }
                for c in sorted(self.components, key=lambda c: (c.component_type, c.name))
            ],
            "parse_errors": list(self.parse_errors),
        }


def _parse_intent_filter(el: ET._Element) -> IntentFilterData:
    f = IntentFilterData()
    for child in el:
        tag = _strip_ns(child.tag)
        if tag == "action":
            name = _attr(child, "name")
            if name:
                f.actions.append(name)
        elif tag == "category":
            name = _attr(child, "name")
            if name:
                f.categories.append(name)
        elif tag == "data":
            data_entry: dict[str, str] = {}
            for key in ("scheme", "host", "port", "path", "pathPrefix", "pathPattern", "mimeType", "ssp"):
                value = _attr(child, key)
                if value:
                    data_entry[key] = value
            if data_entry:
                f.data.append(data_entry)
    f.actions = sorted(set(f.actions))
    f.categories = sorted(set(f.categories))
    f.data = sorted(f.data, key=lambda d: tuple(sorted(d.items())))
    return f


_COMPONENT_TAG_MAP = {
    "activity": "activity",
    "activity-alias": "activity",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}


def _parse_component(el: ET._Element, ctype: str) -> ComponentRecord:
    name = _attr(el, "name") or "<anonymous>"
    exported = _bool_attr(el, "exported")
    permission = _attr(el, "permission")
    filters = [
        _parse_intent_filter(child)
        for child in el
        if _strip_ns(child.tag) == "intent-filter"
    ]
    # Heuristic: a component with an intent-filter is implicitly exported on
    # SDK<=30. We surface the explicit value and let the adapter assume
    # implicit-exported = True when filters are present.
    if exported is None and filters:
        exported = True
    return ComponentRecord(
        component_type=ctype,
        name=name,
        exported=exported,
        permission=permission,
        intent_filters=filters,
    )


def parse_manifest(path: Path) -> ManifestAnalysis:
    """Parse a single AndroidManifest.xml file with XXE protections."""
    analysis = ManifestAnalysis(package=None, application_name=None, manifest_path=str(path))
    parser = _safe_parser()
    try:
        tree = ET.parse(str(path), parser=parser)
    except ET.XMLSyntaxError as exc:
        analysis.parse_errors.append(f"xml parse error: {exc}")
        return analysis
    except OSError as exc:
        analysis.parse_errors.append(f"io error: {exc}")
        return analysis

    root = tree.getroot()
    if _strip_ns(root.tag) != "manifest":
        analysis.parse_errors.append(f"root tag is {root.tag!r}, expected 'manifest'")
        return analysis

    analysis.package = root.get("package")

    for child in root:
        tag = _strip_ns(child.tag)
        if tag == "uses-permission":
            name = _attr(child, "name")
            if name:
                analysis.permissions_used.append(name)
        elif tag == "permission":
            entry = {"name": _attr(child, "name") or ""}
            for key in ("protectionLevel", "label"):
                value = _attr(child, key)
                if value:
                    entry[key] = value
            if entry["name"]:
                analysis.permissions_declared.append(entry)
        elif tag == "uses-native-library":
            name = _attr(child, "name")
            required = _bool_attr(child, "required")
            if name:
                analysis.native_libraries.append(
                    {"name": name, "required": "true" if required else "false"}
                )
        elif tag == "application":
            analysis.application_name = _attr(child, "name")
            for grandchild in child:
                gtag = _strip_ns(grandchild.tag)
                ctype = _COMPONENT_TAG_MAP.get(gtag)
                if ctype:
                    analysis.components.append(_parse_component(grandchild, ctype))
                elif gtag == "meta-data":
                    name = _attr(grandchild, "name")
                    value = _attr(grandchild, "value")
                    if name and value and name == "android.app.lib_name":
                        analysis.native_libraries.append({"name": value, "required": "true"})

    # De-duplicate permissions_used
    analysis.permissions_used = sorted(set(analysis.permissions_used))
    return analysis


def find_manifest_files(source_root: Path) -> list[Path]:
    """Return all AndroidManifest.xml files under source_root, excluding
    build directories and test fixtures we don't want to score."""
    matches: list[Path] = []
    skip_dir_names = {"build", ".gradle", ".idea", "out", "node_modules", ".git", ".kotlin"}
    skip_path_substrings = ("/test/", "/androidTest/", "/sharedTest/", "/__test__/")
    for path in source_root.rglob("AndroidManifest.xml"):
        if any(part in skip_dir_names for part in path.parts):
            continue
        path_str = str(path).replace("\\", "/")
        if any(sub in path_str for sub in skip_path_substrings):
            continue
        matches.append(path)
    return sorted(matches)


def analyze_source_tree(source_root: Path) -> dict[str, Any]:
    """Analyze every AndroidManifest.xml under source_root.

    Returns a deterministic dict listing all manifests, with per-manifest
    component / permission / native-lib data.
    """
    manifests = find_manifest_files(source_root)
    analyses = [parse_manifest(m).as_dict() for m in manifests]
    # Sort by manifest_path so output is byte-stable across filesystem orders.
    analyses.sort(key=lambda a: str(a.get("manifest_path", "")))
    return {
        "tool_output_type": "manifest_analysis_set",
        "version": "v1.0",
        "source_root": str(source_root),
        "manifest_count": len(analyses),
        "analyses": analyses,
    }


def _summarize(result: dict[str, Any]) -> dict[str, Any]:
    """Compact summary used by adapters that don't need every component."""
    component_count = sum(
        len(a.get("components", [])) for a in result.get("analyses", [])
    )
    exported_with_filter = 0
    intent_filter_count = 0
    for a in result.get("analyses", []):
        for comp in a.get("components", []):
            ifs = comp.get("intent_filters", [])
            intent_filter_count += len(ifs)
            if comp.get("exported") and ifs:
                exported_with_filter += 1
    permissions_used: set[str] = set()
    permissions_declared: set[str] = set()
    native_libs: set[str] = set()
    for a in result.get("analyses", []):
        permissions_used.update(a.get("permissions_used", []))
        for d in a.get("permissions_declared", []):
            if d.get("name"):
                permissions_declared.add(d["name"])
        for n in a.get("native_libraries", []):
            if n.get("name"):
                native_libs.add(n["name"])
    return {
        "manifest_count": result.get("manifest_count", 0),
        "component_count": component_count,
        "exported_components_with_intent_filter": exported_with_filter,
        "intent_filter_count": intent_filter_count,
        "permissions_used_count": len(permissions_used),
        "permissions_declared_count": len(permissions_declared),
        "native_library_count": len(native_libs),
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="manifest_analyzer")
    parser.add_argument(
        "source_root",
        help="Path to a target source tree (one cloned by build_db.sh, NOT the AegisGraph repo).",
    )
    parser.add_argument(
        "--output",
        default="-",
        help="Output JSON path; default '-' = stdout.",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print a one-line summary instead of the full JSON.",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    src = Path(args.source_root).resolve()
    if not src.is_dir():
        print(f"manifest_analyzer: source root not found: {src}", file=sys.stderr)
        return 2

    result = analyze_source_tree(src)
    if args.summary:
        print(json.dumps(_summarize(result), sort_keys=True))
        return 0

    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output == "-":
        sys.stdout.write(payload)
    else:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(payload, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

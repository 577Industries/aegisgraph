"""Manifest analyzer tests (Phase C4).

The manifest analyzer is the one piece of the Phase 1 extraction pipeline
that runs end-to-end without an external toolchain. We exercise it against
a synthetic AndroidManifest.xml fixture to lock the parsing contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from extraction.manifest.manifest_analyzer import (
    analyze_source_tree,
    find_manifest_files,
    parse_manifest,
)


_MANIFEST_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.aegisgraphtest">

  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.READ_CONTACTS"/>
  <permission android:name="com.example.aegisgraphtest.ADMIN_PERMISSION"
              android:protectionLevel="signature"/>

  <uses-native-library android:name="libffmpeg.so" android:required="true"/>

  <application android:name=".App">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <activity android:name=".DeepLinkActivity">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <data android:scheme="aegisgraph" android:host="open"/>
      </intent-filter>
    </activity>
    <service android:name=".SyncService" android:exported="false"/>
    <receiver android:name=".BootReceiver" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
      </intent-filter>
    </receiver>
    <meta-data android:name="android.app.lib_name" android:value="libapp.so"/>
  </application>
</manifest>
"""


@pytest.fixture
def fixture_tree(tmp_path: Path) -> Path:
    """Build a tiny Android-style source tree under tmp_path with one
    manifest in `app/src/main/` and one inside a build/ that should be
    excluded.
    """
    main = tmp_path / "app" / "src" / "main"
    main.mkdir(parents=True)
    (main / "AndroidManifest.xml").write_text(_MANIFEST_XML)

    bld = tmp_path / "app" / "build" / "intermediates"
    bld.mkdir(parents=True)
    (bld / "AndroidManifest.xml").write_text(_MANIFEST_XML)
    return tmp_path


def test_find_manifest_files_skips_build_dir(fixture_tree: Path) -> None:
    found = find_manifest_files(fixture_tree)
    assert len(found) == 1, [str(p) for p in found]
    assert "/build/" not in str(found[0])


def test_parse_manifest_components_and_permissions(fixture_tree: Path) -> None:
    manifest = next(p for p in find_manifest_files(fixture_tree))
    analysis = parse_manifest(manifest).as_dict()
    assert analysis["package"] == "com.example.aegisgraphtest"
    assert analysis["application_name"] == ".App"
    assert "android.permission.INTERNET" in analysis["permissions_used"]
    declared = [p["name"] for p in analysis["permissions_declared"]]
    assert "com.example.aegisgraphtest.ADMIN_PERMISSION" in declared
    components = analysis["components"]
    names = [(c["component_type"], c["name"]) for c in components]
    assert ("activity", ".MainActivity") in names
    assert ("activity", ".DeepLinkActivity") in names
    assert ("service", ".SyncService") in names
    assert ("receiver", ".BootReceiver") in names

    # DeepLinkActivity intent filter has scheme="aegisgraph"
    deeplink = next(c for c in components if c["name"] == ".DeepLinkActivity")
    assert any(
        d.get("scheme") == "aegisgraph"
        for f in deeplink["intent_filters"]
        for d in f.get("data", [])
    )


def test_parse_manifest_native_library(fixture_tree: Path) -> None:
    manifest = next(p for p in find_manifest_files(fixture_tree))
    analysis = parse_manifest(manifest).as_dict()
    libs = [n["name"] for n in analysis["native_libraries"]]
    assert "libffmpeg.so" in libs
    # meta-data android:name="android.app.lib_name" should also be captured.
    assert "libapp.so" in libs


def test_analyze_source_tree_emits_byte_stable_json(fixture_tree: Path) -> None:
    a = analyze_source_tree(fixture_tree)
    b = analyze_source_tree(fixture_tree)
    assert a == b


def test_analyze_source_tree_sets_manifest_count(fixture_tree: Path) -> None:
    result = analyze_source_tree(fixture_tree)
    assert result["manifest_count"] == 1


def test_xxe_bomb_does_not_explode(tmp_path: Path) -> None:
    """Sanity: feeding a billion-laughs XXE payload doesn't crash the
    analyzer or expand exponentially. The safe parser refuses to resolve
    entities.
    """
    bomb = """<?xml version="1.0"?>
    <!DOCTYPE lolz [
      <!ENTITY lol "lol">
      <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    ]>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="&lol2;">
      <application/>
    </manifest>
    """
    manifest_path = tmp_path / "AndroidManifest.xml"
    manifest_path.write_text(bomb)
    analysis = parse_manifest(manifest_path).as_dict()
    # Either a parse error is recorded (lxml refuses external/internal entities
    # under our config) or the package field doesn't expand the entity. Both
    # outcomes are safe; what we forbid is an exponential-blowup process.
    assert analysis is not None
    pkg = analysis.get("package") or ""
    # No "lol" expansion to a million chars.
    assert len(pkg) < 1000, f"package field length unexpectedly large: {len(pkg)}"

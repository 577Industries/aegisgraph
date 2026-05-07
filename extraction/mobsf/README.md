# MobSF runner (Phase C3, offline)

Runs the [Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
against locally-acquired APKs and normalizes findings into AegisGraph
evidence via `extraction/adapters/mobsf_to_graph.py`.

## Pinned digest

The `Dockerfile` in this directory uses
`opensecurity/mobile-security-framework-mobsf:latest`. The exact digest
must be captured during devcontainer rebuild and recorded here:

```
# Capture digest with:
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker inspect --format='{{index .RepoDigests 0}}' opensecurity/mobile-security-framework-mobsf:latest

# Pinned digest (update after each rebuild and submission):
# opensecurity/mobile-security-framework-mobsf@sha256:OVERRIDE_AT_BUILD_TIME
```

A digest bump changes the static-analysis ruleset and therefore changes
the evidence record for both targets — coordinate with the integration
stream before bumping.

## APK acquisition asymmetry

| Target | Source | Network requirement |
|---|---|---|
| Signal-Android | Build APK from source via `gradlew :Signal-Android:assembleStagingRelease` (run inside `extraction/targets/signal-android/build_db.sh`'s clone dir, NOT committed) | None (local build) |
| Element-X-Android | F-Droid release APK download | F-Droid is **not** in the AegisGraph sandbox network allowlist; manual step required, see "F-Droid manual step" below |

We document this asymmetry honestly: Signal is built from the pinned
commit; Element-X is downloaded from F-Droid because that's the
distribution channel that ships the matching binary. The two artifacts
therefore have different provenance and that fact appears in the
evidence record's `provenance.source` field.

### F-Droid manual step (Element-X)

```
# On a machine with F-Droid network access:
curl -L -o /tmp/element-x.apk \
  "https://f-droid.org/repo/io.element.android.x_<VERSION>.apk"

# Verify against F-Droid index signature (out of scope here; see f-droid.org).

# Move into the AegisGraph workspace temp dir (do NOT commit).
mv /tmp/element-x.apk "${TMPDIR}/element-x-91d265e6.apk"
```

Then invoke:

```bash
python3 -m extraction.mobsf.run_mobsf element-x \
  --apk "${TMPDIR}/element-x-91d265e6.apk" \
  --output extraction/output/element-x/mobsf-results.json
```

## When MobSF cannot run

The runner emits `extraction/output/<target>/mobsf-results.json` with
`status="skipped"` and a `reason` enum
(`docker_unavailable`, `apk_missing`, `httpx_unavailable`,
`container_start_failed: <stderr>`, `mobsf_boot_timeout`,
`scan_failed: <error>`). It does **not** silently no-op.

The `extraction/adapters/mobsf_to_graph.py` adapter sees the skipped
record and records `tool_run_status="skipped"` with the same reason,
which surfaces in `coverage.json` per-target.

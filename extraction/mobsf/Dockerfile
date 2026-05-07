# MobSF runner image for AegisGraph Tier 3 extraction.
#
# Pin: opensecurity/mobile-security-framework-mobsf:latest, digest captured
# at devcontainer-rebuild time and recorded in extraction/mobsf/README.md
# (see "Pinned digest" section). Do not bump silently — a digest bump
# changes MobSF's static-analysis ruleset and therefore changes evidence.
#
# Network policy: MobSF is run with --env MOBSF_DISABLE_NETWORK_FEATURES=1
# at run time (see run_mobsf.py), and the container is started with --network
# none when the orchestrator requires fully-offline mode. The Dockerfile
# itself does NOT need to disable network access; that's enforced by the
# caller.
FROM opensecurity/mobile-security-framework-mobsf:latest

# Document the digest pin in the image label so `docker inspect` recovers it.
LABEL aegisgraph.mobsf.digest_pin="OVERRIDE_AT_BUILD_TIME"
LABEL aegisgraph.mobsf.notes="See extraction/mobsf/README.md for the digest captured during the AegisGraph devcontainer rebuild."

# MobSF expects /home/mobsf/.MobSF for state. We don't bake an APK in here —
# APK acquisition is run-time per target (see run_mobsf.py).
WORKDIR /home/mobsf

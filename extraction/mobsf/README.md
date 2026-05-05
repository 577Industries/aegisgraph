# MobSF Runner Placeholder

MobSF is optional in early CI because it needs APK or AAB artifacts and Docker orchestration. The initial policy is:

- Prefer Element X distributed APK analysis first if source-build APKs are not yet reliable.
- Treat Signal APK analysis as a separate decision gate.
- Normalize only derived findings, scores, and hashes. Do not export raw scanner dumps.

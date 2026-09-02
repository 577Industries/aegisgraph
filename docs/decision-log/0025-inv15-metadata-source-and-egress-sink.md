# 0025 — INV-15: metadata comes from a message object; the egress call is the one sink

Status: accepted (2026-09-02)

## Context

INV-15 (message metadata outside the encrypted envelope) planted two
violations in `MetadataLeakOutsideEnvelope.kt` and measured **0** under the
traced build (the only build that extracts Kotlin). Two independent causes:

1. **No source could bind.** The query's sources are metadata *getters*
   (`getRecipientId`, `getTimestamp`, …) or parameters typed
   `*MessageMetadata` / `*EnvelopeMetadata`. The fixture passed
   `recipientId: String` and `ts: Long` as bare parameters — nothing the
   model recognises as metadata, so the planted flows had no start.
2. **okhttp is opaque.** The request is assembled through
   `RequestBody.create(...)`, `Request.Builder().url(..).post(..).build()` and
   sent with `client.newCall(req)`. okhttp is a compiled dependency
   (`compileOnly 'com.squareup.okhttp3:okhttp:3.14.9'`), so CodeQL sees no
   method bodies and taint stops at the first builder call.

## Decision

Fixture (`MetadataLeakOutsideEnvelope.kt`): metadata is read from an
`OutgoingMessage` object — `msg.recipientId` (a Kotlin property read, which
the extractor represents as the getter call `getRecipientId()`),
`msg.timestamp` (`getTimestamp()`), `msg.body`. The three methods keep their
shape (body leak / query-string leak / sealed clean control); only where the
metadata comes from changes. 55 lines, under the 60-LoC budget.

Query (`15_metadata_leak_outside_envelope.ql`):

1. `okhttpRequestAssemblyStep`: `RequestBody.create(mediaType, content)` →
   body; `Request.Builder.url / post / put / patch / delete / method / header /
   addHeader / tag / build` → the builder (qualifier and argument both flow
   into the result); `Request.newBuilder()` → the builder.
2. The okhttp sink is **only** `OkHttpClient.newCall(request)` — the point
   where the request leaves the process. `Request.Builder.post(body)` and
   friends were sinks before; with the assembly steps in place they would
   have reported every leak twice (once at `.post`, once at `newCall`).
   Same principle as ADR 0022: the egress is the sink, assembly is a step.

## Consequences

- Measured locally (traced build: Gradle 9.7.1, Kotlin 2.4.0, android-34,
  Temurin 17, bundle 2.26.4): **2** results — line 27 (`client.newCall(req)`
  in `sendRecipientIdInClearMetadata`) and line 36 (in
  `sendTimestampInQueryString`). The clean control reports nothing:
  `sealer.wrap(msg.recipientId, msg.body)` is a `*SealedSender*` barrier on
  its arguments and result, so nothing tainted reaches the builder.
- Buildless cannot extract the Kotlin fixture at all; INV-15 stays a
  `kotlin-extraction` xfail there (unchanged). It leaves the **traced** table.
- `manifest.json` expected count (2) unchanged.

## Related

- 0022 — INV-10 (sink is the write); 0023 — INV-14; 0024 — INV-12 (same pass)
- `tests/fixtures/demo-vulnerable-app-traced/build.gradle` — why okhttp 3.14.9

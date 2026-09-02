# 0024 — INV-12: violation 3 carries attacker bytes; MediaCodec input path modelled

Status: accepted (2026-09-02)

## Context

INV-12 (media decode without dimension bound / sanitisation) planted three
violations in `MediaDecodeUnsanitized.java` and measured **1** under both
extraction modes (line 23, `BitmapFactory.decodeStream(in)`). The two misses:

- **Violation 2** `decodeWithGlide(byte[] bytes)`: the parameter-source rule
  required a decode-verb immediately followed by a media noun
  (`decodeImage`, `handleAttachment`, …). "decodeWithGlide" has a word in
  between and was never a source. A genuine model miss.
- **Violation 3** `decodeMediaCodec(MediaFormat format)`: the method carried
  **no attacker bytes at all** — a `MediaFormat` is codec configuration, and
  `MediaCodec.configure(format, …)` was not (and should not be) a decoder
  sink. The planted "violation" could not be a taint finding under any
  model; the fixture, not the query, was wrong.

## Decision

Query (`12_media_decode_unsanitized.ql`):

1. Parameter sources: a decode/handle/process/receive/on verb **anywhere
   before** a media noun (`attachment|media|image|video|thumbnail|bitmap|glide|coil|frame`),
   case-insensitive — `decodeWithGlide`, `handleInboundThumbnail`,
   `onAttachmentReceived` all qualify; `decodeSafe` does not.
2. MediaCodec sink: the bytes enter the decoder through `ByteBuffer.put(bytes)`
   on a buffer obtained from `MediaCodec.getInputBuffer(s)` (local flow from
   the getter to the `put` qualifier). The previous rule marked the integer
   arguments of `queueInputBuffer` / `getInputBuffer` as sinks, which no
   byte flow can reach.

Fixture (`MediaDecodeUnsanitized.java`, violation 3 only):

```java
// before
public void decodeMediaCodec(MediaFormat format) throws Exception {
    MediaCodec codec = MediaCodec.createDecoderByType("video/avc");
    codec.configure(format, null, null, 0);
}
// after
public void decodeMediaCodec(byte[] frame) throws Exception {
    MediaCodec codec = MediaCodec.createDecoderByType("video/avc");
    int index = codec.dequeueInputBuffer(10_000);
    ByteBuffer input = codec.getInputBuffer(index);
    input.put(frame);
    codec.queueInputBuffer(index, 0, frame.length, 0, 0);
}
```

The `MediaFormat` import goes, `java.nio.ByteBuffer` comes in; the file stays
under the 60-LoC budget (55 lines).

## Consequences

- Measured locally (buildless, bundle 2.26.4): **2** results — lines 24 and
  31 (violations 1 and 2). Violation 3 does **not** bind under buildless for
  an extraction reason, not a model one: the buildless extractor emits no
  call node for `codec.getInputBuffer(index)` (only the `codec` and `index`
  reads survive at that line; `dequeueInputBuffer`, `put` and
  `queueInputBuffer` on the neighbouring lines are all extracted). With
  `android.jar` on the classpath (the traced job) the call resolves.
  `INV-12` therefore stays in the **buildless** xfail table as
  `(2, extraction …)` and leaves the **traced** table; the PR's CI run is the
  traced measurement.
- Removing the integer-argument MediaCodec sinks removes nothing real: no
  byte flow ever reached them.
- `manifest.json` expected count (3) unchanged; violations 1 and 2 untouched.

## Related

- 0022 — INV-10 sink semantics; 0023 — INV-14 restore source (same pass)
- `tests/fixtures/demo-vulnerable-app-traced/` — the overlay that makes the
  traced measurement possible

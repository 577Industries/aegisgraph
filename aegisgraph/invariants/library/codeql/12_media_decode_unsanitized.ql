/**
 * @id aegisgraph/inv-12-media-decode-unsanitized
 * @name InvariantCheck INV-12: Media decode without dimension-bound or sanitization (STUB — M7 deliverable)
 * @description Incoming media (images, video, audio thumbnails) must not
 *              be decoded via BitmapFactory.decodeStream /
 *              android.media.MediaCodec / Glide / Coil without an
 *              intervening dimension-bound check (width × height ×
 *              bytes-per-pixel against an explicit upper limit) or a
 *              first-pixel sanitization gate. This is the
 *              libwebp / libavif / libheif memory-corruption-via-image
 *              class (CVE-2023-4863, CVE-2023-5217, the libwebp WebPMux
 *              integer-overflow lineage).
 *
 *              This invariant complements the PolyDiff image family
 *              (libwebp / libavif / libheif / glide / coil parser axes)
 *              by checking whether the host SMA implements its own
 *              upstream defenses against the parser bugs the witnesses
 *              chase.
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id-mapping INV-12
 * @tags security
 *       external-input
 *       media-decode
 *       native-boundary
 *       aegisgraph-invariantcheck
 *       mastg-platform-11
 *       ssdf-pw-7-1
 *       stub
 */

/*
 * ─────────────────────────────────────────────────────────────────────
 * STUB QUERY — NOT YET FULLY ENCODED (M7 deliverable)
 * ─────────────────────────────────────────────────────────────────────
 *
 * This file is committed so the M5.3 manifest entry for INV-12 resolves
 * to a real file on disk. The full encoding is scheduled for M7
 * alongside the PolyDiff image-family ground-truth pass.
 *
 * Intended encoding sketch (drives the M7 work):
 *
 *   Sources (inbound-media getters / streams):
 *     - Attachment.getInputStream / Attachment.getBytes
 *     - MediaItem.getStream / MediaItem.getByteArray
 *     - Top-of-handler parameters typed as a *Bitmap source InputStream
 *       arriving from a message receiver.
 *
 *   Sinks (decoders):
 *     - android.graphics.BitmapFactory.decodeStream / decodeByteArray /
 *       decodeFile / decodeResourceStream
 *     - android.media.MediaCodec.queueInputBuffer when invoked on a
 *       handler whose input is attacker-controllable
 *     - com.bumptech.glide.Glide.with(...).load(...) / RequestBuilder.load
 *     - coil.ImageLoader.execute / coil.Coil.imageLoader.execute /
 *       AsyncImage / SubcomposeAsyncImage in Compose
 *     - Native JNI hops into libwebp / libavif / libheif decoders
 *
 *   Barriers (dimension / sanitization checks):
 *     - BitmapFactory.Options with inJustDecodeBounds=true followed by
 *       a width × height check before the actual decode.
 *     - Methods named ["isImageSafe", "checkImageDimensions",
 *       "validateImageBounds", "sanitizeImage", "downsampleToSafeSize",
 *       "rejectOversizedImage"]
 *     - Pre-decode magic-bytes / first-frame inspection (e.g.
 *       readFirstChunk + signature comparison).
 *
 *   Configuration:
 *     class MediaDecodeUnsanitizedConfig extends
 *       TaintTracking::Configuration { ... }
 *     module MediaDecodeUnsanitizedFlow =
 *       TaintTracking::Global<MediaDecodeUnsanitizedConfig>;
 *
 *   Select clause emits: sink, "INV-12: Inbound media from $@ reaches
 *     decoder without a dimension-bound or sanitization barrier."
 *
 *   Ground truth (planned):
 *     - demo-vulnerable-app: 3 violations (BitmapFactory direct, Glide
 *       direct, Coil direct).
 *     - Signal Android / Element X: unknown.
 *
 * Until this stub is fleshed out, the runner produces an empty SARIF
 * result set for INV-12.
 *
 * See aegisgraph/invariants/manifest.json :: INV-12 for the canonical
 * statement, rationale, MASTG-PLATFORM-11 / SSDF PW.7.1 mappings.
 *
 * TODO[M7]: Fully encode this query per the spec above. Cross-reference
 * with aegisgraph/polydiff/extended_axes/{libwebp,libavif,libheif,
 * glide,coil} so witness IDs in the PolyDiff family can be linked to
 * INV-12 violations on the same target.
 * ─────────────────────────────────────────────────────────────────────
 */

import java

// Trivially-empty query so codeql syntactically accepts the file while
// the stub is in place. select clause produces no results.
from Method m
where none()
select m, "INV-12 stub — see comment block in this file for the M7 encoding plan."

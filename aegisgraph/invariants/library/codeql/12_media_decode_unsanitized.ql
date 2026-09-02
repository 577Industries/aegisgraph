/**
 * @id aegisgraph/inv-12-media-decode-unsanitized
 * @name InvariantCheck INV-12: Media decode without dimension-bound or sanitization
 * @description Incoming media (images, video, audio thumbnails) must not
 *              be decoded via BitmapFactory.decodeStream /
 *              BitmapFactory.decodeByteArray /
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
 * @kind path-problem
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
 */

/*
 * Encoding notes:
 *
 *   Sources: inbound-media getters / streams — Attachment.getInputStream,
 *            MediaItem.getStream, getBytes/getByteArray on a *Media or
 *            *Attachment type.
 *
 *   Sinks: decoder calls — BitmapFactory.decode*, BitmapRegionDecoder,
 *          Glide load, Coil load, and ByteBuffer.put on a MediaCodec input
 *          buffer (the bytes' real entry into the codec; queueInputBuffer
 *          only carries integers — ADR 0024).
 *
 *   Barriers: BitmapFactory.Options with inJustDecodeBounds=true
 *             followed by a width/height check, or helper methods named
 *             isImageSafe / checkImageDimensions / validateImageBounds /
 *             sanitizeImage / downsampleToSafeSize.
 *
 * TODO[ground-truth-pass]: Signal-android and Element-X attachment-
 * decoder class names are placeholders rooted in public Android API
 * naming; the M7-GT pass pins them against the anchored commits.
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import MediaDecodeUnsanitizedFlow::PathGraph

/**
 * Sources: inbound-media byte streams or byte arrays.
 */
class InboundMediaSource extends DataFlow::Node {
  InboundMediaSource() {
    // Attachment.getInputStream / Attachment.getBytes / getByteArray.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*Attachment.*|.*MediaItem.*|.*ImageMessage.*|.*VideoMessage.*|.*MediaPayload.*|.*Thumbnail.*") and
      mc.getMethod()
          .hasName([
            "getInputStream", "getBytes", "getByteArray",
            "getStream", "getData", "getRawBytes", "getBuffer",
            "getContent", "openStream"
          ]) and
      this.asExpr() = mc
    )
    or
    // Top-of-handler parameters typed *InputStream / *byte[] arriving
    // from a message receiver.
    exists(Parameter p |
      (
        p.getType().(RefType).hasQualifiedName("java.io", "InputStream") or
        p.getType().(RefType).hasQualifiedName("java.nio", "ByteBuffer") or
        p.getType().getName() = "byte[]"
      ) and
      // A decode/handle/process/receive verb and a media noun anywhere
      // in the name: decodeImage, decodeWithGlide, handleInboundThumbnail,
      // onAttachmentReceived… but not decodeSafe.
      p.getCallable()
          .getName()
          .regexpMatch("(?i).*(handle|process|decode|receive|on).*(attachment|media|image|video|thumbnail|bitmap|glide|coil|frame).*") and
      this.asExpr() = p.getAnAccess()
    )
  }
}

/**
 * Sinks: media-decoder calls.
 */
class MediaDecoderSink extends DataFlow::Node {
  MediaDecoderSink() {
    // android.graphics.BitmapFactory.decode* — the bytes/stream arg.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName("android.graphics", "BitmapFactory") and
      mc.getMethod()
          .hasName([
            "decodeStream", "decodeByteArray", "decodeFile",
            "decodeFileDescriptor", "decodeResourceStream"
          ]) and
      this.asExpr() = mc.getArgument(0)
    )
    or
    // android.media.MediaCodec: the attacker's bytes enter the decoder
    // through ByteBuffer.put on a buffer obtained from getInputBuffer
    // (queueInputBuffer itself only carries index/size/flags integers).
    exists(MethodCall put, MethodCall gib |
      put.getMethod().getDeclaringType().hasQualifiedName("java.nio", "ByteBuffer") and
      put.getMethod().hasName("put") and
      gib.getMethod().getDeclaringType().hasQualifiedName("android.media", "MediaCodec") and
      gib.getMethod().hasName(["getInputBuffer", "getInputBuffers"]) and
      DataFlow::localExprFlow(gib, put.getQualifier()) and
      this.asExpr() = put.getArgument(0)
    )
    or
    // Glide: RequestManager.load / RequestBuilder.load — first arg.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*RequestManager.*|.*RequestBuilder.*|com\\.bumptech\\.glide\\..*") and
      mc.getMethod().hasName("load") and
      this.asExpr() = mc.getArgument(0)
    )
    or
    // Coil: ImageLoader.execute / Coil.imageLoader.execute — request arg.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*ImageLoader.*|coil\\..*|.*Coil$") and
      mc.getMethod()
          .hasName(["execute", "enqueue", "load", "loadAny"]) and
      this.asExpr() = mc.getAnArgument()
    )
    or
    // BitmapRegionDecoder.newInstance — the bytes/stream arg.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName("android.graphics", "BitmapRegionDecoder") and
      mc.getMethod().hasName("newInstance") and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

/**
 * Barriers: dimension-bound and sanitization predicates.
 */
class DimensionOrSanitizationBarrier extends DataFlow::Node {
  DimensionOrSanitizationBarrier() {
    // BitmapFactory.Options with inJustDecodeBounds=true. The bounds-
    // check intent is modeled here as the barrier; downstream code that
    // reads outWidth/outHeight to gate decoding gets the credit.
    exists(FieldAccess fa |
      fa.getField()
          .getDeclaringType()
          .hasQualifiedName("android.graphics", "BitmapFactory$Options") and
      fa.getField()
          .getName()
          .regexpMatch("inJustDecodeBounds|outWidth|outHeight|inSampleSize|outMimeType") and
      this.asExpr() = fa
    )
    or
    // Explicit sanitizer helpers.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "isImageSafe", "checkImageDimensions",
            "validateImageBounds", "sanitizeImage",
            "downsampleToSafeSize", "rejectOversizedImage",
            "validateImageHeader", "checkMaxDimensions",
            "isWithinSafePixelBudget", "verifyImageSignature"
          ]) and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
    or
    // Magic-bytes inspection — read first N bytes and compare.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName(["readFirstChunk", "readMagicBytes", "checkMagicBytes"]) and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
  }
}

/**
 * Configuration: taint flow from inbound-media sources to decoder
 * sinks, with dimension-bound / sanitization helpers as barriers.
 */
module MediaDecodeUnsanitizedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof InboundMediaSource }

  predicate isSink(DataFlow::Node snk) { snk instanceof MediaDecoderSink }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof DimensionOrSanitizationBarrier
  }
}

module MediaDecodeUnsanitizedFlow =
  TaintTracking::Global<MediaDecodeUnsanitizedConfig>;

from
  MediaDecodeUnsanitizedFlow::PathNode source,
  MediaDecodeUnsanitizedFlow::PathNode sink
where MediaDecodeUnsanitizedFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "INV-12: Inbound media from $@ reaches decoder sink without traversing a dimension-bound or sanitization barrier.",
  source.getNode(), "this source"

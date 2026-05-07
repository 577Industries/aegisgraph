/**
 * @id aegisgraph/media-decoder-entry
 * @name AegisGraph: Calls into Glide/Coil/BitmapFactory/ImageDecoder
 * @description Surfaces every call site that delegates image decoding to
 *              Glide, Coil, android.graphics.BitmapFactory, or
 *              android.graphics.ImageDecoder. This is the bridge into the
 *              media-decode path-class and is the primary handoff to
 *              ReproChain's libwebp harness mapping.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external-input
 *       media-decode
 *       aegisgraph-sma
 */

import java

class MediaDecodeApi extends Method {
  MediaDecodeApi() {
    // Glide entry points
    this.getDeclaringType().getQualifiedName() = "com.bumptech.glide.Glide" or
    this.getDeclaringType().getQualifiedName() = "com.bumptech.glide.RequestManager" or
    this.getDeclaringType().getQualifiedName() = "com.bumptech.glide.RequestBuilder" or
    // Coil entry points (Kotlin -> Java surface; matches by qualified name)
    this.getDeclaringType().getQualifiedName().matches("coil.%") or
    this.getDeclaringType().getQualifiedName().matches("coil3.%") or
    // Android platform decoders
    this.getDeclaringType().getQualifiedName() = "android.graphics.BitmapFactory" or
    this.getDeclaringType().getQualifiedName() = "android.graphics.ImageDecoder" or
    // Common generic helpers
    this.getDeclaringType().getQualifiedName() = "android.graphics.drawable.BitmapDrawable"
  }
}

from MethodCall mc
where mc.getMethod() instanceof MediaDecodeApi
select mc,
  "Media-decoder call to '" + mc.getMethod().getQualifiedName() +
    "'. Source: " + mc.getEnclosingCallable().getQualifiedName() + "."

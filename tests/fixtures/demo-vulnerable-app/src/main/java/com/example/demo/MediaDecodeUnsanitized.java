// Synthetic ground-truth fixture for InvariantCheck INV-12.
// Not based on any real product code.
//
// Expected violations: 3
//   * decodeImage: BitmapFactory.decodeStream() called without
//     dimension-bound check.
//   * decodeWithGlide: Glide.with().load(bytes) without dimension limits.
//   * decodeMediaCodec: MediaCodec.configure() called without sanitization gate.
//
// Clean control: decodeSafe checks BitmapFactory.Options.outWidth/Height bound.
package com.example.demo;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.media.MediaCodec;
import android.media.MediaFormat;
import java.io.InputStream;

public class MediaDecodeUnsanitized {

    public Bitmap decodeImage(InputStream in) {
        // VIOLATION 1: decodeStream without dimension-bound check.
        return BitmapFactory.decodeStream(in);
    }

    public Bitmap decodeWithGlide(byte[] bytes) {
        // VIOLATION 2: simulated Glide.load without dimension limits.
        // (Structural: BitmapFactory.decodeByteArray as the stand-in
        // sink — Glide.with().load() is the real-world equivalent.)
        return BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
    }

    public void decodeMediaCodec(MediaFormat format) throws Exception {
        // VIOLATION 3: MediaCodec.configure without sanitization gate.
        MediaCodec codec = MediaCodec.createDecoderByType("video/avc");
        codec.configure(format, null, null, 0);
    }

    // Clean control: dimension-bound check barrier present.
    public Bitmap decodeSafe(InputStream in, int maxW, int maxH) {
        BitmapFactory.Options bounds = new BitmapFactory.Options();
        bounds.inJustDecodeBounds = true;
        BitmapFactory.decodeStream(in, null, bounds);
        if (bounds.outWidth > maxW || bounds.outHeight > maxH) {
            return null;
        }
        return BitmapFactory.decodeStream(in);
    }
}

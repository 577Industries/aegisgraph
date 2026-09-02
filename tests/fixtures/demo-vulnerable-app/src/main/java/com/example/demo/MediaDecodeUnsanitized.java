// Synthetic ground-truth fixture for InvariantCheck INV-12.
// Not based on any real product code.
//
// Expected violations: 3
//   * decodeImage: BitmapFactory.decodeStream() called without
//     dimension-bound check.
//   * decodeWithGlide: Glide.with().load(bytes) without dimension limits.
//   * decodeMediaCodec: inbound frame bytes queued into a MediaCodec input
//     buffer without a sanitization gate.
//
// Clean control: decodeSafe checks BitmapFactory.Options.outWidth/Height bound.
package com.example.demo;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.media.MediaCodec;
import java.io.InputStream;
import java.nio.ByteBuffer;

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

    public void decodeMediaCodec(byte[] frame) throws Exception {
        // VIOLATION 3: attacker frame bytes reach the decoder input buffer
        // without a sanitization gate.
        MediaCodec codec = MediaCodec.createDecoderByType("video/avc");
        int index = codec.dequeueInputBuffer(10_000);
        ByteBuffer input = codec.getInputBuffer(index);
        input.put(frame);
        codec.queueInputBuffer(index, 0, frame.length, 0, 0);
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

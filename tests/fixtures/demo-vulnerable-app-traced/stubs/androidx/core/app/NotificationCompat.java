// Compile-only stub for the traced ground-truth overlay. Synthetic ground-truth
// fixture tooling. Not based on any real product code. androidx.core ships as
// an AAR; the fixture uses only Builder.setContentText / setContentTitle.
package androidx.core.app;

public class NotificationCompat {
    public static class Builder {
        public Builder setContentText(CharSequence text) { return this; }
        public Builder setContentTitle(CharSequence title) { return this; }
    }
}

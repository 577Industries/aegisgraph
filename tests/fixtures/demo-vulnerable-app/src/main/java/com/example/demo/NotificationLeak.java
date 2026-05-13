// Synthetic ground-truth fixture for InvariantCheck INV-02.
// Not based on any real product code.
//
// Expected violations: 2
//   * showBodyOnLockscreen: getBody() -> setContentText() (no redaction)
//   * showSenderOnLockscreen: getSenderDisplayName() -> setContentTitle() (no redaction)
//
// Clean control: showRedacted uses redactedBody() barrier.
package com.example.demo;

import androidx.core.app.NotificationCompat;

public class NotificationLeak {

    public void showBodyOnLockscreen(Message msg, NotificationCompat.Builder builder) {
        // VIOLATION 1: msg.getBody() flows directly into setContentText without redaction.
        String body = msg.getBody();
        builder.setContentText(body);
    }

    public void showSenderOnLockscreen(Message msg, NotificationCompat.Builder builder) {
        // VIOLATION 2: msg.getSenderDisplayName() flows into setContentTitle.
        String sender = msg.getSenderDisplayName();
        builder.setContentTitle(sender);
    }

    // Clean control: redaction barrier present.
    public void showRedacted(Message msg, NotificationCompat.Builder builder) {
        String redacted = msg.redactedBody();
        builder.setContentText(redacted);
    }

    public static class Message {
        public String getBody() { return ""; }
        public String getSenderDisplayName() { return ""; }
        public String redactedBody() { return "***"; }
    }
}

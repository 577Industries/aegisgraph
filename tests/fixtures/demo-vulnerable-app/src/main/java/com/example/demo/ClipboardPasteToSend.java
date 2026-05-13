// Synthetic ground-truth fixture for InvariantCheck INV-08.
// Not based on any real product code.
//
// Expected violations: 1
//   * autoPasteAndSend: ClipboardManager.getPrimaryClip().getItemAt(0).getText()
//     flows into MessageSender.sendMessage() without a confirmation barrier.
//
// Clean control: pasteAndSendWithConfirm uses AlertDialog barrier.
package com.example.demo;

import android.content.ClipboardManager;
import android.content.ClipData;
import android.app.AlertDialog;

public class ClipboardPasteToSend {

    public void autoPasteAndSend(ClipboardManager clipboard, MessageSender sender) {
        // VIOLATION 1: clipboard read flows into sendMessage without confirmation.
        ClipData clip = clipboard.getPrimaryClip();
        String text = clip.getItemAt(0).getText().toString();
        sender.sendMessage(text);
    }

    // Clean control: AlertDialog confirmation barrier present.
    public void pasteAndSendWithConfirm(ClipboardManager clipboard, MessageSender sender,
                                        AlertDialog.Builder dialogBuilder) {
        ClipData clip = clipboard.getPrimaryClip();
        final String text = clip.getItemAt(0).getText().toString();
        dialogBuilder.setMessage("Send: " + text + "?")
                     .setPositiveButton("OK", (d, w) -> sender.sendMessage(text))
                     .show();
    }

    public static class MessageSender {
        public void sendMessage(String text) {}
    }
}

// Synthetic ground-truth fixture for InvariantCheck INV-01.
// Not based on any real product code.
//
// Expected violations: 3
//   * fetchLinkPreview: getText() -> URL.openStream() (no policy check)
//   * fetchAttachment: getBody() -> HttpURLConnection.connect() (no policy)
//   * fetchPushUrl: getPreviewUrl() -> OkHttp Request.Builder.url() (no policy)
//
// Clean control: fetchClean uses Allowlist.isAllowedUrl barrier.
package com.example.demo;

import java.net.URL;
import java.net.HttpURLConnection;
import java.io.InputStream;
import com.example.fixtures.Allowlist;

public class UrlFetchWithoutPolicy {

    public InputStream fetchLinkPreview(LinkPreview preview) throws Exception {
        // VIOLATION 1: preview.getText() flows to URL.openStream() without policy.
        String urlStr = preview.getText();
        URL url = new URL(urlStr);
        return url.openStream();
    }

    public void fetchAttachment(Message msg) throws Exception {
        // VIOLATION 2: msg.getBody() flows to HttpURLConnection.connect() without policy.
        String urlStr = msg.getBody();
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.connect();
    }

    public void fetchPushUrl(PushPayload push) throws Exception {
        // VIOLATION 3: push.getPreviewUrl() flows to OkHttp Request.Builder.url() without policy.
        String urlStr = push.getPreviewUrl();
        okhttp3.Request request = new okhttp3.Request.Builder().url(urlStr).build();
        new okhttp3.OkHttpClient().newCall(request).execute();
    }

    // Clean control: allowlist barrier present.
    public InputStream fetchClean(LinkPreview preview) throws Exception {
        String urlStr = preview.getText();
        if (!Allowlist.isAllowedUrl(urlStr)) {
            return null;
        }
        return new URL(urlStr).openStream();
    }

    // Stub types so the file compiles in isolation.
    public static class LinkPreview { public String getText() { return ""; } }
    public static class Message { public String getBody() { return ""; } }
    public static class PushPayload { public String getPreviewUrl() { return ""; } }
}

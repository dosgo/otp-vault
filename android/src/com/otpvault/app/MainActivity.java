package com.otpvault.app;

import android.Manifest;
import android.app.Activity;
import android.content.ContentValues;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.AssetManager;
import android.database.Cursor;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.MediaStore;
import android.provider.OpenableColumns;
import android.util.Base64;
import android.view.KeyEvent;
import android.view.View;
import android.webkit.JavascriptInterface;
import android.webkit.PermissionRequest;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 口令宝 Android 壳。
 * 页面通过「仅绑定 127.0.0.1」的内置 HTTP 服务加载，这样 WebView 会把来源视为
 * 安全上下文（secure context），crypto.subtle / localStorage / getUserMedia 才能正常工作。
 * 服务不监听外网端口，也不发起任何外部网络请求；全部资源来自 APK assets。
 */
public class MainActivity extends Activity {

    private WebView webView;
    private LocalAssetsServer server;
    private ValueCallback<Uri[]> filePathCallback;
    private PermissionRequest pendingCameraRequest;
    private byte[] pendingBackup;
    private static final int REQ_FILE = 1001;
    private static final int REQ_CAMERA = 1002;
    private static final int REQ_SAVE = 1003;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        clearQrCache();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            getWindow().setStatusBarColor(Color.parseColor("#F5F7FB"));
            getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR);
        }

        try {
            // 端口必须保持稳定：WebView 的 localStorage 按 origin(含端口) 隔离，
            // 端口每次变化都会让已保存的账号「凭空消失」。
            android.content.SharedPreferences prefs = getSharedPreferences("otpvault", MODE_PRIVATE);
            int lastPort = prefs.getInt("server_port", 47821);
            int[] candidates = {lastPort, 47821, 47822, 47823, 47824, 47825,
                    47826, 47827, 47828, 47829, 47830};
            for (int candidate : candidates) {
                try {
                    server = new LocalAssetsServer(getAssets(), candidate);
                    break;
                } catch (IOException ignored) {
                }
            }
            if (server == null) throw new IOException("无法绑定本地资源服务端口");
            prefs.edit().putInt("server_port", server.getPort()).apply();
            server.start();

            webView = new WebView(this);
            setContentView(webView);

            WebSettings s = webView.getSettings();
            s.setJavaScriptEnabled(true);
            s.setDomStorageEnabled(true);
            s.setDatabaseEnabled(true);
            s.setAllowFileAccess(true);
            s.setAllowContentAccess(true);
            s.setLoadWithOverviewMode(true);
            s.setUseWideViewPort(true);
            s.setMediaPlaybackRequiresUserGesture(false);
            s.setJavaScriptCanOpenWindowsAutomatically(false);
            s.setCacheMode(WebSettings.LOAD_NO_CACHE);
            s.setSupportMultipleWindows(false);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
            }
            s.setUserAgentString(s.getUserAgentString() + " OTPVaultAndroid/1.2");

            // Blob + <a download> 在 Android WebView 里不触发下载；改由原生桥写入「下载」目录
            webView.addJavascriptInterface(new BackupBridge(), "OtpVault");

            webView.setWebViewClient(new WebViewClient() {
                @Override
                public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                    Uri uri = request.getUrl();
                    if ("127.0.0.1".equals(uri.getHost())) return false;
                    try {
                        startActivity(new Intent(Intent.ACTION_VIEW, uri));
                    } catch (Exception ignored) {
                    }
                    return true;
                }
            });

            webView.setWebChromeClient(new WebChromeClient() {
                @Override
                public boolean onConsoleMessage(android.webkit.ConsoleMessage cm) {
                    android.util.Log.d("OtpVault", "JS " + cm.messageLevel() + ": " + cm.message()
                            + " (" + cm.sourceId() + ":" + cm.lineNumber() + ")");
                    return true;
                }

                @Override
                public void onPermissionRequest(final PermissionRequest request) {
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            boolean wantsCamera = false;
                            for (String r : request.getResources()) {
                                if (PermissionRequest.RESOURCE_VIDEO_CAPTURE.equals(r)) wantsCamera = true;
                            }
                            if (!wantsCamera) {
                                request.deny();
                                return;
                            }
                            // 只在真正扫码时才申请相机权限，避免首屏弹权限框
                            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M
                                    || checkSelfPermission(Manifest.permission.CAMERA)
                                    == PackageManager.PERMISSION_GRANTED) {
                                request.grant(new String[]{PermissionRequest.RESOURCE_VIDEO_CAPTURE});
                            } else {
                                pendingCameraRequest = request;
                                requestPermissions(new String[]{Manifest.permission.CAMERA}, REQ_CAMERA);
                            }
                        }
                    });
                }

                @Override
                public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback,
                                                 FileChooserParams params) {
                    if (filePathCallback != null) filePathCallback.onReceiveValue(null);
                    filePathCallback = callback;
                    try {
                        Intent intent = params.createIntent();
                        // 备份输入同时接受 .zip/.json，WebView 可能挑出单个 MIME 把 zip 过滤掉
                        for (String t : params.getAcceptTypes()) {
                            if (t != null && (t.contains("zip") || t.contains("json"))) {
                                intent.setType("*/*");
                                break;
                            }
                        }
                        if (params.getMode() == FileChooserParams.MODE_OPEN_MULTIPLE) {
                            intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
                        }
                        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                        startActivityForResult(intent, REQ_FILE);
                        return true;
                    } catch (Exception e) {
                        filePathCallback = null;
                        Toast.makeText(MainActivity.this, "无法打开文件选择器", Toast.LENGTH_SHORT).show();
                        return false;
                    }
                }
            });

            webView.loadUrl("http://127.0.0.1:" + server.getPort() + "/index.html");
        } catch (Exception e) {
            Toast.makeText(this, "启动失败：" + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQ_SAVE) {
            if (resultCode == RESULT_OK && data != null && data.getData() != null && pendingBackup != null) {
                try {
                    OutputStream os = getContentResolver().openOutputStream(data.getData());
                    if (os == null) throw new IOException("无法写入所选位置");
                    os.write(pendingBackup);
                    os.flush();
                    os.close();
                    showToast("加密备份已保存");
                } catch (Exception e) {
                    showToast("保存失败：" + e.getMessage());
                }
            }
            pendingBackup = null;
            return;
        }
        if (requestCode == REQ_FILE) {
            if (filePathCallback == null) return;
            Uri[] results = null;
            if (resultCode == RESULT_OK && data != null) {
                // 多选时系统用 clipData 返回全部文件，单选才用 getData()
                List<Uri> picked = new ArrayList<>();
                if (data.getClipData() != null && data.getClipData().getItemCount() > 0) {
                    int n = data.getClipData().getItemCount();
                    for (int i = 0; i < n; i++) {
                        picked.add(data.getClipData().getItemAt(i).getUri());
                    }
                } else if (data.getData() != null) {
                    picked.add(data.getData());
                }
                // 相册返回的 content:// 批量授权在部分 WebView 上读不到（尤其多选），
                // 先复制到应用私有缓存，再以 file:// 交给 WebView，保证任何来源都能解码。
                List<Uri> safe = new ArrayList<>();
                File batch = new File(new File(getCacheDir(), "qr-import"),
                        String.valueOf(System.currentTimeMillis()));
                for (Uri uri : picked) {
                    safe.add(copyToPrivateCache(uri, displayNameOf(uri), batch));
                }
                results = safe.toArray(new Uri[0]);
            }
            filePathCallback.onReceiveValue(results);
            filePathCallback = null;
            return;
        }
        super.onActivityResult(requestCode, resultCode, data);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        if (requestCode == REQ_CAMERA && pendingCameraRequest != null) {
            boolean granted = grantResults.length > 0
                    && grantResults[0] == PackageManager.PERMISSION_GRANTED;
            try {
                if (granted) {
                    pendingCameraRequest.grant(new String[]{PermissionRequest.RESOURCE_VIDEO_CAPTURE});
                } else {
                    pendingCameraRequest.deny();
                }
            } catch (Exception ignored) {
            }
            pendingCameraRequest = null;
            return;
        }
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    }

    private void showToast(final String text) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(MainActivity.this, text, Toast.LENGTH_LONG).show();
            }
        });
    }

    /** 保留用户选择文件的真实文件名与扩展名（.zip / .json / .png） */
    private String displayNameOf(Uri uri) {
        String name = null;
        Cursor c = null;
        try {
            c = getContentResolver().query(uri, null, null, null, null);
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (idx >= 0) name = c.getString(idx);
            }
        } catch (Exception ignored) {
        } finally {
            if (c != null) try { c.close(); } catch (Exception ignored) {}
        }
        if (name == null || name.length() == 0) name = uri.getLastPathSegment();
        if (name == null || name.length() == 0) name = "backup.bin";
        return name.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    /** 供页面调用：把导出的加密 ZIP 保存到系统「下载」目录 */
    private class BackupBridge {
        @JavascriptInterface
        public String saveBackup(String base64, String name) {
            try {
                byte[] bytes = Base64.decode(base64, Base64.DEFAULT);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    ContentValues cv = new ContentValues();
                    cv.put(MediaStore.Downloads.DISPLAY_NAME, name);
                    cv.put(MediaStore.Downloads.MIME_TYPE, "application/zip");
                    cv.put(MediaStore.Downloads.IS_PENDING, 1);
                    Uri uri = getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
                    if (uri == null) throw new IOException("无法创建下载文件");
                    OutputStream os = getContentResolver().openOutputStream(uri);
                    if (os == null) throw new IOException("无法写入下载文件");
                    os.write(bytes);
                    os.flush();
                    os.close();
                    ContentValues done = new ContentValues();
                    done.put(MediaStore.Downloads.IS_PENDING, 0);
                    getContentResolver().update(uri, done, null, null);
                    showToast("加密备份已保存到「下载」目录：" + name);
                    return "ok";
                }
                pendingBackup = bytes;
                Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("application/zip");
                intent.putExtra(Intent.EXTRA_TITLE, name);
                startActivityForResult(intent, REQ_SAVE);
                return "picker";
            } catch (Exception e) {
                return "error:" + e.getMessage();
            }
        }
    }

    /** 把 content:// 文件复制到应用私有缓存，尽量保留原文件名，失败时原样返回 */
    private Uri copyToPrivateCache(Uri src, String name, File batch) {
        try {
            if (!batch.exists() && !batch.mkdirs()) return src;
            File dst = new File(batch, name);
            int dup = 1;
            while (dst.exists()) dst = new File(batch, dup++ + "_" + name);
            InputStream is = getContentResolver().openInputStream(src);
            if (is == null) return src;
            FileOutputStream os = new FileOutputStream(dst);
            byte[] buf = new byte[8192];
            int len;
            while ((len = is.read(buf)) > 0) os.write(buf, 0, len);
            os.close();
            is.close();
            if (dst.length() == 0) return src;
            return Uri.fromFile(dst);
        } catch (Exception e) {
            return src;
        }
    }

    /** 二维码截图里含明文密钥、备份 ZIP 含全部账号，启动时清掉上次残留的临时副本 */
    private void clearQrCache() {
        deleteRecursive(new File(getCacheDir(), "qr-import"));
    }

    private static void deleteRecursive(File f) {
        if (f == null || !f.exists()) return;
        File[] children = f.listFiles();
        if (children != null) for (File c : children) deleteRecursive(c);
        f.delete();
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (keyCode == KeyEvent.KEYCODE_BACK && webView != null && webView.canGoBack()) {
            webView.goBack();
            return true;
        }
        return super.onKeyDown(keyCode, event);
    }

    @Override
    protected void onDestroy() {
        if (server != null) server.stop();
        if (webView != null) webView.destroy();
        super.onDestroy();
    }

    /** 极小的本地静态文件服务：只绑定回环地址，只从 assets/www 读取，禁止路径穿越。 */
    private static class LocalAssetsServer {
        private final AssetManager assets;
        private final ServerSocket socket;
        private final ExecutorService pool = Executors.newCachedThreadPool();
        private volatile boolean running = true;

        LocalAssetsServer(AssetManager assets, int port) throws IOException {
            this.assets = assets;
            this.socket = new ServerSocket(port, 16, InetAddress.getByName("127.0.0.1"));
        }

        int getPort() {
            return socket.getLocalPort();
        }

        void start() {
            Thread acceptor = new Thread(new Runnable() {
                @Override
                public void run() {
                    while (running) {
                        try {
                            final Socket client = socket.accept();
                            pool.execute(new Runnable() {
                                @Override
                                public void run() {
                                    handle(client);
                                }
                            });
                        } catch (IOException e) {
                            if (running) e.printStackTrace();
                        }
                    }
                }
            }, "otp-assets-server");
            acceptor.setDaemon(true);
            acceptor.start();
        }

        void stop() {
            running = false;
            pool.shutdownNow();
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }

        private void handle(Socket client) {
            try {
                BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream(), "UTF-8"));
                OutputStream out = client.getOutputStream();
                String requestLine = in.readLine();
                if (requestLine == null) return;
                // 消费掉剩余请求头
                String header;
                while ((header = in.readLine()) != null && header.length() > 0) {
                    // ignore
                }
                String[] parts = requestLine.split(" ");
                String path = parts.length > 1 ? parts[1] : "/";
                int query = path.indexOf('?');
                if (query >= 0) path = path.substring(0, query);
                if (path.equals("/")) path = "/index.html";
                if (path.contains("..") || path.contains("\\") || !path.startsWith("/")) {
                    write(out, 403, "text/plain; charset=utf-8", "Forbidden".getBytes("UTF-8"));
                    return;
                }
                String assetPath = "www" + path;
                byte[] body;
                try {
                    InputStream is = assets.open(assetPath);
                    body = readAll(is);
                    is.close();
                } catch (IOException e) {
                    write(out, 404, "text/plain; charset=utf-8", "Not found".getBytes("UTF-8"));
                    return;
                }
                write(out, 200, mimeOf(assetPath), body);
            } catch (Exception ignored) {
            } finally {
                try {
                    client.close();
                } catch (IOException ignored) {
                }
            }
        }

        private static byte[] readAll(InputStream is) throws IOException {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int n;
            while ((n = is.read(chunk)) > 0) buffer.write(chunk, 0, n);
            return buffer.toByteArray();
        }

        private static void write(OutputStream out, int code, String type, byte[] body) throws IOException {
            String reason = code == 200 ? "OK" : (code == 403 ? "Forbidden" : "Not Found");
            String head = "HTTP/1.1 " + code + " " + reason + "\r\n"
                    + "Content-Type: " + type + "\r\n"
                    + "Content-Length: " + body.length + "\r\n"
                    + "Cache-Control: no-store\r\n"
                    + "X-Content-Type-Options: nosniff\r\n"
                    + "Connection: close\r\n\r\n";
            out.write(head.getBytes("UTF-8"));
            out.write(body);
            out.flush();
        }

        private static String mimeOf(String name) {
            if (name.endsWith(".html")) return "text/html; charset=utf-8";
            if (name.endsWith(".js")) return "application/javascript; charset=utf-8";
            if (name.endsWith(".css")) return "text/css; charset=utf-8";
            if (name.endsWith(".json") || name.endsWith(".webmanifest")) return "application/json; charset=utf-8";
            if (name.endsWith(".png")) return "image/png";
            if (name.endsWith(".svg")) return "image/svg+xml";
            return "application/octet-stream";
        }
    }
}

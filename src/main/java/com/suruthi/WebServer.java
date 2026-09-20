package com.suruthi;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class WebServer {

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 8080), 0);
        server.createContext("/", ex -> {
            String msg = "";
            if (ex.getRequestMethod().equals("POST")) {
                String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String path = body.startsWith("path=")
                        ? URLDecoder.decode(body.substring(5), StandardCharsets.UTF_8).trim() : "";
                msg = scan(path);
            }
            send(ex, page(msg));
        });
        server.start();
        System.out.println("Open in browser: http://localhost:8080");
    }

    static String scan(String path) {
        try {
            File f = new File(path.replace("\"", ""));
            if (!f.isFile()) return "File not found";
            String file = f.getAbsolutePath();
            double entropy = StaticAnalyzer.entropy(file);
            List<String> found = ThreatScanner.findSuspicious(ThreatScanner.extractStrings(file));
            int score = ThreatScanner.riskScore(file, entropy, found);
            String level = ThreatScanner.level(score);
            DatabaseService.save(file, FileHasher.sha256(file), StaticAnalyzer.fileSize(file),
                    StaticAnalyzer.extension(file), entropy, found.toString(), score, level);
            return "Scanned: risk " + score + " (" + level + ")";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    static String esc(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;");
    }

    static String page(String msg) {
        StringBuilder sb = new StringBuilder();
        sb.append("<html><body style='font-family:Arial;margin:30px'>")
                .append("<h2>SafeMal Dashboard</h2>")
                .append("<form method='post'>")
                .append("<input name='path' size='60' value='C:\\test\\sample.txt'> ")
                .append("<button>Scan</button></form>")
                .append("<p><b>").append(esc(msg)).append("</b></p>")
                .append("<h3>Scan History</h3>")
                .append("<table border='1' cellpadding='6' style='border-collapse:collapse'>")
                .append("<tr><th>ID</th><th>File</th><th>SHA-256</th><th>Size</th><th>Entropy</th>")
                .append("<th>Suspicious</th><th>Score</th><th>Level</th><th>Time</th></tr>");
        try {
            for (String[] r : DatabaseService.history()) {
                String color = r[7].equals("HIGH") ? "red" : r[7].equals("MEDIUM") ? "orange" : "green";
                sb.append("<tr>");
                for (int i = 0; i < r.length; i++) {
                    if (i == 7) sb.append("<td style='color:").append(color).append("'><b>")
                            .append(esc(r[i])).append("</b></td>");
                    else sb.append("<td>").append(esc(r[i])).append("</td>");
                }
                sb.append("</tr>");
            }
        } catch (Exception e) {
            sb.append("<tr><td colspan='9'>DB error: ").append(esc(e.getMessage())).append("</td></tr>");
        }
        sb.append("</table></body></html>");
        return sb.toString();
    }

    static void send(HttpExchange ex, String html) throws IOException {
        byte[] b = html.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "text/html; charset=UTF-8");
        ex.sendResponseHeaders(200, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }
}
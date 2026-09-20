package com.suruthi;

import java.nio.file.*;
import java.util.*;

public class ThreatScanner {

    static final List<String> KEYWORDS = List.of(
            "cmd.exe", "powershell", "CreateRemoteThread", "VirtualAlloc",
            "WriteProcessMemory", "RegSetValue", "keylog", "http://", "https://");

    static final List<String> BAD_EXT =
            List.of("exe", "dll", "bat", "ps1", "vbs", "scr", "js");

    public static List<String> extractStrings(String path) throws Exception {
        byte[] data = Files.readAllBytes(Path.of(path));
        List<String> result = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            if (b >= 32 && b < 127) {
                sb.append((char) b);
            } else {
                if (sb.length() >= 4) result.add(sb.toString());
                sb.setLength(0);
            }
        }
        if (sb.length() >= 4) result.add(sb.toString());
        return result;
    }

    public static List<String> findSuspicious(List<String> strings) {
        List<String> found = new ArrayList<>();
        for (String k : KEYWORDS) {
            for (String s : strings) {
                if (s.toLowerCase().contains(k.toLowerCase())) {
                    found.add(k);
                    break;
                }
            }
        }
        return found;
    }

    public static int riskScore(String path, double entropy, List<String> found) {
        int score = 0;
        if (entropy > 7.0) score += 40;
        if (BAD_EXT.contains(StaticAnalyzer.extension(path))) score += 20;
        score += Math.min(found.size() * 10, 40);
        return Math.min(score, 100);
    }

    public static String level(int score) {
        if (score >= 60) return "HIGH";
        if (score >= 30) return "MEDIUM";
        return "LOW";
    }
}
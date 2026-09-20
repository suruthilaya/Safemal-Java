package com.suruthi;

import java.nio.file.*;

public class StaticAnalyzer {

    public static long fileSize(String path) throws Exception {
        return Files.size(Path.of(path));
    }

    public static String extension(String path) {
        int i = path.lastIndexOf('.');
        return i == -1 ? "none" : path.substring(i + 1).toLowerCase();
    }

    public static double entropy(String path) throws Exception {
        byte[] data = Files.readAllBytes(Path.of(path));
        if (data.length == 0) return 0;
        int[] freq = new int[256];
        for (byte b : data) freq[b & 0xff]++;
        double e = 0;
        for (int f : freq) {
            if (f == 0) continue;
            double p = (double) f / data.length;
            e -= p * (Math.log(p) / Math.log(2));
        }
        return e;
    }
}

package com.suruthi;

import java.nio.file.*;
import java.util.List;

public class ReportGenerator {

    public static void generate(String file, String hash, long size, String type,
                                double entropy, List<String> found,
                                int score, String level) throws Exception {

        String color = level.equals("HIGH") ? "red"
                : level.equals("MEDIUM") ? "orange" : "green";

        String html = "<html><body style='font-family:Arial'>"
                + "<h2>SafeMal Analysis Report</h2>"
                + "<p><b>File:</b> " + file + "</p>"
                + "<p><b>SHA-256:</b> " + hash + "</p>"
                + "<p><b>Size:</b> " + size + " bytes</p>"
                + "<p><b>Type:</b> " + type + "</p>"
                + "<p><b>Entropy:</b> " + String.format("%.2f", entropy) + "</p>"
                + "<p><b>Suspicious:</b> " + found + "</p>"
                + "<h3 style='color:" + color + "'>Risk: " + score + " (" + level + ")</h3>"
                + "</body></html>";

        Files.writeString(Path.of("C:\\test\\report.html"), html);
    }
}
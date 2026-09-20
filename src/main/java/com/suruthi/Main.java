package com.suruthi;

import java.io.File;
import java.util.List;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter file or folder path: ");
        String path = sc.nextLine().trim().replace("\"", "");
        File f = new File(path);

        if (f.isDirectory()) {
            File[] files = f.listFiles(File::isFile);
            if (files == null) return;
            for (File x : files) {
                try {
                    scanOne(x.getAbsolutePath(), false);
                } catch (Exception e) {
                    System.out.println("Skipped: " + x.getName());
                }
            }
        } else if (f.isFile()) {
            scanOne(path, true);
        } else {
            System.out.println("Path not found!");
        }
    }

    static void scanOne(String file, boolean makeReport) throws Exception {
        double entropy = StaticAnalyzer.entropy(file);
        List<String> found = ThreatScanner.findSuspicious(ThreatScanner.extractStrings(file));
        int score = ThreatScanner.riskScore(file, entropy, found);
        String level = ThreatScanner.level(score);
        String hash = FileHasher.sha256(file);
        long size = StaticAnalyzer.fileSize(file);
        String type = StaticAnalyzer.extension(file);

        System.out.println("-----------------------------");
        System.out.println("File       : " + file);
        System.out.println("SHA-256    : " + hash);
        System.out.println("Size       : " + size + " bytes");
        System.out.println("Entropy    : " + String.format("%.2f", entropy));
        System.out.println("Suspicious : " + found);
        System.out.println("Risk Score : " + score + " (" + level + ")");
        try {
            DatabaseService.save(file, hash, size, type, entropy, found.toString(), score, level);
            System.out.println("Saved to MySQL");
        } catch (Exception e) {
            System.out.println("DB error: " + e.getMessage());
        }

        if (makeReport) {
            ReportGenerator.generate(file, hash, size, type, entropy, found, score, level);
            System.out.println("Report created: C:\\test\\report.html");
        }
    }
}
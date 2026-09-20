package com.suruthi;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class DatabaseService {
    static final String URL = "jdbc:mysql://localhost:3306/safemal";
    static final String USER = "root";
    static final String PASS = "YOUR PASSWORD";

    public static void save(String file, String hash, long size, String type,
                            double entropy, String suspicious,
                            int score, String level) throws Exception {
        String sql = "INSERT INTO scans (file_path, sha256, size_bytes, file_type, "
                + "entropy, suspicious, risk_score, risk_level) VALUES (?,?,?,?,?,?,?,?)";
        try (Connection c = DriverManager.getConnection(URL, USER, PASS);
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, file);
            ps.setString(2, hash);
            ps.setLong(3, size);
            ps.setString(4, type);
            ps.setDouble(5, entropy);
            ps.setString(6, suspicious);
            ps.setInt(7, score);
            ps.setString(8, level);
            ps.executeUpdate();
        }
    }

    public static List<String[]> history() throws Exception {
        List<String[]> rows = new ArrayList<>();
        String sql = "SELECT id, file_path, sha256, size_bytes, entropy, suspicious, "
                + "risk_score, risk_level, scanned_at FROM scans ORDER BY id DESC LIMIT 50";
        try (Connection c = DriverManager.getConnection(URL, USER, PASS);
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(sql)) {
            while (rs.next()) {
                rows.add(new String[]{
                        rs.getString(1), rs.getString(2),
                        rs.getString(3).substring(0, 12) + "...",
                        rs.getString(4), String.format("%.2f", rs.getDouble(5)),
                        rs.getString(6), rs.getString(7), rs.getString(8), rs.getString(9)});
            }
        }
        return rows;
    }
}
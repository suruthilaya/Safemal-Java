# SafeMal-Java

Java-based malware analysis and threat detection system (static analysis).

It checks a file without running it: SHA-256 hash, size, type, entropy, suspicious strings, and a risk score (LOW / MEDIUM / HIGH). Results are saved in MySQL and shown on a web dashboard.

## How to run
1. Create the MySQL database safemal and the table scans.
2. Set your MySQL password in DatabaseService.java.
3. Run WebServer.java and open http://localhost:8080

## Technologies
Java, JDBC, MySQL, Maven, IntelliJ IDEA

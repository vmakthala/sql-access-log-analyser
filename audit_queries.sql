-- SQL User Access Log Analyser
-- Dataset: Cybersecurity Intrusion Detection Dataset (Kaggle), 9,537 sessions

-- Setup
CREATE DATABASE access_audit;
USE access_audit;
CREATE TABLE session_data (
    session_id VARCHAR(20),
    network_packet_size INT,
    protocol_type VARCHAR(10),
    login_attempts INT,
    session_duration FLOAT,
    encryption_used VARCHAR(10),
    ip_reputation_score FLOAT,
    failed_logins INT,
    browser_type VARCHAR(20),
    unusual_time_access INT,
    attack_detected INT
);

-- Check all rows loaded (should be 9,537)
SELECT COUNT(*) FROM session_data;

-- Sessions with 3+ failed logins (possible brute-force)
SELECT
    session_id,
    failed_logins,
    attack_detected
FROM session_data
WHERE failed_logins >= 3
ORDER BY failed_logins DESC;

-- Finding 1: repeated failed logins (3+)
SELECT COUNT(*) FROM session_data WHERE failed_logins >= 3;

-- Finding 2: unusual / off-hours access
SELECT COUNT(*) FROM session_data WHERE unusual_time_access = 1;

-- Finding 3: no encryption + high-risk IP
SELECT COUNT(*) FROM session_data WHERE encryption_used = 'None' AND ip_reputation_score > 0.5;

-- Finding 4: confirmed attacks
SELECT COUNT(*) FROM session_data WHERE attack_detected = 1;

-- Failed logins by protocol (used for the Power BI chart)
SELECT protocol_type, SUM(failed_logins) AS total_failed_logins
FROM session_data
GROUP BY protocol_type
ORDER BY total_failed_logins DESC;

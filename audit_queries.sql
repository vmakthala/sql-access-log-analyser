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

-- Finding 4: sessions labelled as attacks in the dataset
SELECT COUNT(*) FROM session_data WHERE attack_detected = 1;

-- Failed logins by protocol (used for the Power BI chart)
SELECT protocol_type, SUM(failed_logins) AS total_failed_logins
FROM session_data
GROUP BY protocol_type
ORDER BY total_failed_logins DESC;

-- Data checks: missing values
SELECT COUNT(*) - COUNT(session_id) AS missing_session_id,
       COUNT(*) - COUNT(failed_logins) AS missing_failed_logins,
       COUNT(*) - COUNT(encryption_used) AS missing_encryption,
       COUNT(*) - COUNT(ip_reputation_score) AS missing_ip_score
FROM session_data;

-- Data checks: duplicate session IDs
SELECT COUNT(*) - COUNT(DISTINCT session_id) AS duplicate_ids
FROM session_data;

-- Data checks: value ranges
SELECT MIN(failed_logins), MAX(failed_logins),
       MIN(ip_reputation_score), MAX(ip_reputation_score)
FROM session_data;

-- Flag test: 3+ failed logins vs attack rate
SELECT CASE WHEN failed_logins >= 3 THEN 'Flagged (3+)'
            ELSE 'Not flagged' END AS login_group,
       COUNT(*) AS sessions,
       ROUND(AVG(attack_detected) * 100, 1) AS attack_rate_pct
FROM session_data
GROUP BY login_group;

-- Flag test: off-hours access vs attack rate
SELECT unusual_time_access,
       COUNT(*) AS sessions,
       ROUND(AVG(attack_detected) * 100, 1) AS attack_rate_pct
FROM session_data
GROUP BY unusual_time_access;

-- Flag test: no encryption + high-risk IP vs attack rate
SELECT CASE WHEN encryption_used = 'None' AND ip_reputation_score > 0.5
            THEN 'Flagged' ELSE 'Not flagged' END AS enc_ip_group,
       COUNT(*) AS sessions,
       ROUND(AVG(attack_detected) * 100, 1) AS attack_rate_pct
FROM session_data
GROUP BY enc_ip_group;

-- Threshold check: attack rate by number of failed logins
SELECT failed_logins,
       COUNT(*) AS sessions,
       ROUND(AVG(attack_detected) * 100, 1) AS attack_rate_pct
FROM session_data
GROUP BY failed_logins
ORDER BY failed_logins;

-- Threshold check: attack rate by IP reputation band
SELECT CASE WHEN ip_reputation_score < 0.25 THEN '1: 0 to 0.25'
            WHEN ip_reputation_score < 0.5 THEN '2: 0.25 to 0.5'
            WHEN ip_reputation_score < 0.75 THEN '3: 0.5 to 0.75'
            ELSE '4: 0.75 and above' END AS ip_band,
       COUNT(*) AS sessions,
       ROUND(AVG(attack_detected) * 100, 1) AS attack_rate_pct
FROM session_data
GROUP BY ip_band
ORDER BY ip_band;

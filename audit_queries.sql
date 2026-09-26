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
SELECT COUNT(*) FROM session_data;
SELECT 
    session_id,
    failed_logins,
    attack_detected
FROM session_data
WHERE failed_logins >= 3
ORDER BY failed_logins DESC;
SELECT COUNT(*) FROM session_data WHERE failed_logins >= 3;
SELECT COUNT(*) FROM session_data WHERE unusual_time_access = 1;
SELECT COUNT(*) FROM session_data WHERE encryption_used = 'None' AND ip_reputation_score > 0.5;
SELECT COUNT(*) FROM session_data WHERE attack_detected = 1;
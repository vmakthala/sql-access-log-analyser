# SQL User Access Log Analyser

## Problem
Organisations need to detect suspicious login activity, such as repeated failed logins,
unusual access times and weak security controls, before they lead to a breach.
This project analyses 9,537 simulated session records to flag these patterns.

## Approach
- Imported a public intrusion-detection dataset into MySQL
- Wrote SQL queries to flag audit-relevant risk patterns
- Visualised key findings in Power BI

## Key Findings
| Finding | Count | % of 9,537 Sessions |
|---|---|---|
| Repeated failed logins (3+) | 1,584 | 16.6% |
| Unusual/off-hours access | 1,430 | 15.0% |
| No encryption + high-risk IP | 368 | 3.9% |
| Confirmed attacks (overall) | 4,264 | 44.7% |

## Tools Used
MySQL, MySQL Workbench, Power BI

## Chart
Failed login attempts by protocol type:

![Failed logins by protocol type](chart_failed_logins.png)

## Audit Implications
If these were a real organisation's logs, I would check:
- Failed logins: do accounts lock after a few failed attempts, and is MFA used?
- Off-hours access: are out-of-hours logins monitored and reviewed?
- No encryption + high-risk IP: is encryption enforced, and are risky IPs blocked or flagged?
- Log review: are access logs reviewed regularly, not only after an incident?

## Files
- audit_queries.sql: all SQL queries used
- chart_failed_logins.png: Power BI chart

## Dataset
Cybersecurity Intrusion Detection Dataset (Kaggle):
https://www.kaggle.com/datasets/dnkumars/cybersecurity-intrusion-detection-dataset
